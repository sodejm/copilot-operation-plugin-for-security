"""Deterministic, read-only playback for the integrated workflow catalog.

Playback is intentionally restricted to checked-in fixture targets and handlers.
Every stage is still compiled through :func:`compile_action_plan`, so the example
plans have the same target, action, scope, and argument binding as an authorized
worker plan without consuming an approval or performing a side effect.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cops.evidence.canonical import canonical, digest

from .contracts import WorkflowDefinition, value_matches_type
from .exposure_evidence import assess_exposure, scoped_records
from .purple import PurpleTeamHandoffContract, emit_purple_team_handoff, evaluate_purple_team_handoff
from .runtime import (
    WorkflowRuntimeError,
    _resolve_bindings,
    _topological_order,
    _validate_inputs,
    compile_action_plan,
)

CATALOG_SCHEMA_VERSION = "cops.integrated-workflow-catalog/v1"
FIXTURE_SCHEMA_VERSION = "cops.integrated-workflow-fixture/v1"
PLAYBACK_SCHEMA_VERSION = "cops.integrated-workflow-playback/v1"
DEFAULT_CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog" / "workflows"
DEFAULT_SPECIALIST_REGISTRY = Path(__file__).resolve().parents[2] / "agents" / "registry.json"
DEFAULT_SCENARIO_REGISTRY = Path(__file__).resolve().parents[2] / "catalog" / "scenarios.json"
_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class IntegratedWorkflowError(RuntimeError):
    """The integrated catalog or offline playback violated its contract."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class EvidenceBundleSigner:
    """Caller-owned Ed25519 signer used for credential evidence bundles."""

    key_id: str
    private_key: Ed25519PrivateKey

    def __post_init__(self) -> None:
        if _KEY_ID_PATTERN.fullmatch(self.key_id) is None:
            raise ValueError("invalid_evidence_signer_key_id")


def validate_integrated_workflow_catalog(
    catalog_dir: str | Path = DEFAULT_CATALOG_DIR,
    *,
    specialist_registry_path: str | Path = DEFAULT_SPECIALIST_REGISTRY,
    scenario_registry_path: str | Path = DEFAULT_SCENARIO_REGISTRY,
) -> dict[str, Any]:
    """Validate catalog paths, digests, registered ownership, and fixtures."""
    root = Path(catalog_dir).resolve()
    registered_specialists = _load_specialist_ids(Path(specialist_registry_path).resolve())
    registered_scenarios = _load_scenario_ids(Path(scenario_registry_path).resolve())
    catalog = _read_json(root / "catalog.json")
    if not isinstance(catalog, dict) or set(catalog) != {"schema_version", "workflows"}:
        raise IntegratedWorkflowError("catalog_shape")
    if catalog["schema_version"] != CATALOG_SCHEMA_VERSION or not isinstance(catalog["workflows"], list):
        raise IntegratedWorkflowError("catalog_schema_version")
    definitions: dict[str, WorkflowDefinition] = {}
    profiles: set[tuple[str, str]] = set()
    for entry in catalog["workflows"]:
        if not isinstance(entry, dict) or set(entry) != {"workflow_id", "path", "definition_digest", "profiles"}:
            raise IntegratedWorkflowError("catalog_entry_shape")
        workflow_id = entry["workflow_id"]
        if not isinstance(workflow_id, str) or workflow_id in definitions:
            raise IntegratedWorkflowError("duplicate_workflow")
        document = _read_json(_safe_child(root, entry["path"]))
        definition = WorkflowDefinition.from_dict(document)
        if definition.workflow_id != workflow_id or definition.definition_digest != entry["definition_digest"]:
            raise IntegratedWorkflowError("workflow_digest_mismatch")
        if definition.scenario_id not in registered_scenarios:
            raise IntegratedWorkflowError("unregistered_scenario")
        _validate_offline_definition(definition)
        for stage in definition.stages:
            if stage["action"]["specialist_id"] not in registered_specialists:
                raise IntegratedWorkflowError("unregistered_specialist")
        definitions[workflow_id] = definition
        if not isinstance(entry["profiles"], list) or len(entry["profiles"]) < 2:
            raise IntegratedWorkflowError("fixture_profiles")
        for profile in entry["profiles"]:
            required = {"profile_id", "path", "input_digest", "expected_outcome"}
            if not isinstance(profile, dict) or set(profile) != required:
                raise IntegratedWorkflowError("fixture_profile_shape")
            profile_id = profile["profile_id"]
            key = (workflow_id, profile_id)
            if not isinstance(profile_id, str) or key in profiles:
                raise IntegratedWorkflowError("duplicate_fixture_profile")
            fixture = _read_json(_safe_child(root, profile["path"]))
            if digest(fixture) != profile["input_digest"]:
                raise IntegratedWorkflowError("fixture_digest_mismatch")
            _validate_fixture(fixture, workflow_id, profile_id, definition)
            if fixture["expected_outcome"] != profile["expected_outcome"]:
                raise IntegratedWorkflowError("fixture_outcome_mismatch")
            profiles.add(key)
    if not definitions:
        raise IntegratedWorkflowError("empty_catalog")
    return catalog


def load_integrated_workflows(
    catalog_dir: str | Path = DEFAULT_CATALOG_DIR,
    *,
    specialist_registry_path: str | Path = DEFAULT_SPECIALIST_REGISTRY,
    scenario_registry_path: str | Path = DEFAULT_SCENARIO_REGISTRY,
) -> dict[str, WorkflowDefinition]:
    """Return validated workflow definitions keyed by stable workflow ID."""
    root = Path(catalog_dir).resolve()
    catalog = validate_integrated_workflow_catalog(
        root,
        specialist_registry_path=specialist_registry_path,
        scenario_registry_path=scenario_registry_path,
    )
    return {
        entry["workflow_id"]: WorkflowDefinition.from_dict(_read_json(_safe_child(root, entry["path"])))
        for entry in catalog["workflows"]
    }


def run_fixture_profile(
    workflow_id: str,
    profile_id: str,
    *,
    catalog_dir: str | Path = DEFAULT_CATALOG_DIR,
    run_id: str | None = None,
    specialist_registry_path: str | Path = DEFAULT_SPECIALIST_REGISTRY,
    scenario_registry_path: str | Path = DEFAULT_SCENARIO_REGISTRY,
    evidence_signer: EvidenceBundleSigner | None = None,
) -> dict[str, Any]:
    """Run one digest-pinned catalog fixture and verify its declared outcome."""
    root = Path(catalog_dir).resolve()
    catalog = validate_integrated_workflow_catalog(
        root,
        specialist_registry_path=specialist_registry_path,
        scenario_registry_path=scenario_registry_path,
    )
    for entry in catalog["workflows"]:
        if entry["workflow_id"] != workflow_id:
            continue
        for profile in entry["profiles"]:
            if profile["profile_id"] == profile_id:
                fixture = _read_json(_safe_child(root, profile["path"]))
                report = run_offline_playback(
                    workflow_id,
                    fixture["inputs"],
                    catalog_dir=root,
                    run_id=run_id or f"fixture-{workflow_id}-{profile_id}",
                    specialist_registry_path=specialist_registry_path,
                    scenario_registry_path=scenario_registry_path,
                    evidence_signer=evidence_signer,
                )
                if report["outcome"] != fixture["expected_outcome"]:
                    raise IntegratedWorkflowError("unexpected_fixture_outcome")
                return report
        raise IntegratedWorkflowError("unknown_fixture_profile")
    raise IntegratedWorkflowError("unknown_workflow")


def run_offline_playback(
    workflow_id: str,
    inputs: dict[str, Any],
    *,
    catalog_dir: str | Path = DEFAULT_CATALOG_DIR,
    run_id: str = "offline-playback",
    specialist_registry_path: str | Path = DEFAULT_SPECIALIST_REGISTRY,
    scenario_registry_path: str | Path = DEFAULT_SCENARIO_REGISTRY,
    evidence_signer: EvidenceBundleSigner | None = None,
) -> dict[str, Any]:
    """Compile and evaluate a workflow with allowlisted, side-effect-free handlers."""
    definitions = load_integrated_workflows(
        catalog_dir,
        specialist_registry_path=specialist_registry_path,
        scenario_registry_path=scenario_registry_path,
    )
    if workflow_id not in definitions:
        raise IntegratedWorkflowError("unknown_workflow")
    definition = definitions[workflow_id]
    workflow_inputs = _validate_inputs(definition, inputs)
    state: dict[str, Any] = {"stages": {}}
    evidence_count = 0
    output_bytes = 0
    stage_map = {stage["stage_id"]: stage for stage in definition.stages}
    for stage_id in _topological_order(stage_map):
        stage = stage_map[stage_id]
        resolved = _resolve_bindings(stage["inputs"], workflow_inputs, state)
        plan = compile_action_plan(
            definition,
            run_id,
            stage_id,
            resolved,
            "2026-01-01T00:00:00Z",
        )
        action = stage["action"]["action"]
        handler = _HANDLERS.get(action)
        if handler is None:
            raise IntegratedWorkflowError("unregistered_fixture_action")
        if action == "credential.build_evidence_bundle":
            outputs = _credential_bundle(resolved, evidence_signer)
        else:
            outputs = handler(resolved)
        if set(outputs) != set(stage["outputs"]):
            raise IntegratedWorkflowError("fixture_output_shape")
        if any(not value_matches_type(outputs[name], spec["type"]) for name, spec in stage["outputs"].items()):
            raise IntegratedWorkflowError("fixture_output_type")
        encoded = canonical(outputs, max_bytes=stage["action"]["limits"]["max_output_bytes"])
        output_bytes += len(encoded)
        evidence_ref = f"evidence://offline/{workflow_id}/{stage_id}/{digest(outputs)[:24]}"
        evidence_count += 1
        if output_bytes > definition.budget["max_output_bytes"]:
            raise WorkflowRuntimeError("workflow_output_budget_exceeded")
        if evidence_count > definition.budget["max_evidence_refs"]:
            raise WorkflowRuntimeError("workflow_evidence_budget_exceeded")
        state["stages"][stage_id] = {
            "status": "success",
            "outputs": outputs,
            "evidence_refs": [evidence_ref],
            "plan": plan.approved_snapshot(include_digest=True),
        }
    workflow_outputs = {
        name: _resolve_output(spec["source"], state) for name, spec in definition.outputs.items()
    }
    outcome = workflow_outputs.get("outcome")
    if not isinstance(outcome, str):
        raise IntegratedWorkflowError("missing_outcome")
    return {
        "schema_version": PLAYBACK_SCHEMA_VERSION,
        "workflow_id": workflow_id,
        "run_id": run_id,
        "status": "completed",
        "outcome": outcome,
        "outputs": workflow_outputs,
        "stages": state["stages"],
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IntegratedWorkflowError("invalid_catalog_json") from exc


def _load_specialist_ids(path: Path) -> frozenset[str]:
    registry = _read_json(path)
    if not isinstance(registry, dict) or not isinstance(registry.get("specialists"), list):
        raise IntegratedWorkflowError("specialist_registry_shape")
    identifiers: list[str] = []
    for specialist in registry["specialists"]:
        if not isinstance(specialist, dict) or not isinstance(specialist.get("id"), str):
            raise IntegratedWorkflowError("specialist_registry_shape")
        identifiers.append(specialist["id"])
    if not identifiers or len(identifiers) != len(set(identifiers)):
        raise IntegratedWorkflowError("specialist_registry_shape")
    return frozenset(identifiers)


def _load_scenario_ids(path: Path) -> frozenset[str]:
    registry = _read_json(path)
    if not isinstance(registry, dict) or not isinstance(registry.get("scenarios"), list):
        raise IntegratedWorkflowError("scenario_registry_shape")
    identifiers: list[str] = []
    for scenario in registry["scenarios"]:
        if not isinstance(scenario, dict) or not isinstance(scenario.get("scenario_id"), str):
            raise IntegratedWorkflowError("scenario_registry_shape")
        identifiers.append(scenario["scenario_id"])
    if not identifiers or len(identifiers) != len(set(identifiers)):
        raise IntegratedWorkflowError("scenario_registry_shape")
    return frozenset(identifiers)


def _safe_child(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise IntegratedWorkflowError("unsafe_catalog_path")
    child = (root / relative).resolve()
    if root not in child.parents:
        raise IntegratedWorkflowError("unsafe_catalog_path")
    return child


def _validate_offline_definition(definition: WorkflowDefinition) -> None:
    expected_target = f"fixture://{definition.workflow_id}"
    for stage in definition.stages:
        action = stage["action"]
        if (
            action["target"] != expected_target
            or action["limits"]["egress_allowed"] is not False
            or action.get("side_effects", [])
            or action["action"] not in _HANDLERS
            or not action.get("expected_evidence")
        ):
            raise IntegratedWorkflowError("unsafe_offline_definition")


def _validate_fixture(
    fixture: Any, workflow_id: str, profile_id: str, definition: WorkflowDefinition
) -> None:
    if not isinstance(fixture, dict) or set(fixture) != {
        "schema_version",
        "workflow_id",
        "profile_id",
        "inputs",
        "expected_outcome",
    }:
        raise IntegratedWorkflowError("fixture_shape")
    if (
        fixture["schema_version"] != FIXTURE_SCHEMA_VERSION
        or fixture["workflow_id"] != workflow_id
        or fixture["profile_id"] != profile_id
        or not isinstance(fixture["expected_outcome"], str)
    ):
        raise IntegratedWorkflowError("fixture_identity")
    _validate_inputs(definition, fixture["inputs"])


def _resolve_output(source: str, state: dict[str, Any]) -> Any:
    parts = source.split(".")
    try:
        return state["stages"][parts[1]]["outputs"][parts[3]]
    except (IndexError, KeyError) as exc:
        raise IntegratedWorkflowError("missing_workflow_output") from exc


def _credential_scan(values: dict[str, Any]) -> dict[str, Any]:
    snapshot = values["repository_snapshot"]
    findings = [item for item in snapshot.get("findings", []) if isinstance(item, dict)]
    return {"secret_findings": findings, "scan_summary": {"objects_scanned": snapshot.get("objects_scanned", 0)}}


def _credential_correlate(values: dict[str, Any]) -> dict[str, Any]:
    findings = values["secret_findings"]
    identity = values["identity_evidence"]
    soc = values["soc_evidence"]
    active = sorted({item.get("principal") for item in findings if item.get("active") is True and item.get("principal")})
    observed = sorted({item.get("principal") for item in soc.get("events", []) if item.get("suspicious") is True})
    return {
        "correlation": {
            "active_principals": active,
            "observed_suspicious_use": [item for item in observed if item in active],
            "identity_evidence_present": bool(identity.get("accounts")),
            "soc_evidence_present": "events" in soc,
        }
    }


def _credential_assess(values: dict[str, Any]) -> dict[str, Any]:
    correlation = values["correlation"]
    if not correlation["identity_evidence_present"] or not correlation["soc_evidence_present"]:
        outcome = "insufficient_evidence"
    elif correlation["active_principals"]:
        outcome = "action_required"
    else:
        outcome = "no_active_exposure_observed"
    return {"exposure_assessment": {"outcome": outcome, **correlation}, "outcome": outcome}


def _credential_checklist(values: dict[str, Any]) -> dict[str, Any]:
    assessment = values["exposure_assessment"]
    principals = assessment.get("active_principals", [])
    return {
        "rotation_checklist": [
            {"principal": principal, "steps": ["revoke", "rotate", "review_sessions", "confirm_telemetry"]}
            for principal in principals
        ],
        "outcome": assessment["outcome"],
    }


def _credential_bundle(
    values: dict[str, Any], signer: EvidenceBundleSigner | None = None
) -> dict[str, Any]:
    payload = {"assessment": values["exposure_assessment"], "checklist": values["rotation_checklist"]}
    payload_digest = digest(payload)
    signature: dict[str, Any]
    if signer is None:
        signature = {
            "status": "unsigned",
            "algorithm": None,
            "key_id": None,
            "value": None,
            "payload_digest": payload_digest,
            "reason": "signer_not_configured",
        }
        cryptographically_signed = False
        signature_verified = False
        trust_status = "unsigned"
    else:
        try:
            payload_bytes = canonical(payload)
            signature_bytes = signer.private_key.sign(payload_bytes)
            public_key = signer.private_key.public_key()
            public_key.verify(signature_bytes, payload_bytes)
            public_key_bytes = public_key.public_bytes_raw()
        except (AttributeError, InvalidSignature, TypeError, ValueError) as exc:
            raise IntegratedWorkflowError("evidence_signing_failed") from exc
        signature = {
            "status": "signed",
            "algorithm": "ed25519",
            "key_id": signer.key_id,
            "value": signature_bytes.hex(),
            "public_key": public_key_bytes.hex(),
            "payload_digest": payload_digest,
        }
        cryptographically_signed = True
        signature_verified = True
        trust_status = "caller_configured_unanchored"
    return {
        "evidence_bundle": {
            "payload": payload,
            "signature": signature,
            "cryptographically_signed": cryptographically_signed,
            "signature_verified": signature_verified,
            "authenticity_established": False,
            "trust_status": trust_status,
            "live_signing_required": signer is None,
        },
        "outcome": values["outcome"],
    }


def _cve_ingest(values: dict[str, Any]) -> dict[str, Any]:
    from .cve_evidence import match_dependency

    return {"dependency_match": match_dependency(values["advisory"], values["dependency_inventory"])}


def _cve_reachability(values: dict[str, Any]) -> dict[str, Any]:
    from .cve_evidence import assess_reachability

    return {"reachability_assessment": assess_reachability(
        values["dependency_match"], values["callgraph_evidence"], values["runtime_evidence"],
    )}


def _cve_controls(values: dict[str, Any]) -> dict[str, Any]:
    from .cve_evidence import assess_controls

    return {"control_assessment": assess_controls(values["compensating_controls"], values["reachability_assessment"])}


def _cve_remediate(values: dict[str, Any]) -> dict[str, Any]:
    reachability = values["reachability_assessment"]
    if reachability["status"] == "reachable":
        outcome, priority = "urgent_remediation", "P0"
    elif reachability["status"] == "not_established":
        outcome, priority = "insufficient_evidence", "P1"
    elif reachability["status"] == "corrected_dependency":
        outcome, priority = "known_corrected_component", "P2"
    else:
        outcome, priority = "prioritized_remediation", "P2"
    return {
        "remediation": {
            "outcome": outcome,
            "priority": priority,
            "non_exploitability_established": reachability["non_exploitability_established"],
            "verified_compensating_controls": values["control_assessment"]["count"],
        },
        "outcome": outcome,
    }


def _kube_snapshot(values: dict[str, Any]) -> dict[str, Any]:
    return {"snapshot": {"cluster": values["cluster_evidence"], "captured": bool(values["cluster_evidence"])}}


def _kube_review(values: dict[str, Any]) -> dict[str, Any]:
    bindings = values["snapshot"]["cluster"].get("bindings", [])
    excessive = [item for item in bindings if item.get("cluster_admin") is True or item.get("wildcard") is True]
    return {"rbac_review": {"excessive_bindings": excessive, "finding_count": len(excessive)}}


def _kube_propose(values: dict[str, Any]) -> dict[str, Any]:
    proposals = [
        {"subject": item.get("subject"), "action": "remove_excessive_binding"}
        for item in values["rbac_review"]["excessive_bindings"]
    ]
    return {"containment_proposal": {"changes": proposals, "requires_authorization": bool(proposals)}}


def _kube_apply(values: dict[str, Any]) -> dict[str, Any]:
    changes = values["containment_proposal"]["changes"]
    return {
        "lab_application": {
            "fixture_only": True,
            "activity_performed": False,
            "live_authorization_required": bool(changes),
            "modeled_changes": changes,
            "validation_status": "insufficient_lab_validation" if changes else "not_required",
            "restoration_verified": False,
        }
    }


def _kube_verify(values: dict[str, Any]) -> dict[str, Any]:
    application = values["lab_application"]
    changes = application["modeled_changes"]
    outcome = "insufficient_lab_validation" if changes else "no_containment_required"
    return {
        "report": {
            "outcome": outcome,
            "activity_performed": False,
            "connectivity_verified": False,
            "cleanup_verified": False,
            "requires_authorized_lab": bool(changes),
            "modeled_expectations": ["containment_applied", "connectivity_preserved", "cleanup_restored"]
            if changes
            else [],
        },
        "hardening_guide": ["use least-privilege roles", "rotate service account credentials"],
        "incident_response_guide": ["preserve audit evidence", "revoke affected sessions", "validate recovery"],
        "outcome": outcome,
    }


def _consent_import(values: dict[str, Any]) -> dict[str, Any]:
    from .consent_evidence import SCHEMA

    return {"entra_evidence": {"schema_version": SCHEMA, **{
        key: values[key] for key in ("grants", "signins", "service_principals", "coverage")
    }}}


def _consent_assess(values: dict[str, Any]) -> dict[str, Any]:
    from .consent_evidence import assess_consent

    return {"suspicious_assessment": assess_consent(values["entra_evidence"])}


def _consent_propose(values: dict[str, Any]) -> dict[str, Any]:
    assessment = values["suspicious_assessment"]
    return {"remediation_proposal": {**assessment, "steps": ["revoke_grant", "revoke_sessions", "hunt_activity"]
                                     if assessment["targets"] else []}}


def _consent_validate(values: dict[str, Any]) -> dict[str, Any]:
    proposal = values["remediation_proposal"]
    targets = proposal["targets"]
    outcome = "insufficient_lab_validation" if targets else proposal["status"]
    return {
        "lab_validation": {
            "outcome": outcome,
            "identity_package_exercised": False,
            "hunt_package_exercised": False,
            "fixture_only": True,
            "activity_performed": False,
            "requires_authorized_lab": bool(targets),
            "targets": targets,
            "evidence_refs": proposal["evidence_refs"],
            "limitations": proposal["limitations"],
            "modeled_expectations": ["grant_revoked", "sessions_revoked", "activity_hunted"]
            if targets
            else [],
        },
        "outcome": outcome,
    }


def _detection_replay(values: dict[str, Any]) -> dict[str, Any]:
    handoff = emit_purple_team_handoff(
        values["source_result"],
        values["expected_telemetry"],
        values["correlation_ids"],
        values["time_window"],
        values["evidence_refs"],
    )
    return {
        "replay": {
            "handoff": handoff.to_dict(),
            "telemetry": values["telemetry"],
            "alerts": values["alerts"],
            "attack_fixture": values["attack_fixture"],
            "benign_fixture": values["benign_fixture"],
        }
    }


def _detection_execute(values: dict[str, Any]) -> dict[str, Any]:
    replay = values["replay"]
    evaluation = evaluate_purple_team_handoff(
        PurpleTeamHandoffContract.from_dict(replay["handoff"]),
        replay["telemetry"],
        replay["alerts"],
        replay["attack_fixture"],
        replay["benign_fixture"],
    )
    return {"rule_evaluation": evaluation}


def _detection_counts(values: dict[str, Any]) -> dict[str, Any]:
    counts = values["rule_evaluation"]["fixture_counts"]
    return {"fixture_counts": counts, "detection_status": values["rule_evaluation"]["status"]}


def _detection_report(values: dict[str, Any]) -> dict[str, Any]:
    evaluation = values["rule_evaluation"]
    return {
        "report": {
            "status": values["detection_status"],
            "counts": values["fixture_counts"],
            "rule_proposal": evaluation["rule_proposal"],
            "reason": evaluation["reason"],
        },
        "outcome": values["detection_status"],
    }


def _exposure_inventory(values: dict[str, Any]) -> dict[str, Any]:
    records = scoped_records(values["scope"], values["dns_service_inventory"], dns=True)
    return {"scoped_inventory": {
        "hosts": sorted({item["host"] for item in records}), "records": records,
        "evidence": {"scope": values["scope"], "dns_service_inventory": values["dns_service_inventory"]},
    }}


def _exposure_routes(values: dict[str, Any]) -> dict[str, Any]:
    evidence = {**values["scoped_inventory"]["evidence"], "port_route_evidence": values["port_route_evidence"]}
    return {"route_assessment": {
        "checks": scoped_records(evidence["scope"], values["port_route_evidence"]), "evidence": evidence,
    }}


def _exposure_auth(values: dict[str, Any]) -> dict[str, Any]:
    return {"auth_assessment": assess_exposure({
        **values["route_assessment"]["evidence"], "auth_evidence": values["auth_evidence"],
    })}


def _exposure_report(values: dict[str, Any]) -> dict[str, Any]:
    assessment = values["auth_assessment"]
    exposures = assessment["exposures"]
    return {
        "remediation_report": {
            **assessment,
            "recommendations": ["require authentication", "restrict route", "retest"] if exposures else [],
        },
        "outcome": assessment["outcome"],
    }


_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "credential.scan_git_history": _credential_scan,
    "credential.correlate_identity_soc": _credential_correlate,
    "credential.assess_exposure": _credential_assess,
    "credential.build_rotation_checklist": _credential_checklist,
    "credential.build_evidence_bundle": _credential_bundle,
    "cve.match_dependency": _cve_ingest,
    "cve.assess_reachability": _cve_reachability,
    "cve.assess_controls": _cve_controls,
    "cve.prioritize_remediation": _cve_remediate,
    "kubernetes.capture_snapshot": _kube_snapshot,
    "kubernetes.review_rbac": _kube_review,
    "kubernetes.propose_containment": _kube_propose,
    "kubernetes.authorized_lab_apply": _kube_apply,
    "kubernetes.verify_connectivity_cleanup": _kube_verify,
    "consent.import_entra_evidence": _consent_import,
    "consent.assess_suspicious_activity": _consent_assess,
    "consent.propose_remediation": _consent_propose,
    "consent.validate_in_lab": _consent_validate,
    "detection.replay_telemetry": _detection_replay,
    "detection.execute_sigma_kql": _detection_execute,
    "detection.report_fixture_counts": _detection_counts,
    "detection.build_evidence_report": _detection_report,
    "exposure.scope_inventory": _exposure_inventory,
    "exposure.check_ports_routes": _exposure_routes,
    "exposure.check_authentication": _exposure_auth,
    "exposure.build_remediation_report": _exposure_report,
}
