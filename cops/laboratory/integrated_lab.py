"""Signed, service-backed acceptance for the cross-plugin workflows.

All services bind to loopback. Strict callers must establish operating-system
network isolation before calling this module. Tokens stay in executor memory.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cops.assessments.git_history import (
    GitHistoryScanError, _safe_environment, pinned_git_executable, scan_git_history,
)
from cops.contracts.models import Engagement
from cops.evidence.canonical import canonical, digest
from cops.execution.authorization import (
    AuthorizationSigner,
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
)
from cops.execution.store import ApprovalStore
from cops.laboratory.service_boundaries import run_boundary_acceptance
from cops.laboratory.service_lab import (
    FIXTURE_DIRECTORY,
    _Graph,
    _Telemetry,
    _execute_detection_rules,
    _request_json,
    load_consent_fixture,
    probe_isolated_runtime,
    verify_fixture_manifest,
)
from cops.laboratory.workflow_lab import (
    IOC,
    WORKER,
    IsolationRequiredError,
    _LaboratoryApprovalControl,
    _action,
    _utc,
)
from cops.workflows.consent_evidence import assess_consent
from cops.workflows.contracts import WorkflowDefinition
from cops.workflows.purple import emit_purple_team_handoff, evaluate_purple_team_handoff
from cops.workflows.runtime import (
    StageExecutionResult,
    WorkflowRunner,
    WorkflowRuntimeError,
    compile_action_plan,
)


WORKFLOW_STAGES = {
    "leaked-credential-blast-radius": (
        "scan", "correlate", "assess", "revoke", "verify", "bundle",
    ),
    "cve-reachability-triage": (
        "dependencies", "observe", "controls", "remediate",
    ),
    "illicit-consent-remediation": (
        "snapshot", "correlate", "propose", "revoke", "verify",
    ),
    "detection-rule-ci-validation": (
        "rules", "attack", "benign", "measure",
    ),
    "pre-release-exposure-audit": (
        "inventory", "connect", "authentication", "report",
    ),
}


def _purple_evidence_views(telemetry: _Telemetry, alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate explicitly labeled evidence views of captured service activity."""
    events = copy.deepcopy(telemetry.events)
    captured_alerts = copy.deepcopy(alerts)
    times = [datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) for event in events]
    evidence = {"telemetry": digest(events), "alerts": digest(captured_alerts)}
    handoff = emit_purple_team_handoff(
        {"kind": "simulation", "ref": "laboratory:" + telemetry.correlation_id},
        [{"field": "event", "value": "authenticated_access_rejected"}],
        [telemetry.correlation_id],
        {"start": _utc(min(times) - timedelta(seconds=1)), "end": _utc(max(times) + timedelta(seconds=1))},
        ["sha256:" + evidence["telemetry"], "sha256:" + evidence["alerts"]],
    )
    attack = [event for event in events if event.get("risk") == "attack"]
    benign = [event for event in events if event.get("risk") == "benign"]
    views = (
        ("captured", "captured service telemetry and alerts", events, captured_alerts),
        ("logs_withheld", "captured service logs intentionally withheld", None, captured_alerts),
        ("alerts_withheld", "captured service alerts intentionally withheld", events, []),
        ("alert_evidence_unavailable", "captured service alert evidence marked unavailable", events, None),
    )
    return {
        "source": "captured-service-activity",
        "source_digests": evidence,
        "handoff": handoff.to_dict(), "handoff_digest": handoff.handoff_digest,
        "views": {
            name: {"evidence_view": label, "result": evaluate_purple_team_handoff(
                handoff, logs, matches, attack_fixture=attack, benign_fixture=benign,
            )}
            for name, label, logs, matches in views
        },
    }


def _runtime_git_pin() -> str:
    """Read the reviewed image's root-owned prerequisite, never scanned input."""
    path = Path("/opt/cops-runtime/git-prerequisite.json")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022 or metadata.st_size > 4096):
                raise ValueError("untrusted_git_prerequisite")
            value = json.loads(stream.read(4097))
        if (value.get("schema_version") != "cops.runtime-prerequisite/v1"
                or value.get("tool") != "git" or not isinstance(value.get("sha256"), str)
                or len(value["sha256"]) != 64
                or any(item not in "0123456789abcdef" for item in value["sha256"])):
            raise ValueError("invalid_git_prerequisite")
        return value["sha256"]
    except (OSError, ValueError, AttributeError) as error:
        raise GitHistoryScanError("reviewed_runtime_git_pin_required") from error


def _scan_disposable_credential(token: str, git_sha256: str) -> dict[str, Any]:
    """Commit the issued token, remove it at HEAD, and inspect real Git objects."""
    deadline = time.monotonic() + 30
    with tempfile.TemporaryDirectory(prefix="cops-credential-history-") as temporary:
        repository = Path(temporary).resolve()
        environment = _safe_environment()
        environment.update({
            "GIT_AUTHOR_NAME": "COPS Laboratory", "GIT_COMMITTER_NAME": "COPS Laboratory",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2026-10-15T12:00:00+00:00", "GIT_COMMITTER_DATE": "2026-10-15T12:00:00+00:00",
        })
        with pinned_git_executable(git_sha256, deadline=deadline) as git:
            def command(*arguments: str) -> None:
                try:
                    subprocess.run(
                        [git, "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgSign=false",
                         "-c", "gc.auto=0", "-c", "maintenance.auto=false", *arguments],
                        cwd=repository, env=environment, stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        shell=False, check=True, timeout=max(0.01, deadline - time.monotonic()),
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    raise GitHistoryScanError("disposable_git_fixture_failed") from error
            command("init", "--quiet", "--template=")
            target = repository / "synthetic-credential.txt"
            target.write_text(token + "\n", encoding="utf-8")
            command("add", "--", target.name)
            command("commit", "--quiet", "-m", "synthetic exposure")
            target.write_text("credential obtained from identity service\n", encoding="utf-8")
            command("add", "--", target.name)
            command("commit", "--quiet", "-m", "remove exposed credential from HEAD")

        def snapshot() -> dict[str, tuple[int, str]]:
            return {item.relative_to(repository).as_posix(): (
                item.stat().st_mode, hashlib.sha256(item.read_bytes()).hexdigest(),
            ) for item in repository.rglob("*") if item.is_file()}

        before = snapshot()
        artifact = scan_git_history(repository, expected_git_sha256=git_sha256)
        unchanged = snapshot() == before
        fingerprint = hashlib.sha256(b"cops.synthetic-credential/v1\0" + token.encode()).hexdigest()
        occurrences = artifact["content"]["occurrences"]
        matched = bool(occurrences) and all(item["fingerprint"] == fingerprint for item in occurrences)
        historical = matched and all(
            item["commit"] != artifact["content"]["source"]["head_commit"] for item in occurrences
        )
    return {
        "source": "disposable-git-history-and-service-issued-credential",
        "fingerprint": fingerprint, "value_redacted": True, "artifact": artifact,
        "same_credential_observed": matched, "historical_exposure_observed": historical,
        "repository_unchanged_by_scan": unchanged, "disposable_repository_removed": not repository.exists(),
    }


def laboratory_workflow(workflow_id: str) -> WorkflowDefinition:
    """Build a fixed-stage workflow whose approvals bind exact service URLs."""
    names = WORKFLOW_STAGES[workflow_id]
    stages = []
    for index, name in enumerate(names):
        inputs = {
            "configuration": {
                "type": "object", "source": "workflow.input.configuration",
            },
        }
        if index:
            inputs["prior"] = {
                "type": "object", "source": "stage." + names[index - 1] + ".output.observations",
            }
        stages.append({
            "stage_id": name,
            "depends_on": list(names[index - 1:index]) if index else [],
            "inputs": inputs,
            "outputs": {"observations": {"type": "object"}},
            "action": _action(name),
        })
    return WorkflowDefinition.from_dict({
        "schema_version": "cops.workflow-definition/v1",
        "workflow_id": "laboratory-" + workflow_id,
        "engagement_id": "eng-integrated-laboratory",
        "scenario_id": "scen-" + workflow_id,
        "inputs": {"configuration": {"type": "object", "required": True}},
        "outputs": {
            "assessment": {
                "type": "object",
                "source": "stage." + names[-1] + ".output.observations",
            },
        },
        "budget": {
            "max_stages": len(names), "max_total_attempts": len(names),
            "max_output_bytes": 262144, "max_evidence_refs": 64,
        },
        "stages": stages,
    })


class _IntegratedExecutor:
    def __init__(self, graph: _Graph, workflow_id: str, configuration: dict[str, Any],
                 telemetry: _Telemetry, token: str, benign_token: str | None = None) -> None:
        self.graph = graph
        self.workflow_id = workflow_id
        self.configuration = copy.deepcopy(configuration)
        self.telemetry = telemetry
        self.token = token
        self.benign_token = benign_token
        self.requests: list[dict[str, Any]] = []
        self.observations: dict[str, Any] = {}
        self.executed: list[str] = []
        self.cleanup_count = 0

    def request(self, service: str, path: str, *, method: str = "GET",
                payload: dict[str, Any] | None = None, authenticated: bool = False,
                benign: bool = False) -> tuple[int, dict[str, Any]]:
        destination = self.configuration["destinations"][service] + path
        status, body = _request_json(destination, method=method, payload=payload,
                                     token=(self.benign_token if benign else self.token) if authenticated else None)
        # Neither response bodies nor credential-bearing request bodies enter reports.
        self.requests.append({"destination": destination, "method": method, "status": status})
        return status, body

    def execute(self, plan: Any, receipt: Any, *, idempotency_key: str) -> StageExecutionResult:
        operation = plan.to_dict()["operations"][0]
        name = operation["action"]
        if len(self.executed) >= len(WORKFLOW_STAGES[self.workflow_id]):
            raise ValueError("laboratory stage executed twice")
        expected_name = WORKFLOW_STAGES[self.workflow_id][len(self.executed)]
        expected_arguments = {"configuration": self.configuration}
        if self.executed:
            expected_arguments["prior"] = self.observations
        if name != expected_name or operation["arguments"] != expected_arguments:
            raise ValueError("laboratory stage, configuration, or prior output changed")
        # Consume the typed, approval-bound result of the preceding stage.
        self.observations = copy.deepcopy(operation["arguments"].get("prior", {}))
        self.executed.append(name)
        handler = getattr(self, "_" + self.workflow_id.replace("-", "_"))
        handler(name)
        return StageExecutionResult(
            "success", outputs={"observations": copy.deepcopy(self.observations)},
            evidence_refs=("laboratory:" + idempotency_key,),
        )

    def cleanup(self, plan: Any, *, idempotency_key: str) -> None:
        self.cleanup_count += 1
        with self.graph._lock:
            self.graph.state.restore(self.graph.baseline)

    def _leaked_credential_blast_radius(self, name: str) -> None:
        if name == "scan":
            self.observations["synthetic_exposure"] = _scan_disposable_credential(
                self.token, self.configuration["git_sha256"],
            )
        elif name == "correlate":
            status, _ = self.request("resource", "/protected", authenticated=True)
            self.observations["before_revocation"] = status
        elif name == "assess":
            self.observations["exposure"] = "verified" if self.observations["before_revocation"] == 200 else "indeterminate"
        elif name == "revoke":
            status, _ = self.request("identity", "/revoke", method="POST", payload={"token": self.token})
            self.observations["revocation"] = status
        elif name == "verify":
            status, _ = self.request("resource", "/protected", authenticated=True)
            self.observations["after_revocation"] = status
            self.observations["corrected"] = status == 401
        elif name == "bundle":
            payload = copy.deepcopy(self.observations)
            key = Ed25519PrivateKey.generate()
            signature = key.sign(canonical(payload))
            key.public_key().verify(signature, canonical(payload))
            self.observations["bundle"] = {
                "payload": payload, "payload_digest": digest(payload),
                "algorithm": "Ed25519", "signature": signature.hex(),
                "public_key": key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
                ).hex(),
                "signature_verified": True, "authenticity_established": False,
                "trust_status": "ephemeral_laboratory_key",
            }

    def _cve_reachability_triage(self, name: str) -> None:
        from cops.workflows.cve_evidence import assess_reachability, match_dependency

        if name == "dependencies":
            verify_fixture_manifest()
            self.observations["advisory"] = json.loads((FIXTURE_DIRECTORY / "cve-advisory.json").read_text())
        elif name in {"observe", "remediate"}:
            profile = "vulnerable" if name == "observe" else "corrected"
            observed = run_boundary_acceptance(profile=profile)
            self.observations[profile] = observed
            matched = match_dependency(self.observations["advisory"], observed["dependency_inventory"])
            assessment = assess_reachability(matched, {}, observed["runtime_evidence"])
            self.observations[profile + "_assessment"] = assessment
            if profile == "vulnerable":
                self.observations["reachability"] = (
                    "observed" if assessment["status"] == "reachable" and observed["injection_exposed_other_object"] else "indeterminate"
                )
            else:
                self.observations["remediation_verified"] = (
                    assessment["status"] == "corrected_dependency" and observed["injection_rows"] == 0
                    and observed["benign_query_preserved"] and self.observations["reachability"] == "observed"
                )
        elif name == "controls":
            match = self.observations["vulnerable_assessment"]["dependency_match"]
            absent = assess_reachability(match, {}, {})
            self.observations["without_runtime_evidence"] = {
                "reachability": "unknown" if absent["status"] == "not_established" else absent["status"],
                "non_exploitable": absent["non_exploitability_established"],
            }

    def _illicit_consent_remediation(self, name: str) -> None:
        # The disposable identity service represents an application grant. Its
        # revocation invalidates actual HTTP authorization. It is not Entra.
        if name == "snapshot":
            self.observations["identity_backend"] = "disposable-application-grant-emulator"
            self.observations["production_entra_validation"] = "unverified"
            self.observations["snapshot_digest"] = self.graph.state.snapshot()
            self.observations["evidence_digest"] = digest(self.configuration["consent_evidence"])
        elif name == "correlate":
            self.observations["assessment"] = assess_consent(self.configuration["consent_evidence"])
            status, _ = self.request("resource", "/protected", authenticated=True)
            self.observations["grant_access_before"] = status
            self.observations["benign_access_before"] = self.request("resource", "/protected", authenticated=True, benign=True)[0]
        elif name == "propose":
            assessment = self.observations["assessment"]
            targets = assessment["targets"]
            self.observations["proposal"] = {
                "targets": targets, "action": "revoke_grant", "evidence_refs": assessment["evidence_refs"],
                "eligible": assessment["status"] == "suspicious_consent_observed" and len(targets) == 1,
                "limitations": ["session revocation and hunt remain proposed; production Entra unverified"],
            }
        elif name == "revoke":
            proposal = self.observations["proposal"]
            self.observations["revocation"] = None
            if proposal["eligible"]:
                status, _ = self.request("identity", "/revoke-grant", method="POST", payload={"identity": proposal["targets"][0]})
                self.observations["revocation"] = status
        elif name == "verify":
            status, _ = self.request("resource", "/protected", authenticated=True)
            self.observations["grant_access_after"] = status
            self.observations["benign_access_after"] = self.request("resource", "/protected", authenticated=True, benign=True)[0]
            self.observations["remediation_verified"] = (
                self.observations["grant_access_before"] == 200 and status == 401
                and self.observations["revocation"] == 200
                and self.observations["benign_access_before"] == self.observations["benign_access_after"] == 200
            )

    def _detection_rule_ci_validation(self, name: str) -> None:
        if name == "rules":
            self.observations["rule_engine"] = "registered-laboratory-event-rules"
            self.observations["sigma_kql_engine_validation"] = "unverified"
        elif name == "attack":
            self.request("hunt", "/ioc", method="POST", payload={"value": IOC})
            self.request("hunt", "/hunt?value=" + IOC)
            self.request("resource", "/protected")
        elif name == "benign":
            self.request("resource", "/protected", authenticated=True)
            self.request("hunt", "/hunt?value=198.51.100.9")
        elif name == "measure":
            counts, alerts = _execute_detection_rules(self.telemetry.events)
            self.observations["event_counts"] = counts
            self.observations["alerts"] = list(alerts)
            self.observations["attack_and_benign_executed"] = True
            self.observations["purple_team"] = _purple_evidence_views(self.telemetry, list(alerts))

    def _pre_release_exposure_audit(self, name: str) -> None:
        if name == "inventory":
            self.observations["inventory"] = copy.deepcopy(self.configuration["destinations"])
            self.observations["dns_validation"] = "not_applicable_numeric_loopback_only"
        elif name == "connect":
            status, _ = self.request("resource", "/protected", authenticated=True)
            self.observations["authorized_status"] = status
        elif name == "authentication":
            status, _ = self.request("resource", "/protected")
            self.observations["anonymous_status"] = status
        elif name == "report":
            self.observations["authentication_verified"] = (
                self.observations["authorized_status"] == 200
                and self.observations["anonymous_status"] == 401
            )
            self.observations["coverage"] = "explicit loopback destinations only"


class _IntegratedApprovalControl(_LaboratoryApprovalControl):
    """Sign only the next concrete laboratory action and its resolved inputs.

    This ephemeral operator is confined to fixed disposable services. Production
    execution still requires an independent operator and isolated approval service.
    """

    def __init__(self, store: ApprovalStore, trust: AuthorizationTrustStore,
                 engagement: Engagement, now: str, *, signer: AuthorizationSigner,
                 authorized_until: str, definition: WorkflowDefinition, run_id: str,
                 executor: _IntegratedExecutor, authorization_ids: dict[str, str]) -> None:
        super().__init__(store, trust, engagement, now)
        self.signer = signer
        self.authorized_until = authorized_until
        self.definition = definition
        self.run_id = run_id
        self.executor = executor
        self.authorization_ids = dict(authorization_ids)
        self.plan_digests: dict[str, str] = {}

    def consume_authorization(self, authorization_id: str, action_plan: Any, worker_identity: str) -> Any:
        self.assert_ready(worker_identity)
        stages = tuple(stage["stage_id"] for stage in self.definition.stages)
        if len(self.executor.executed) >= len(stages):
            raise WorkflowRuntimeError("replayed_authorization")
        stage = stages[len(self.executor.executed)]
        if authorization_id != self.authorization_ids[stage] or stage in self.plan_digests:
            raise WorkflowRuntimeError("replayed_or_unexpected_authorization")
        resolved = {"configuration": self.executor.configuration}
        if self.executor.executed:
            resolved["prior"] = self.executor.observations
        expected = compile_action_plan(self.definition, self.run_id, stage, resolved, self.now)
        if action_plan.plan_digest != expected.plan_digest:
            raise WorkflowRuntimeError("laboratory_plan_or_input_changed")
        authorization = create_execution_authorization(
            action_plan, signer=self.signer, engagement=self.engagement,
            worker_identity=worker_identity, issued_at=self.now,
            authorized_until_utc=self.authorized_until, authorization_id=authorization_id,
        )
        self.store.store_authorization(authorization)
        receipt = super().consume_authorization(authorization_id, action_plan, worker_identity)
        self.plan_digests[stage] = action_plan.plan_digest
        return receipt


def run_integrated_service_laboratory(
    state_dir: str | Path, *, workflow_id: str, require_isolation: bool = False,
    run_id: str | None = None, git_sha256: str | None = None,
    consent_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Exercise one catalog workflow with one-use, action-bound approvals."""
    probe = probe_isolated_runtime()
    if require_isolation and not probe.verified:
        raise IsolationRequiredError(probe)
    definition = laboratory_workflow(workflow_id)
    if workflow_id == "leaked-credential-blast-radius":
        git_sha256 = git_sha256 or _runtime_git_pin()
    path = Path(state_dir)
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    telemetry_path = path / "telemetry.jsonl"
    actual_run_id = run_id or "integrated-" + secrets.token_hex(8)
    telemetry = _Telemetry(telemetry_path, correlation_id=actual_run_id)
    token = "COPS_TEST_TOKEN_" + secrets.token_urlsafe(32)
    current = datetime.now(timezone.utc).replace(microsecond=0)
    now = _utc(current)
    start = _utc(current - timedelta(minutes=5))
    end = _utc(current + timedelta(hours=2))
    trust_end = _utc(current + timedelta(hours=3))
    key = secrets.token_bytes(32)
    signer = AuthorizationSigner("integrated-lab-key", "laboratory-operator", key, start, trust_end)
    trust = AuthorizationTrustStore([
        TrustedAuthorizationKey("integrated-lab-key", "laboratory-operator", key, start, trust_end),
    ])
    engagement = Engagement.from_dict({
        "schema_version": "cops.engagement/v1", "engagement_id": definition.engagement_id,
        "name": "Integrated service laboratory", "status": "active",
        "scope": {"included_targets": ["laboratory-loopback-services"], "excluded_targets": []},
        "window": {"started_at": start, "authorized_until_utc": trust_end},
        "operator": "laboratory-operator",
        "rules_of_engagement": {
            "max_intensity": "low", "allowed_actions": list(WORKFLOW_STAGES[workflow_id]),
            "emergency_contact": "soc@example.test", "safe_mode": True,
        },
        "created_at": start, "mode": "laboratory",
    })
    store = ApprovalStore(path / "approvals.sqlite3")
    authorization_ids: dict[str, str] = {}
    fixture = json.loads((FIXTURE_DIRECTORY / "corrected.json").read_text())
    benign_token = None
    if workflow_id == "illicit-consent-remediation":
        canonical_consent = load_consent_fixture()
        principals = {item["id"]: item for item in canonical_consent["service_principals"]}
        fixture["synthetic_grants"] = [{
            "tenant_id": grant["tenant_id"], "grant_id": grant["id"], "client_id": grant["client_id"],
            "app_id": principals[grant["client_id"]]["app_id"],
        } for grant in canonical_consent["grants"]]
        benign_token = "COPS_BENIGN_TOKEN_" + secrets.token_urlsafe(32)
    with _Graph(fixture, telemetry) as graph:
        configuration = {
            "destinations": {name: getattr(graph, name).url for name in ("identity", "resource", "hunt", "sink")},
            "workflow_id": workflow_id,
        }
        if workflow_id == "leaked-credential-blast-radius":
            configuration["git_sha256"] = git_sha256
        if workflow_id == "illicit-consent-remediation":
            configuration["consent_evidence"] = copy.deepcopy(canonical_consent if consent_evidence is None else consent_evidence)
            setup_status, _ = _request_json(graph.identity.url + "/issue-grant", method="POST",
                                            payload={"token": token, "identity": fixture["synthetic_grants"][0]})
            benign_status, _ = _request_json(graph.identity.url + "/issue-grant", method="POST",
                                             payload={"token": benign_token, "identity": fixture["synthetic_grants"][1]})
            if benign_status != 201:
                raise ValueError("benign grant setup failed")
        else:
            setup_status, _ = _request_json(graph.identity.url + "/issue", method="POST", payload={"token": token})
        executor = _IntegratedExecutor(graph, workflow_id, configuration, telemetry, token, benign_token)
        for name in WORKFLOW_STAGES[workflow_id]:
            authorization_id = "auth-" + digest({"run_id": actual_run_id, "stage": name})[:24]
            authorization_ids[name] = authorization_id
        approval = _IntegratedApprovalControl(
            store, trust, engagement, now, signer=signer, authorized_until=end,
            definition=definition, run_id=actual_run_id, executor=executor,
            authorization_ids=authorization_ids,
        )
        runner = WorkflowRunner(path / "workflow-state", approval, WORKER, executor, clock=lambda: now)
        result = runner.run(definition, run_id=actual_run_id,
                            inputs={"configuration": configuration}, authorization_ids=authorization_ids)
        # Restore mutable service state before stopping all listeners.
        with graph._lock:
            graph.state.restore(graph.baseline)
        restored = graph.state.snapshot() == graph.baseline.snapshot()
        consumed = sum(store.get_authorization(value).status == "consumed" for value in authorization_ids.values())
    persisted_events = [json.loads(line) for line in telemetry_path.read_text().splitlines()]
    counts, alerts = _execute_detection_rules(persisted_events)
    report = {
        "schema_version": "cops.integrated-service-laboratory/v1",
        "workflow_id": workflow_id, "run_id": actual_run_id,
        "status": result.status, "setup_status": setup_status,
        "isolation": probe.to_dict(), "outputs": result.outputs,
        "stages": list(executor.executed), "requests": executor.requests,
        "authorization": {
            "provisioned": len(approval.plan_digests), "consumed": consumed,
            "plan_digests": approval.plan_digests, "bound_destinations": configuration["destinations"],
            "boundary_limitation": "in-process approval control; no production UID boundary claim",
        },
        "events": persisted_events, "event_counts": counts, "alerts": list(alerts),
        "telemetry_matches_memory": persisted_events == telemetry.events,
        "restoration": {
            "baseline_restored": restored and graph.final_reset_verified,
            "services_stopped": all(not service.thread.is_alive() for service in graph.services),
        },
        "limitations": ["synthetic service laboratory; production integrations require live validation"],
    }
    # A credential value must never enter persisted workflow state or the report.
    if any(secret in json.dumps(report) or any(secret in item.read_text() for item in (path / "workflow-state").rglob("*.json"))
           for secret in (token, benign_token) if secret):
        raise ValueError("laboratory credential escaped the executor")
    return report
