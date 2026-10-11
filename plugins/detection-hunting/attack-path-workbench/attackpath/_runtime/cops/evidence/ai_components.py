"""Offline, bounded verification records for behavior-bearing AI components.

This module neither fetches nor executes a component.  It compares caller supplied
observations with a versioned manifest and reports the assurance each input supports.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .ai_inventory import inventory_report
from .canonical import EvidenceError, canonical, digest

SCHEMA_VERSION = "cops.ai-components/v1"
MAX_COMPONENTS = 256
MAX_DEPENDENCIES = 128
MAX_OBSERVATIONS = 1_024
COMPONENT_TYPES = frozenset({"mcp_tool", "prompt_bundle", "skill_bundle", "model_alias", "dataset_reference"})


class ComponentVerificationError(EvidenceError):
    """A safe, bounded component manifest or observation validation failure."""


def _fail(code: str) -> None:
    raise ComponentVerificationError(code)


def _string(value: Any, code: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        _fail(code)
    return value


def _mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code)
    return value


def _identity_input(component: Mapping[str, Any]) -> dict[str, Any]:
    behavior = _mapping(component.get("behavior"), "invalid_behavior")
    component_type = component["component_type"]
    if component_type == "model_alias":
        alias = _string(behavior.get("alias"), "invalid_behavior")
        immutable_digest = behavior.get("immutable_digest")
        if immutable_digest is not None:
            _string(immutable_digest, "invalid_behavior", limit=128)
        return {"component_type": component_type, "alias": alias, "immutable_digest": immutable_digest}
    if component_type in {"prompt_bundle", "skill_bundle", "dataset_reference"}:
        content_digest = _string(behavior.get("content_digest"), "invalid_behavior", limit=128)
        return {"component_type": component_type, "content_digest": content_digest}
    allowed = {"name", "description", "input_schema", "output_schema", "policy"}
    if set(behavior) - allowed or {"name", "description", "input_schema", "policy"} - set(behavior):
        _fail("invalid_behavior")
    result = {
        "component_type": component_type,
        "name": _string(behavior["name"], "invalid_behavior"),
        "description": _string(behavior["description"], "invalid_behavior"),
        "input_schema": behavior["input_schema"],
        "policy": behavior["policy"],
    }
    if "output_schema" in behavior:
        result["output_schema"] = behavior["output_schema"]
    canonical(result, max_bytes=64 * 1024)
    return result


def canonical_component_identity(component: Mapping[str, Any]) -> str:
    """Return a stable identity over behavior-bearing fields only."""
    return digest(_identity_input(component), max_bytes=64 * 1024)


def _component(value: Any) -> dict[str, Any]:
    item = _mapping(value, "invalid_component")
    allowed = {
        "component_id",
        "component_type",
        "source",
        "version",
        "expected_publisher",
        "provenance_evidence_refs",
        "licensing_decision_id",
        "dependencies",
        "behavior",
        "signature",
        "organizational_approval",
        "inventory_asset_id",
    }
    if set(item) - allowed or {
        "component_id",
        "component_type",
        "source",
        "version",
        "expected_publisher",
        "provenance_evidence_refs",
        "licensing_decision_id",
        "dependencies",
        "behavior",
    } - set(item):
        _fail("invalid_component")
    component_type = _string(item["component_type"], "invalid_component")
    if component_type not in COMPONENT_TYPES:
        _fail("invalid_component_type")
    source = _mapping(item["source"], "invalid_component")
    if set(source) != {"provider", "name"}:
        _fail("invalid_component")
    refs = item["provenance_evidence_refs"]
    dependencies = item["dependencies"]
    if (
        not isinstance(refs, list)
        or not isinstance(dependencies, list)
        or len(refs) > MAX_DEPENDENCIES
        or len(dependencies) > MAX_DEPENDENCIES
    ):
        _fail("invalid_component")
    result = {
        "component_id": _string(item["component_id"], "invalid_component"),
        "component_type": component_type,
        "source": {key: _string(source[key], "invalid_component") for key in source},
        "version": _string(item["version"], "invalid_component"),
        "expected_publisher": _string(item["expected_publisher"], "invalid_component"),
        "provenance_evidence_refs": sorted({_string(ref, "invalid_component") for ref in refs}),
        "licensing_decision_id": _string(item["licensing_decision_id"], "invalid_component"),
        "dependencies": sorted({_string(dep, "invalid_component") for dep in dependencies}),
        "behavior": dict(_mapping(item["behavior"], "invalid_behavior")),
    }
    for optional in ("signature", "organizational_approval"):
        if optional in item:
            value = _mapping(item[optional], "invalid_component")
            result[optional] = dict(value)
    if "inventory_asset_id" in item:
        result["inventory_asset_id"] = _string(item["inventory_asset_id"], "invalid_component")
    result["identity"] = canonical_component_identity(result)
    return result


def _licensing_decision(decision_id: str) -> dict[str, str] | None:
    """Return the registered #209 decision, without treating a manifest claim as review."""
    try:
        # Keep this import lazy because the registry imports contract validation,
        # which imports evidence helpers while initializing.
        from cops.scenarios.registry import RegistryError, load_provenance_registry

        decisions = load_provenance_registry().get("decisions", [])
    except RegistryError:
        return None
    for decision in decisions:
        if isinstance(decision, Mapping) and decision.get("decision_id") == decision_id:
            rationale = decision.get("rationale")
            if isinstance(rationale, str) and rationale:
                return {"decision_id": decision_id, "rationale": rationale}
    return None


def validate_component_manifest(
    manifest: Mapping[str, Any], *, inventory: Mapping[str, Any] | None = None, engagement_id: str | None = None
) -> dict[str, Any]:
    """Validate and normalize a local component declaration without side effects."""
    canonical(manifest, max_bytes=512 * 1024)
    document = _mapping(manifest, "invalid_manifest")
    if set(document) != {"schema_version", "manifest_id", "policy", "components"}:
        _fail("invalid_manifest")
    if document["schema_version"] != SCHEMA_VERSION:
        _fail("unsupported_schema")
    policy = _mapping(document["policy"], "invalid_manifest")
    if set(policy) != {"version", "signing_required"} or type(policy["signing_required"]) is not bool:
        _fail("invalid_policy")
    components = document["components"]
    if not isinstance(components, list) or not components or len(components) > MAX_COMPONENTS:
        _fail("invalid_manifest")
    normalized = [_component(component) for component in components]
    if len({component["component_id"] for component in normalized}) != len(normalized):
        _fail("duplicate_component")
    identifiers = {component["component_id"] for component in normalized}
    if any(not set(component["dependencies"]) <= identifiers for component in normalized):
        _fail("unknown_dependency")
    for component in normalized:
        if _licensing_decision(component["licensing_decision_id"]) is None:
            _fail("missing_licensing_decision")
    if inventory is not None:
        if engagement_id is None:
            _fail("inventory_engagement_required")
        try:
            inventory_report(inventory, engagement_id=engagement_id)
        except EvidenceError as error:
            _fail(error.code)
        snapshot = _mapping(inventory, "invalid_inventory")
        assets = snapshot.get("assets")
        if not isinstance(assets, list):
            _fail("invalid_inventory")
        available = {asset.get("qualified_id") for asset in assets if isinstance(asset, Mapping)}
        for component in normalized:
            asset_id = component.get("inventory_asset_id")
            if asset_id is not None and asset_id not in available:
                _fail("component_absent_from_inventory")
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": _string(document["manifest_id"], "invalid_manifest"),
        "policy": {
            "version": _string(policy["version"], "invalid_policy"),
            "signing_required": policy["signing_required"],
        },
        "components": sorted(normalized, key=lambda item: item["component_id"]),
    }


def _provenance(refs: Sequence[str], revoked: set[str]) -> tuple[str, list[str]]:
    if not refs:
        return "missing_provenance", []
    if revoked.intersection(refs):
        return "revoked_evidence", list(sorted(revoked.intersection(refs)))
    missing = []
    for reference in refs:
        try:
            # Import on demand: the scenario registry depends on contract validation,
            # which in turn imports canonical evidence helpers during initialization.
            from cops.scenarios.registry import RegistryError, get_provenance_source

            get_provenance_source(reference)
        except RegistryError:
            missing.append(reference)
    return ("recorded" if not missing else "missing_provenance"), missing


def verify_component_manifest(
    manifest: Mapping[str, Any],
    *,
    observations: Sequence[Mapping[str, Any]] = (),
    revoked_evidence_ids: Sequence[str] = (),
    trusted_verification_receipts: Sequence[Mapping[str, Any]] = (),
    inventory: Mapping[str, Any] | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Report local verification states from supplied observations; never execute or fetch."""
    normalized = validate_component_manifest(manifest, inventory=inventory, engagement_id=engagement_id)
    if (
        not isinstance(observations, Sequence)
        or isinstance(observations, (str, bytes))
        or len(observations) > MAX_OBSERVATIONS
    ):
        _fail("invalid_observations")
    revoked = {_string(item, "invalid_revocation") for item in revoked_evidence_ids}
    if (
        not isinstance(trusted_verification_receipts, Sequence)
        or isinstance(trusted_verification_receipts, (str, bytes))
        or len(trusted_verification_receipts) > MAX_COMPONENTS
    ):
        _fail("invalid_verification_receipts")
    receipts = set()
    for receipt in trusted_verification_receipts:
        item = _mapping(receipt, "invalid_verification_receipt")
        if set(item) != {"receipt_id", "component_id", "identity", "verifier"}:
            _fail("invalid_verification_receipt")
        receipts.add(
            tuple(
                _string(item[key], "invalid_verification_receipt", limit=1024)
                for key in ("receipt_id", "component_id", "identity", "verifier")
            )
        )
    observed = {}
    for observation in observations:
        item = _mapping(observation, "invalid_observation")
        if set(item) != {"component_id", "identity", "manifest_id"}:
            _fail("invalid_observation")
        component_id = _string(item["component_id"], "invalid_observation")
        if component_id in observed:
            _fail("duplicate_observation")
        observed[component_id] = {key: _string(item[key], "invalid_observation", limit=1024) for key in item}
    results = []
    for component in normalized["components"]:
        provenance, provenance_detail = _provenance(component["provenance_evidence_refs"], revoked)
        signature = component.get("signature", {})
        signature_status = signature.get("status", "missing")
        if signature_status not in {"verified", "failed", "untrusted", "unsupported", "unsigned_allowed", "missing"}:
            _fail("invalid_signature_status")
        authenticity = {
            "verified": "verified",
            "failed": "signature_failure",
            "untrusted": "untrusted_signer",
            "unsupported": "unsupported_verification",
            "unsigned_allowed": "unsigned_allowed",
            "missing": "missing_signature",
        }[signature_status]
        if signature_status == "verified":
            receipt_id = signature.get("receipt_id")
            if (
                not isinstance(receipt_id, str)
                or not receipt_id
                or not any(
                    receipt[0] == receipt_id
                    and receipt[1] == component["component_id"]
                    and receipt[2] == component["identity"]
                    for receipt in receipts
                )
            ):
                authenticity = "unverified_signature_claim"
        approval = component.get("organizational_approval", {}).get("status", "missing")
        if approval not in {"approved", "missing", "revoked"}:
            _fail("invalid_approval_status")
        observation = observed.get(component["component_id"])
        integrity = "not_observed"
        if observation:
            integrity = "match" if observation["identity"] == component["identity"] else "substituted"
            if observation["manifest_id"] != normalized["manifest_id"]:
                integrity = "stale_manifest"
        if component["component_type"] == "model_alias" and component["behavior"].get("immutable_digest") is None:
            integrity = "limited_opaque_alias" if integrity in {"not_observed", "match"} else integrity
        blocked = (
            integrity in {"substituted", "stale_manifest"} or provenance == "revoked_evidence" or approval == "revoked"
        )
        blocked = blocked or (normalized["policy"]["signing_required"] and authenticity != "verified")
        licensing = _licensing_decision(component["licensing_decision_id"])
        results.append(
            {
                "component_id": component["component_id"],
                "identity": component["identity"],
                "integrity": integrity,
                "authenticity": authenticity,
                "provenance": provenance,
                "provenance_detail": provenance_detail,
                "organizational_approval": approval,
                "licensing_decision": licensing,
                "outcome": "rejected"
                if blocked
                else (
                    "limited"
                    if integrity != "match"
                    or authenticity
                    in {
                        "unsigned_allowed",
                        "unsupported_verification",
                        "unverified_signature_claim",
                    }
                    or provenance != "recorded"
                    or approval != "approved"
                    else "verified"
                ),
            }
        )
    return {
        "schema_version": "cops.ai-component-verification-report/v1",
        "manifest_id": normalized["manifest_id"],
        "policy_version": normalized["policy"]["version"],
        "components": results,
    }


def assess_component_baselines(
    manifest: Mapping[str, Any], baselines: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Mark a caller-held assessment stale when a reviewed identity no longer matches.

    A previous stale state stays stale when a component is restored; a new human
    review record is required to reset that state outside this function.
    """
    normalized = validate_component_manifest(manifest)
    identities = {component["component_id"]: component["identity"] for component in normalized["components"]}
    output = []
    for baseline in baselines:
        item = _mapping(baseline, "invalid_baseline")
        if set(item) != {
            "baseline_id",
            "reviewed_identities",
            "state",
            "component_test_dependencies",
            "component_assessment_scope",
        } or item["state"] not in {"current", "stale"}:
            _fail("invalid_baseline")
        reviewed = _mapping(item["reviewed_identities"], "invalid_baseline")
        changed = sorted(
            component_id for component_id, identity in reviewed.items() if identities.get(component_id) != identity
        )
        test_dependencies = _mapping(item["component_test_dependencies"], "invalid_baseline")
        scope_dependencies = _mapping(item["component_assessment_scope"], "invalid_baseline")
        known_components = set(reviewed)
        affected_tests = []
        for test_id, component_ids in test_dependencies.items():
            test_id = _string(test_id, "invalid_baseline")
            if not isinstance(component_ids, list) or not set(component_ids) <= known_components:
                _fail("invalid_baseline")
            if set(component_ids).intersection(changed):
                affected_tests.append(test_id)
        affected_scope = set()
        for component_id, scopes in scope_dependencies.items():
            component_id = _string(component_id, "invalid_baseline")
            if component_id not in known_components or not isinstance(scopes, list):
                _fail("invalid_baseline")
            if component_id in changed:
                affected_scope.update(_string(scope, "invalid_baseline") for scope in scopes)
        state = "stale" if item["state"] == "stale" or changed else "current"
        output.append(
            {
                "baseline_id": _string(item["baseline_id"], "invalid_baseline"),
                "state": state,
                "review_required": state == "stale",
                "retest_required": state == "stale",
                "changed_components": changed,
                "affected_tests": sorted(affected_tests),
                "affected_assessment_scope": sorted(affected_scope),
            }
        )
    return output
