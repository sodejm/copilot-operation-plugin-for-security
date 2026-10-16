"""Adapt bounded artifact assessments to the shared assessment report contract."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from cops.assessments.artifacts import CAPABILITIES, REPORT_SCHEMA, ArtifactAssessmentError
from cops.contracts.models import Finding
from cops.contracts.validation import validate_contract, validate_identifier
from cops.evidence.canonical import EvidenceError, canonical, timestamp
from cops.reporting.assessment import validate_report_semantics


ASSESSMENT_REPORT_SCHEMA = "cops.assessment-report/v1"
EVIDENCE_NOTICE = (
    "Record hashes establish internal integrity only; source authenticity and authorization need separate validation."
)
_ASSESSMENT_KEYS = {
    "schema_version",
    "capability",
    "assessment_mode",
    "generated_at",
    "readiness",
    "findings",
    "finding_codes",
    "evidence",
    "coverage",
    "limitations",
    "prerequisites",
}
_EVIDENCE_KEYS = {"artifact_id", "kind", "sha256", "bytes"}
_COVERAGE_KEYS = {"artifact_count", "analyzed_artifact_count", "kinds"}
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")
_CODE = re.compile(r"[a-z0-9_]{1,96}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_REFERENCE = re.compile(r"artifact:([A-Za-z0-9_.:-]{1,96}):sha256:([a-f0-9]{64})\Z")
_READINESS = {"supported", "limited", "insufficient_evidence"}
_MAX_ITEMS = 256


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or value.keys() != keys:
        raise ValueError("invalid object")
    return value


def _bounded_strings(value: Any, *, nonempty: bool = True) -> list[str]:
    if type(value) is not list or len(value) > _MAX_ITEMS:
        raise ValueError("invalid string list")
    if any(type(item) is not str or len(item) > 4096 or (nonempty and not item.strip()) for item in value):
        raise ValueError("invalid string list")
    return value


def _targets(target: str, excluded_targets: Sequence[str]) -> list[str]:
    if type(target) is not str or not target.strip() or len(target) > 512:
        raise ValueError("invalid target")
    if isinstance(excluded_targets, (str, bytes)) or not isinstance(excluded_targets, Sequence):
        raise ValueError("invalid excluded targets")
    if len(excluded_targets) > _MAX_ITEMS:
        raise ValueError("invalid excluded targets")
    values = list(excluded_targets)
    if any(type(item) is not str or not item.strip() or len(item) > 512 for item in values):
        raise ValueError("invalid excluded targets")
    if len(values) != len(set(values)) or target in values:
        raise ValueError("invalid excluded targets")
    return values


def _validate_context(*, report_id: str, engagement_id: str, scenario_id: str, result_id: str) -> None:
    validate_identifier(report_id, "assessment_report")
    validate_identifier(engagement_id, "engagement")
    validate_identifier(scenario_id, "scenario")
    validate_identifier(result_id, "run_result")


def _evidence_index(value: Any) -> tuple[dict[str, str], list[str], set[str]]:
    if type(value) is not list or len(value) > 64:
        raise ValueError("invalid evidence")
    by_artifact: dict[str, str] = {}
    kinds: set[str] = set()
    hashes: set[str] = set()
    for raw in value:
        item = _object(raw, _EVIDENCE_KEYS)
        artifact_id, kind, sha256, size = item["artifact_id"], item["kind"], item["sha256"], item["bytes"]
        if (
            type(artifact_id) is not str
            or not _ID.fullmatch(artifact_id)
            or artifact_id in by_artifact
            or type(kind) is not str
            or not _ID.fullmatch(kind)
            or type(sha256) is not str
            or not _SHA256.fullmatch(sha256)
            or type(size) is not int
            or size < 0
        ):
            raise ValueError("invalid evidence")
        by_artifact[artifact_id] = sha256
        kinds.add(kind)
        hashes.add(sha256)
    return by_artifact, sorted(hashes), kinds


def _coverage(value: Any, *, evidence_count: int, kinds: set[str]) -> tuple[str, str]:
    item = _object(value, _COVERAGE_KEYS)
    artifact_count = item["artifact_count"]
    analyzed_count = item["analyzed_artifact_count"]
    reported_kinds = item["kinds"]
    if (
        type(artifact_count) is not int
        or type(analyzed_count) is not int
        or artifact_count != evidence_count
        or not 0 <= analyzed_count <= artifact_count
        or type(reported_kinds) is not list
        or reported_kinds != sorted(kinds)
    ):
        raise ValueError("invalid coverage")
    return ("partial", "available") if evidence_count and analyzed_count else ("not_assessed", "unknown")


def _reference_hashes(references: list[str], evidence: Mapping[str, str]) -> list[str]:
    result: set[str] = set()
    for reference in references:
        if type(reference) is not str:
            raise ValueError("invalid evidence reference")
        match = _REFERENCE.fullmatch(reference)
        if match is None or evidence.get(match.group(1)) != match.group(2):
            raise ValueError("invalid evidence reference")
        result.add(match.group(2))
    return sorted(result)


def _adapt_finding(
    value: Any,
    *,
    evidence: Mapping[str, str],
    engagement_id: str,
    scenario_id: str,
    result_id: str,
    target: str,
    coverage_status: str,
    limitations: list[str],
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("invalid finding")
    finding = Finding.from_dict(value)
    if (
        finding.engagement_id != engagement_id
        or finding.scenario_id != scenario_id
        or finding.result_id != result_id
    ):
        raise ValueError("finding context mismatch")
    references = _reference_hashes(finding.evidence_references, evidence)
    if finding.verification == "contradicted":
        assessment_status = "unresolved"
        evidence_strength = "contradicted" if references else "missing"
        classification = "unresolved"
    elif coverage_status == "partial" and references:
        assessment_status = "partial"
        evidence_strength = "limited"
        classification = finding.classification
    else:
        assessment_status = "not_assessed"
        evidence_strength = "limited" if references else "missing"
        classification = finding.classification
    verification = "partially-verified" if finding.verification == "verified" else finding.verification
    finding_limitations = sorted(set(limitations) | {f"Not assessed for assets: {target}"})
    return {
        "finding_id": finding.finding_id,
        "scenario_id": finding.scenario_id,
        "result_id": finding.result_id,
        "title": finding.title,
        "severity": finding.severity,
        "classification": classification,
        "verification": verification,
        "confidence": finding.confidence,
        "kind": "configuration_observation",
        "claim": finding.claim,
        "affected_assets": [target],
        "reproducibility": "historical_import",
        "attack_path_dependencies": [],
        "remediation": finding.remediation,
        "uncertainty": finding.uncertainty,
        "mitre_attack": finding.mitre_attack,
        "evidence_strength": evidence_strength,
        "evidence_references": references,
        "assessment_status": assessment_status,
        "limitations": finding_limitations,
    }


def _verification_summaries(item: dict[str, Any], evidence: Mapping[str, str]) -> list[str]:
    """Keep bounded local verification outcomes in the shared report's limitations."""
    if "verification_results" not in item:
        return []
    values = item["verification_results"]
    if item["capability"] != "transport_identity" or type(values) is not list or len(values) > 64:
        raise ValueError("invalid verification results")
    codes = {
        "accepted": {"certificate_verified", "jwt_verified"},
        "rejected": {"certificate_rejected", "client_not_authorized", "jwt_rejected"},
        "unknown": {"certificate_policy_missing", "client_authorization_missing", "hostname_missing",
                    "hostname_invalid", "jwt_policy_missing", "jwt_policy_invalid", "unsupported_format",
                    "assessment_time_missing", "input_limit", "invalid_input", "prerequisite_unavailable",
                    "invalid_or_unsupported_input"},
    }
    seen: set[str] = set()
    summaries = []
    for raw in values:
        value = _object(raw, {"artifact_id", "evidence_ref", "status", "code", "fingerprints", "adapter_id"})
        artifact_id, status, code = value["artifact_id"], value["status"], value["code"]
        if (type(artifact_id) is not str or artifact_id not in evidence or artifact_id in seen
                or type(status) is not str or status not in codes or type(code) is not str or code not in codes[status]
                or value["adapter_id"] != "cryptographic-verification/v1"
                or value["evidence_ref"] != f"artifact:{artifact_id}:sha256:{evidence[artifact_id]}"):
            raise ValueError("invalid verification result")
        fingerprints = value["fingerprints"]
        if (type(fingerprints) is not list or len(fingerprints) > 16
                or any(type(value) is not str or not _SHA256.fullmatch(value) for value in fingerprints)):
            raise ValueError("invalid verification fingerprints")
        seen.add(artifact_id)
        summaries.append(f"Offline verification {artifact_id}: {status} ({code}); evidence sha256:{evidence[artifact_id]}. Remote behavior remains unverified.")
    return summaries


def _build_report(
    assessment: Mapping[str, object],
    *,
    report_id: str,
    engagement_id: str,
    scenario_id: str,
    result_id: str,
    target: str,
    excluded_targets: Sequence[str],
) -> dict[str, Any]:
    if type(assessment) is not dict:
        raise ValueError("invalid assessment")
    canonical(assessment, max_bytes=4 * 1024 * 1024, max_depth=32)
    extra_keys = {"verification_results"} if "verification_results" in assessment else set()
    item = _object(assessment, _ASSESSMENT_KEYS | extra_keys)
    if (
        item["schema_version"] != REPORT_SCHEMA
        or item["capability"] not in CAPABILITIES
        or item["assessment_mode"] != "offline"
        or item["readiness"] not in _READINESS
    ):
        raise ValueError("invalid assessment")
    timestamp(item["generated_at"])
    _validate_context(
        report_id=report_id,
        engagement_id=engagement_id,
        scenario_id=scenario_id,
        result_id=result_id,
    )
    excluded = _targets(target, excluded_targets)
    evidence, evidence_hashes, evidence_kinds = _evidence_index(item["evidence"])
    coverage_status, access = _coverage(item["coverage"], evidence_count=len(evidence), kinds=evidence_kinds)
    limitations = _bounded_strings(item["limitations"])
    prerequisites = _bounded_strings(item["prerequisites"])
    verification = _verification_summaries(item, evidence)
    report_limitations = sorted(set(limitations) | set(verification) | {f"Prerequisite: {value}" for value in prerequisites})
    raw_findings = item["findings"]
    if type(raw_findings) is not list or len(raw_findings) > _MAX_ITEMS:
        raise ValueError("invalid findings")
    finding_codes = item["finding_codes"]
    if type(finding_codes) is not dict or len(finding_codes) > _MAX_ITEMS:
        raise ValueError("invalid finding codes")
    findings = [
        _adapt_finding(
            finding,
            evidence=evidence,
            engagement_id=engagement_id,
            scenario_id=scenario_id,
            result_id=result_id,
            target=target,
            coverage_status=coverage_status,
            limitations=report_limitations,
        )
        for finding in raw_findings
    ]
    finding_ids = {finding["finding_id"] for finding in findings}
    if len(finding_ids) != len(findings) or set(finding_codes) != finding_ids:
        raise ValueError("invalid finding codes")
    if any(type(code) is not str or not _CODE.fullmatch(code) for code in finding_codes.values()):
        raise ValueError("invalid finding codes")
    report = {
        "schema_version": ASSESSMENT_REPORT_SCHEMA,
        "report_id": report_id,
        "engagement_id": engagement_id,
        "generated_at": item["generated_at"],
        "scope": {"included_targets": [target], "excluded_targets": excluded},
        "coverage": [
            {
                "scenario_id": scenario_id,
                "target": target,
                "mode": "import",
                "provenance": "imported",
                "access": access,
                "status": coverage_status,
                "result_id": result_id,
                "evidence_records": evidence_hashes,
            }
        ],
        "findings": findings,
        "limitations": report_limitations,
        "evidence_notice": EVIDENCE_NOTICE,
    }
    validate_contract(report, "assessment_report", max_bytes=4 * 1024 * 1024)
    validate_report_semantics(report)
    return report


def to_assessment_report(
    assessment: Mapping[str, object],
    *,
    report_id: str,
    engagement_id: str,
    scenario_id: str,
    result_id: str,
    target: str,
    excluded_targets: Sequence[str] = (),
) -> dict[str, Any]:
    """Convert an offline artifact assessment without overstating validation.

    Explicit report, engagement, scenario, result, and target context is required;
    the adapter never fabricates operational identifiers or scope. Invalid inputs
    fail with a stable, content-free error code.
    """
    try:
        return _build_report(
            assessment,
            report_id=report_id,
            engagement_id=engagement_id,
            scenario_id=scenario_id,
            result_id=result_id,
            target=target,
            excluded_targets=excluded_targets,
        )
    except ArtifactAssessmentError:
        raise
    except (EvidenceError, ValueError, TypeError, KeyError):
        raise ArtifactAssessmentError("invalid_artifact_assessment") from None
