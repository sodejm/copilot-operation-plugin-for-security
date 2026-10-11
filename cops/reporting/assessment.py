"""Join validated contracts into bounded, evidence-aware offline reports."""

from __future__ import annotations

import html
import ipaddress
import re
from typing import Any

from cops.contracts.validation import validate_contract, validate_identifier
from cops.evidence.canonical import EvidenceError
from cops.evidence.validation import validate_envelope


class ReportError(ValueError):
    """An input bundle cannot support a safe assessment report."""


_INPUT_KEYS = {
    "schema_version",
    "report_id",
    "generated_at",
    "engagement",
    "action_plans",
    "run_results",
    "findings",
    "evidence_envelopes",
    "coverage",
    "finding_contexts",
    "limitations",
}
_COVERAGE_KEYS = {"scenario_id", "target", "mode", "access", "result_id"}
_CONTEXT_KEYS = {
    "finding_id",
    "kind",
    "affected_assets",
    "reproducibility",
    "attack_path_dependencies",
    "limitations",
}
_KINDS = {
    "configuration_observation",
    "scanner_assertion",
    "observed_behavior",
    "reproduced_attack_path",
}
_MODES = {"planning", "import", "laboratory", "live"}
_ACCESS = {"available", "unavailable", "unknown"}
_REPRODUCIBILITY = {"repeatable", "limited", "historical_import", "unknown"}


def _object(item: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(item) is not dict or item.keys() != keys:
        raise ReportError(f"{label} must have exactly the required fields")
    return item


def _list(item: Any, label: str) -> list[Any]:
    if type(item) is not list or len(item) > 10000:
        raise ReportError(f"{label} must be a bounded array")
    return item


def _strings(item: Any, label: str, *, nonempty: bool = False) -> list[str]:
    values = _list(item, label)
    if any(type(value) is not str or (nonempty and not value.strip()) for value in values):
        raise ReportError(f"{label} must contain strings")
    return values


def _valid_contract(item: Any, kind: str, *, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    if type(item) is not dict:
        raise ReportError(f"{kind} must be an object")
    try:
        return validate_contract(item, kind, max_bytes=max_bytes)
    except (ValueError, TypeError, KeyError) as error:
        raise ReportError(f"invalid {kind} contract") from error


def _parse_target(
    target: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network | str:
    try:
        return ipaddress.ip_network(target, strict=False) if "/" in target else ipaddress.ip_address(target)
    except ValueError:
        return target.casefold().rstrip(".")


def _contains(container: str, target: str) -> bool:
    left, right = _parse_target(container), _parse_target(target)
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if left.version != right.version:
        return False
    if isinstance(left, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return left == right
    if isinstance(right, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return right in left
    return right.subnet_of(left)


def _in_scope(target: str, scope: dict[str, Any]) -> bool:
    if not any(_contains(included, target) for included in scope["included_targets"]):
        return False
    return not any(_contains(excluded, target) or _contains(target, excluded) for excluded in scope["excluded_targets"])


def _coverage_status(
    mode: str, access: str, result: dict[str, Any] | None, evidence_ids: list[str], plan: dict[str, Any] | None
) -> str:
    if access != "available" or mode == "planning" or result is None or not evidence_ids:
        return "not_assessed"
    if mode == "import" or plan is None:
        return "partial"
    if mode == "live" and plan["status"] != "fulfilled":
        return "partial"
    if result["status"] == "success":
        return "assessed"
    if result["status"] == "partial":
        return "partial"
    return "not_assessed"


def _provenance(mode: str, status: str) -> str:
    if mode == "planning":
        return "planned"
    if mode == "import":
        return "imported"
    if mode == "laboratory":
        return "laboratory"
    return "live_validated" if status == "assessed" else "live_unvalidated"


def build_assessment_report(bundle: dict[str, Any]) -> dict[str, Any]:
    """Build a report without copying source payloads, secrets, or artifact paths.

    Record hashes establish internal integrity only. Mode and status are supplied
    by validated contracts; they do not prove source authenticity or authorization.
    """
    _object(bundle, _INPUT_KEYS, "assessment input")
    _valid_contract(bundle, "assessment_input", max_bytes=4 * 1024 * 1024)

    engagement = _valid_contract(bundle["engagement"], "engagement")
    engagement_id = engagement["engagement_id"]
    scope = engagement["scope"]
    action_plans: dict[str, dict[str, Any]] = {}
    for item in _list(bundle["action_plans"], "action_plans"):
        plan = _valid_contract(item, "action_plan")
        if plan["engagement_id"] != engagement_id or plan["plan_id"] in action_plans:
            raise ReportError("action plan engagement or identifier mismatch")
        if not _in_scope(plan["target"], scope):
            raise ReportError("action plan target is outside engagement scope")
        action_plans[plan["plan_id"]] = plan
    run_results: dict[str, dict[str, Any]] = {}
    for item in _list(bundle["run_results"], "run_results"):
        result = _valid_contract(item, "run_result")
        if result["engagement_id"] != engagement_id or result["result_id"] in run_results:
            raise ReportError("run result engagement or identifier mismatch")
        run_results[result["result_id"]] = result

    evidence: dict[str, dict[str, Any]] = {}
    for item in _list(bundle["evidence_envelopes"], "evidence_envelopes"):
        try:
            validate_envelope(item)
        except (EvidenceError, KeyError, TypeError) as error:
            raise ReportError("invalid evidence envelope") from error
        record_id = item["record_id"]
        if record_id in evidence:
            raise ReportError("duplicate evidence record")
        evidence[record_id] = item

    coverage: list[dict[str, Any]] = []
    coverage_keys: set[tuple[str, str, str]] = set()
    covered_result_ids: set[str] = set()
    result_modes: dict[str, str] = {}
    for item in _list(bundle["coverage"], "coverage"):
        row = _object(item, _COVERAGE_KEYS, "coverage entry")
        try:
            validate_identifier(row["scenario_id"], "scenario")
        except (ValueError, TypeError) as error:
            raise ReportError("invalid coverage scenario") from error
        if type(row["target"]) is not str or not row["target"].strip() or not _in_scope(row["target"], scope):
            raise ReportError("coverage target is outside engagement scope")
        if row["mode"] not in _MODES or row["access"] not in _ACCESS:
            raise ReportError("invalid coverage mode or access")
        if row["mode"] == "live" and engagement.get("mode", "planning") != "live":
            raise ReportError("live coverage requires live engagement mode")
        result_id = row["result_id"]
        if result_id is not None and (type(result_id) is not str or result_id not in run_results):
            raise ReportError("coverage references unknown run result")
        if result_id is not None:
            if row["mode"] == "planning":
                raise ReportError("planning coverage cannot reference a run result")
            if result_id in result_modes and result_modes[result_id] != row["mode"]:
                raise ReportError("run result has conflicting coverage modes")
            result_modes[result_id] = row["mode"]
            covered_result_ids.add(result_id)
        key = (row["scenario_id"], row["target"], row["mode"])
        if key in coverage_keys:
            raise ReportError("duplicate coverage entry")
        coverage_keys.add(key)
        result = run_results.get(result_id)
        plan = action_plans.get(result["plan_id"]) if result else None
        if result and plan is None and row["mode"] != "import":
            raise ReportError("non-imported run result requires its action plan")
        if plan and (plan["scenario_id"] != row["scenario_id"] or not _contains(plan["target"], row["target"])):
            raise ReportError("coverage scenario or target does not match its action plan")
        validated_ids = sorted(
            record_id
            for record_id in (result["evidence_records"] if result else [])
            if record_id in evidence
            and any(_contains(source_target, row["target"]) for source_target in evidence[record_id]["source"]["scope"])
        )
        status = _coverage_status(row["mode"], row["access"], result, validated_ids, plan)
        coverage.append(
            {
                "scenario_id": row["scenario_id"],
                "target": row["target"],
                "mode": row["mode"],
                "provenance": _provenance(row["mode"], status),
                "access": row["access"],
                "status": status,
                "result_id": result_id,
                "evidence_records": validated_ids,
            }
        )
    if covered_result_ids != run_results.keys():
        raise ReportError("every run result requires a coverage entry")

    contexts: dict[str, dict[str, Any]] = {}
    for item in _list(bundle["finding_contexts"], "finding_contexts"):
        context = _object(item, _CONTEXT_KEYS, "finding context")
        try:
            validate_identifier(context["finding_id"], "finding")
        except (ValueError, TypeError) as error:
            raise ReportError("invalid finding context identifier") from error
        if context["finding_id"] in contexts or context["kind"] not in _KINDS:
            raise ReportError("duplicate finding context or invalid kind")
        if context["reproducibility"] not in _REPRODUCIBILITY:
            raise ReportError("invalid reproducibility")
        assets = _strings(context["affected_assets"], "affected_assets", nonempty=True)
        if not assets or any(not _in_scope(asset, scope) for asset in assets):
            raise ReportError("finding asset is outside engagement scope")
        dependencies = _strings(context["attack_path_dependencies"], "attack_path_dependencies", nonempty=True)
        try:
            for dependency in dependencies:
                validate_identifier(dependency, "finding")
        except (ValueError, TypeError) as error:
            raise ReportError("invalid attack path dependency") from error
        _strings(context["limitations"], "finding limitations")
        contexts[context["finding_id"]] = context

    findings: list[dict[str, Any]] = []
    finding_ids: set[str] = set()
    limitations = _strings(bundle["limitations"], "limitations")[:]
    for item in _list(bundle["findings"], "findings"):
        finding = _valid_contract(item, "finding")
        finding_id = finding["finding_id"]
        if finding_id in finding_ids or finding_id not in contexts:
            raise ReportError("duplicate finding or missing finding context")
        finding_ids.add(finding_id)
        if finding["engagement_id"] != engagement_id or finding["result_id"] not in run_results:
            raise ReportError("finding references a different engagement or unknown run result")
        context = contexts[finding_id]
        rows = [
            row
            for row in coverage
            if row["result_id"] == finding["result_id"]
            and row["scenario_id"] == finding["scenario_id"]
            and any(_contains(row["target"], asset) for asset in context["affected_assets"])
        ]
        if not rows:
            raise ReportError("finding has no matching scoped coverage entry")
        record_ids = set(finding["evidence_references"])
        validated_ids = set().union(*(set(row["evidence_records"]) for row in rows))
        complete_evidence = bool(record_ids) and record_ids <= validated_ids
        uncovered_assets = [
            asset
            for asset in context["affected_assets"]
            if not any(row["status"] == "assessed" and _contains(row["target"], asset) for row in rows)
        ]
        best_status = (
            "assessed"
            if not uncovered_assets
            else ("partial" if any(row["status"] in {"assessed", "partial"} for row in rows) else "not_assessed")
        )
        finding_limitations = context["limitations"][:]
        if uncovered_assets:
            finding_limitations.append("Not assessed for assets: " + ", ".join(uncovered_assets))
        if finding["verification"] == "contradicted":
            assessment_status = "unresolved"
            strength = "contradicted" if complete_evidence else "missing"
            if not complete_evidence:
                message = f"{finding_id}: missing validated evidence for one or more referenced records."
                if message not in limitations:
                    limitations.append(message)
        elif not complete_evidence:
            assessment_status, strength = "not_assessed", "missing"
            message = f"{finding_id}: missing validated evidence for one or more referenced records."
            if message not in limitations:
                limitations.append(message)
        elif (
            best_status == "assessed"
            and finding["verification"] == "verified"
            and not any(row["mode"] == "import" for row in rows)
        ):
            assessment_status, strength = "assessed", "recorded"
        elif best_status in {"assessed", "partial"}:
            assessment_status, strength = "partial", "limited"
        else:
            assessment_status, strength = "not_assessed", "limited"
        if context["kind"] == "reproduced_attack_path" and (
            assessment_status != "assessed"
            or context["reproducibility"] != "repeatable"
            or not any(row["mode"] in {"laboratory", "live"} for row in rows)
        ):
            raise ReportError("reproduced attack path requires repeatable validated laboratory or live evidence")
        if context["kind"] == "reproduced_attack_path" and not context["attack_path_dependencies"]:
            raise ReportError("reproduced attack path requires declared dependencies")
        findings.append(
            {
                "finding_id": finding_id,
                "scenario_id": finding["scenario_id"],
                "result_id": finding["result_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "classification": "unresolved"
                if finding["verification"] == "contradicted"
                else finding["classification"],
                "verification": finding["verification"],
                "confidence": finding["confidence"],
                "kind": context["kind"],
                "claim": finding["claim"],
                "affected_assets": context["affected_assets"][:],
                "reproducibility": context["reproducibility"],
                "attack_path_dependencies": context["attack_path_dependencies"][:],
                "remediation": finding["remediation"],
                "uncertainty": finding["uncertainty"],
                "mitre_attack": finding["mitre_attack"][:],
                "evidence_strength": strength,
                "evidence_references": sorted(record_ids & validated_ids),
                "assessment_status": assessment_status,
                "limitations": finding_limitations,
            }
        )
    if finding_ids != contexts.keys():
        raise ReportError("orphan finding context")
    for finding in findings:
        dependencies = finding["attack_path_dependencies"]
        if finding["finding_id"] in dependencies or any(dependency not in finding_ids for dependency in dependencies):
            raise ReportError("attack path dependency must reference a different included finding")
    report = {
        "schema_version": "cops.assessment-report/v1",
        "report_id": bundle["report_id"],
        "engagement_id": engagement_id,
        "generated_at": bundle["generated_at"],
        "scope": {"included_targets": scope["included_targets"][:], "excluded_targets": scope["excluded_targets"][:]},
        "coverage": coverage,
        "findings": findings,
        "limitations": limitations,
        "evidence_notice": "Record hashes establish internal integrity only; source authenticity and authorization need separate validation.",
    }
    _valid_contract(report, "assessment_report")
    return report


def _safe(value: Any) -> str:
    escaped = html.escape(str(value), quote=True)
    escaped = re.sub(r"[\r\n\t]+", " ", escaped)
    escaped = re.sub(r"([\\`*_{}\[\]()#+!>~])", r"\\\1", escaped)
    return escaped.replace("|", "&#124;")


def render_markdown(report: dict[str, Any]) -> str:
    """Render validated report fields as escaped, non-executable Markdown text."""
    _valid_contract(report, "assessment_report")
    lines = [
        "# COPS engagement assessment",
        "",
        f"Report: {_safe(report['report_id'])}",
        f"Engagement: {_safe(report['engagement_id'])}",
        f"Generated: {_safe(report['generated_at'])}",
        "",
        "## Scope",
        "",
        "Included: " + ", ".join(map(_safe, report["scope"]["included_targets"])),
        "Excluded: " + ", ".join(map(_safe, report["scope"]["excluded_targets"])),
        "",
        "## Coverage",
        "",
        "| Scenario | Target | Provenance | Access | Assessment |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["coverage"]:
        lines.append(
            "| "
            + " | ".join(_safe(row[key]) for key in ("scenario_id", "target", "provenance", "access", "status"))
            + " |"
        )
    lines.extend(["", "## Findings", ""])
    for finding in report["findings"]:
        lines.extend(
            [
                f"### {_safe(finding['finding_id'])}: {_safe(finding['title'])}",
                "",
                f"Severity: {_safe(finding['severity'])}; kind: {_safe(finding['kind'])}; "
                f"assessment: {_safe(finding['assessment_status'])}; verification: {_safe(finding['verification'].title())}",
                f"Claim: {_safe(finding['claim'])}",
                "Affected assets: " + ", ".join(map(_safe, finding["affected_assets"])),
                f"Reproducibility: {_safe(finding['reproducibility'])}; evidence strength: {_safe(finding['evidence_strength'])}",
                "Evidence records: " + ", ".join(map(_safe, finding["evidence_references"])),
                "Attack path dependencies: " + ", ".join(map(_safe, finding["attack_path_dependencies"])),
                f"Remediation: {_safe(finding['remediation'])}",
                f"Uncertainty: {_safe(finding['uncertainty'])}",
                "Limitations: " + "; ".join(map(_safe, finding["limitations"])),
                "",
            ]
        )
    lines.extend(["## Assessment limitations", ""])
    lines.extend(f"- {_safe(item)}" for item in report["limitations"])
    lines.extend(["", _safe(report["evidence_notice"]), ""])
    return "\n".join(lines)
