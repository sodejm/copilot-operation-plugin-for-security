"""Offline comparison of saved assessment reports for evidence-gated retesting."""

from __future__ import annotations

from typing import Any

from cops.contracts.validation import validate_contract
from cops.evidence.canonical import EvidenceError, digest, timestamp
from .assessment import ReportError, _parse_target, _safe

_MAX_BYTES = 4 * 1024 * 1024
_NOTICE = (
    "All conclusions are candidates based on supplied records. Independently verify source authenticity, "
    "observation time, ownership, cleanup, and execution authority before closure."
)


def _time(value: str):
    try:
        return timestamp(value)
    except EvidenceError as error:
        raise ReportError("invalid retest timestamp") from error


def _exact_asset(value: str) -> bool:
    parsed = _parse_target(value)
    return not hasattr(parsed, "prefixlen") and bool(value.strip())


def _same_asset(left: str, right: str) -> bool:
    return _parse_target(left) == _parse_target(right)


def _receipt_digest(receipt: dict[str, Any]) -> str:
    payload = {key: receipt[key] for key in (
        "receipt_id", "plan_id", "engagement_id", "worker_identity", "cleaned_effects", "unresolved_effects"
    )}
    return digest(payload)


def _receipt_status(receipt: dict[str, Any]) -> str:
    if receipt["unresolved_effects"]:
        return "partial" if receipt["cleaned_effects"] else "failed"
    return "completed" if receipt["cleaned_effects"] else "not_required"


def validate_retest_input_semantics(bundle: dict[str, Any]) -> None:
    """Check nested contracts, chronology, identity and receipt consistency."""
    baseline, retest = bundle["baseline_report"], bundle["retest_report"]
    for report in (baseline, retest):
        try:
            validate_contract(report, "assessment_report", max_bytes=_MAX_BYTES)
        except (ValueError, KeyError, TypeError) as error:
            raise ReportError("invalid nested assessment report") from error
    if baseline["engagement_id"] != retest["engagement_id"]:
        raise ReportError("baseline and retest engagement identities differ")
    if baseline["report_id"] == retest["report_id"]:
        raise ReportError("baseline and retest report identities must differ")
    if not (_time(baseline["generated_at"]) < _time(retest["generated_at"]) <= _time(bundle["generated_at"])):
        raise ReportError("retest must follow baseline and precede input generation")
    if not bundle["owner_reference"].strip():
        raise ReportError("owner reference cannot be blank")
    receipts: set[str] = set()
    for receipt in bundle["cleanup_receipts"]:
        try:
            validate_contract(receipt, "cleanup_receipt", max_bytes=_MAX_BYTES)
            expected = _receipt_digest(receipt)
        except (ValueError, KeyError, TypeError, EvidenceError) as error:
            raise ReportError("invalid cleanup receipt") from error
        if receipt["evidence_hash"] != expected:
            raise ReportError("cleanup receipt digest mismatch")
        if receipt["status"] != _receipt_status(receipt):
            raise ReportError("cleanup receipt status disagrees with its effects")
        if receipt["receipt_id"] in receipts:
            raise ReportError("duplicate cleanup receipt")
        receipts.add(receipt["receipt_id"])
        if receipt["engagement_id"] != baseline["engagement_id"]:
            raise ReportError("cleanup receipt engagement differs")
        if receipt["plan_id"] not in {bundle["baseline_plan_id"], bundle["retest_plan_id"]}:
            raise ReportError("cleanup receipt plan differs")
        if _time(receipt["completed_at"]) > _time(bundle["generated_at"]):
            raise ReportError("cleanup receipt is later than retest input")
    baseline_findings = {finding["finding_id"]: finding for finding in baseline["findings"]}
    seen: set[tuple[str, str]] = set()
    for check in bundle["checks"]:
        finding = baseline_findings.get(check["finding_id"])
        if finding is None:
            raise ReportError("retest check references unknown baseline finding")
        if not _exact_asset(check["asset"]) or not _exact_asset(check["retest_asset"]):
            raise ReportError("retest checks require exact asset identities")
        if not any(_same_asset(asset, check["asset"]) for asset in finding["affected_assets"]):
            raise ReportError("retest check asset differs from baseline finding")
        key = (check["finding_id"], str(_parse_target(check["asset"])))
        if key in seen:
            raise ReportError("duplicate retest check")
        seen.add(key)
    if len(bundle["checks"]) > 10000 or len(bundle["cleanup_receipts"]) > 10000:
        raise ReportError("retest input exceeds item limits")


def _result_for(check: dict[str, Any], finding: dict[str, Any], retest: dict[str, Any],
                baseline_records: set[str]) -> tuple[str, str]:
    if not _same_asset(check["asset"], check["retest_asset"]):
        return "identity_changed", "The retest asset identity differs; establish an approved identity mapping and reassess."
    outcome = check["outcome"]
    if outcome in {"inaccessible", "blocked", "not_assessed"}:
        return outcome, "The target was not affirmatively assessed in the retest."
    records = set(check["evidence_records"])
    fresh_records = records - baseline_records
    if not fresh_records:
        return "evidence_gap", "Retest requires evidence record IDs absent from the entire baseline report."
    rows = [row for row in retest["coverage"] if row["scenario_id"] == finding["scenario_id"]
            and row["status"] == "assessed" and row["mode"] in {"laboratory", "live"}
            and _same_asset(row["target"], check["retest_asset"])
            and fresh_records & set(row["evidence_records"])]
    if not rows:
        return "evidence_gap", "No exact-asset assessed laboratory or live coverage links new retest evidence to this asset."
    covered_records = set().union(*(set(row["evidence_records"]) for row in rows)) & fresh_records
    matching = [item for item in retest["findings"] if item["scenario_id"] == finding["scenario_id"]
                and any(_same_asset(asset, check["retest_asset"]) for asset in item["affected_assets"])]
    if outcome == "absent":
        if matching:
            return "evidence_gap", "Retest claims absence but the report still contains a matching finding."
        return "candidate_fixed", "Supplied assessed retest coverage supports absence for this exact asset."
    if not any(item["assessment_status"] == "assessed" and item["kind"] != "scanner_assertion"
               and covered_records & set(item["evidence_references"]) for item in matching):
        return "evidence_gap", "Present outcome lacks a matching assessed, corroborated finding."
    return "candidate_still_vulnerable", "A supplied assessed retest finding supports continued exposure."


def build_retest_report(bundle: dict[str, Any]) -> dict[str, Any]:
    """Classify each baseline finding/asset and produce closure gates, never closure."""
    try:
        validate_contract(bundle, "retest_input", max_bytes=_MAX_BYTES)
    except (ValueError, TypeError, KeyError) as error:
        raise ReportError("invalid retest input") from error
    baseline, retest = bundle["baseline_report"], bundle["retest_report"]
    baseline_records = {record for row in baseline["coverage"] for record in row["evidence_records"]}
    baseline_records.update(record for finding in baseline["findings"]
                            for record in finding["evidence_references"])
    checks = {(check["finding_id"], str(_parse_target(check["asset"]))): check for check in bundle["checks"]}
    results: list[dict[str, Any]] = []
    gates: set[str] = {
        "source_verification_required", "owner_verification_required", "cleanup_verification_required"
    }
    for finding in baseline["findings"]:
        for asset in finding["affected_assets"]:
            check = checks.get((finding["finding_id"], str(_parse_target(asset))))
            if check is None:
                status, reason = "not_assessed", "No retest check was supplied for this baseline finding and asset."
                retest_asset, records = asset, []
            else:
                status, reason = _result_for(check, finding, retest, baseline_records)
                retest_asset, records = check["retest_asset"], check["evidence_records"]
            results.append({"finding_id": finding["finding_id"], "asset": asset,
                            "retest_asset": retest_asset, "scenario_id": finding["scenario_id"],
                            "status": status, "evidence_records": records, "reason": reason})
            if status != "candidate_fixed":
                gates.add(status)
    if not results:
        gates.add("no_baseline_findings")
    if not bundle["owner_acknowledged"]:
        gates.add("owner_acknowledgement_required")
    if bundle["residual_risks"]:
        gates.add("residual_risk_review")
    receipts_by_plan = {plan: [] for plan in {bundle["baseline_plan_id"], bundle["retest_plan_id"]}}
    for receipt in bundle["cleanup_receipts"]:
        receipts_by_plan[receipt["plan_id"]].append(receipt)
    if any(not receipts for receipts in receipts_by_plan.values()):
        gates.add("cleanup_receipt_missing")
    if any(receipt["status"] not in {"completed", "not_required"} or receipt["unresolved_effects"]
           for receipt in bundle["cleanup_receipts"]):
        gates.add("cleanup_incomplete")
    if any(row["mode"] == "live" for row in retest["coverage"]):
        gates.update({"live_authority_binding_required", "cleanup_run_binding_required"})
        if bundle["baseline_plan_id"] != bundle["retest_plan_id"]:
            gates.add("fresh_authorization_required")
    actions = {
        "candidate_still_vulnerable": "Verify the source finding, then remediate the affected asset and run another bounded retest.",
        "inaccessible": "Restore authorized target access and reassess.",
        "blocked": "Resolve the execution blocker and reassess.",
        "not_assessed": "Complete the missing finding and asset retest.",
        "identity_changed": "Verify asset identity and obtain any changed scope authorization before retesting.",
        "evidence_gap": "Supply new assessed evidence linked to the exact retest asset.",
        "no_baseline_findings": "Provide a baseline with findings for retest comparison.",
        "owner_acknowledgement_required": "Obtain recorded owner acknowledgement.",
        "residual_risk_review": "Review and accept or remediate the documented residual risks.",
        "cleanup_receipt_missing": "Provide a cleanup receipt for each baseline and retest plan.",
        "cleanup_incomplete": "Resolve remaining effects and verify cleanup independently.",
        "source_verification_required": "Authenticate the source reports and underlying observations, including observation time.",
        "owner_verification_required": "Verify the owner acknowledgement with the owner or authoritative record.",
        "cleanup_verification_required": "Verify cleanup in the worker or target environment; receipt digests are self-consistency checks only.",
        "live_authority_binding_required": "Verify the live retest run consumed authority covering its exact actions and budget.",
        "cleanup_run_binding_required": "Verify that cleanup evidence belongs to this live retest run, even when plan IDs match.",
        "fresh_authorization_required": "Obtain authorization for the changed live action plan before execution unless already covered by a valid bound approval.",
    }
    return {"schema_version": "cops.retest-report/v1", "retest_id": bundle["retest_id"],
            "engagement_id": baseline["engagement_id"], "baseline_report_id": baseline["report_id"],
            "retest_report_id": retest["report_id"], "generated_at": bundle["generated_at"],
            "input_digest": digest(bundle, max_bytes=_MAX_BYTES),
            "review_context": {
                "baseline_plan_id": bundle["baseline_plan_id"],
                "retest_plan_id": bundle["retest_plan_id"],
                "owner_reference": bundle["owner_reference"],
                "owner_acknowledged": bundle["owner_acknowledged"],
                "cleanup_receipts": [{
                    "receipt_id": receipt["receipt_id"], "plan_id": receipt["plan_id"],
                    "status": receipt["status"], "unresolved_effects": receipt["unresolved_effects"],
                } for receipt in bundle["cleanup_receipts"]],
                "residual_risks": bundle["residual_risks"],
            },
            "results": results,
            "closure_status": "blocked", "closure_gates": sorted(gates),
            "next_actions": [actions[gate] for gate in sorted(gates)],
            "evidence_notice": _NOTICE}


def verify_retest_report_derivation(report: dict[str, Any], bundle: dict[str, Any]) -> None:
    """Recompute the offline comparison; this does not authenticate either source."""
    if report != build_retest_report(bundle):
        raise ReportError("saved retest report differs from supplied input")


def validate_retest_report_semantics(report: dict[str, Any]) -> None:
    context = report["review_context"]
    required_gates: set[str] = {
        "source_verification_required", "owner_verification_required", "cleanup_verification_required"
    }
    if not context["owner_acknowledged"]:
        required_gates.add("owner_acknowledgement_required")
    if context["residual_risks"]:
        required_gates.add("residual_risk_review")
    plan_ids = {context["baseline_plan_id"], context["retest_plan_id"]}
    if not plan_ids.issubset({receipt["plan_id"] for receipt in context["cleanup_receipts"]}):
        required_gates.add("cleanup_receipt_missing")
    if any(receipt["status"] not in {"completed", "not_required"} or receipt["unresolved_effects"]
           for receipt in context["cleanup_receipts"]):
        required_gates.add("cleanup_incomplete")
    if not required_gates.issubset(report["closure_gates"]):
        raise ReportError("retest report omits closure review gate")
    if report["closure_status"] != "blocked":
        raise ReportError("offline retest cannot claim review readiness without external verification")
    seen: set[tuple[str, str]] = set()
    for result in report["results"]:
        key = (result["finding_id"], str(_parse_target(result["asset"])))
        if key in seen:
            raise ReportError("duplicate retest result")
        seen.add(key)
        if result["status"] in {"candidate_fixed", "candidate_still_vulnerable"} and not result["evidence_records"]:
            raise ReportError("candidate retest result requires evidence")
        if result["status"] != "candidate_fixed" and result["status"] not in report["closure_gates"]:
            raise ReportError("non-fixed-candidate result requires a matching closure gate")


def render_retest_markdown(report: dict[str, Any]) -> str:
    validate_contract(report, "retest_report", max_bytes=_MAX_BYTES)
    lines = ["# Retest and closure review", "", f"Status: {_safe(report['closure_status'])}", "",
             "This report does not close findings or authorize execution.", "", "## Results", ""]
    for result in report["results"]:
        lines.append(f"- {_safe(result['finding_id'])} on {_safe(result['asset'])}: "
                     f"**{_safe(result['status'])}** — {_safe(result['reason'])}")
    context = report["review_context"]
    lines.extend(["", "## Closure review context", "",
                  f"- Baseline plan: {_safe(context['baseline_plan_id'])}",
                  f"- Retest plan: {_safe(context['retest_plan_id'])}",
                  f"- Owner reference: {_safe(context['owner_reference'])}",
                  f"- Owner acknowledged: {str(context['owner_acknowledged']).lower()}"])
    for receipt in context["cleanup_receipts"]:
        lines.append(f"- Cleanup receipt {_safe(receipt['receipt_id'])}: "
                     f"{_safe(receipt['status'])}; unresolved effects: {len(receipt['unresolved_effects'])}")
        for effect in receipt["unresolved_effects"]:
            lines.append(f"  - {_safe(effect['effect_id'])} on {_safe(effect['target'])}: {_safe(effect['reason'])}")
    lines.extend(f"- Residual risk: {_safe(risk)}" for risk in context["residual_risks"])
    lines.extend(["", "## Next actions", ""])
    lines.extend(f"- {_safe(action)}" for action in report["next_actions"])
    lines.extend(["", _safe(report["evidence_notice"]), ""])
    return "\n".join(lines)
