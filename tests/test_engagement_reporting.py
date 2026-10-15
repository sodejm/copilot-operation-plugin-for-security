"""Offline engagement report claims stay bounded by linked evidence and scope."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from cops.contracts.lifecycle import ContractError
from cops.contracts.validation import validate_contract
from cops.evidence import build_envelope
from cops.reporting.assessment import ReportError, build_assessment_report, render_markdown
from cops.reporting.cli import command_engagement_report

FIXTURES = Path(__file__).resolve().parents[1] / "cops" / "contracts" / "fixtures"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _envelope(
    *, observed_at: str | None = "2026-10-02T10:05:00Z", target: str = "10.0.0.5", observation: str = "HTTP service"
) -> dict:
    return build_envelope(
        acquisition_id="collection-1",
        product="offline-import",
        api="records/v1",
        tenant="tenant-1",
        scope=[target],
        identity=f"host-{target}",
        locator="private-locator",
        payload={"secret": "DO_NOT_EXPORT", "observation": observation},
        acquired_at="2026-10-02T10:05:00Z",
        transformed_at="2026-10-02T10:05:00Z",
        observed_at=observed_at,
        request_fingerprint="a" * 64,
        page=1,
        raw_reference={"store_id": "PRIVATE_STORE_ID", "sha256": "b" * 64},
    )


def _bundle(*, mode: str = "laboratory") -> dict:
    evidence = _envelope()
    engagement = _fixture("valid_engagement.json")
    engagement["mode"] = mode
    run = _fixture("valid_run_result_success.json")
    plan = _fixture("valid_action_plan.json")
    if mode == "live":
        plan["status"] = "fulfilled"
    run["evidence_records"] = [evidence["record_id"]]
    finding = _fixture("valid_finding_verified.json")
    finding["evidence_references"] = [evidence["record_id"]]
    return {
        "schema_version": "cops.assessment-input/v1",
        "report_id": "report-internal-001",
        "generated_at": "2026-10-02T12:00:00Z",
        "engagement": engagement,
        "action_plans": [plan],
        "run_results": [run],
        "findings": [finding],
        "evidence_envelopes": [evidence],
        "coverage": [
            {
                "scenario_id": finding["scenario_id"],
                "target": "10.0.0.5",
                "mode": mode,
                "access": "available",
                "result_id": run["result_id"],
            }
        ],
        "finding_contexts": [
            {
                "finding_id": finding["finding_id"],
                "kind": "observed_behavior",
                "affected_assets": ["10.0.0.5"],
                "reproducibility": "repeatable",
                "attack_path_dependencies": [],
                "limitations": [],
            }
        ],
        "limitations": ["Only the selected service was reviewed."],
    }


def test_accepted_and_rejected_bundle_fixtures():
    accepted = _fixture("valid_assessment_input.json")
    validate_contract(accepted, "assessment_input")
    assert build_assessment_report(accepted)["coverage"][0]["status"] == "assessed"

    rejected = _fixture("invalid_assessment_input_conflicting_mode.json")
    validate_contract(rejected, "assessment_input")
    with pytest.raises(ReportError, match="conflicting coverage modes"):
        build_assessment_report(rejected)


def test_report_joins_evidence_and_excludes_sensitive_source_fields():
    bundle = _bundle()
    bundle["run_results"][0]["artifacts"][0]["path"] = "DO_NOT_EXPORT_PATH"
    bundle["engagement"]["credential_references"] = ["DO_NOT_EXPORT_CREDENTIAL_REF"]
    report = build_assessment_report(bundle)
    validate_contract(report, "assessment_report")
    assert report["coverage"][0]["status"] == "assessed"
    assert report["coverage"][0]["provenance"] == "laboratory"
    assert report["findings"][0]["evidence_strength"] == "recorded"
    assert report["findings"][0]["assessment_status"] == "assessed"
    serialized = json.dumps(report) + render_markdown(report)
    for marker in ("DO_NOT_EXPORT", "PRIVATE_STORE_ID", "private-locator", "tenant-1"):
        assert marker not in serialized


def test_saved_report_rejects_evidence_on_resultless_coverage():
    report = build_assessment_report(_bundle())
    report["coverage"].append(
        {
            "scenario_id": "COPS-E17.01-S02",
            "target": "10.0.0.5",
            "mode": "planning",
            "provenance": "planned",
            "access": "available",
            "status": "not_assessed",
            "result_id": None,
            "evidence_records": [report["coverage"][0]["evidence_records"][0]],
        }
    )
    with pytest.raises(ContractError, match="coverage without a result cannot carry evidence"):
        validate_contract(report, "assessment_report")


def test_saved_report_rejects_replaced_evidence_notice():
    report = build_assessment_report(_bundle())
    report["evidence_notice"] = "Record hashes prove this source is authentic and authorized."
    with pytest.raises(ContractError, match="evidence notice"):
        validate_contract(report, "assessment_report")
    with pytest.raises(ReportError, match="invalid assessment_report contract"):
        render_markdown(report)


def test_saved_report_rejects_removed_per_asset_gap():
    bundle = _bundle()
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    report = build_assessment_report(bundle)
    report["findings"][0]["limitations"] = []
    with pytest.raises(ContractError, match="finding omits unassessed assets"):
        validate_contract(report, "assessment_report")


def test_partial_and_missing_access_stay_not_assessed():
    bundle = _bundle()
    bundle["coverage"].append(
        {
            "scenario_id": "COPS-E17.01-S02",
            "target": "10.0.0.6",
            "mode": "planning",
            "access": "unavailable",
            "result_id": None,
        }
    )
    bundle["run_results"][0]["status"] = "partial"
    bundle["run_results"][0]["status_details"]["reason"] = "collection incomplete"
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "partial"
    assert report["coverage"][1]["status"] == "not_assessed"
    assert report["findings"][0]["assessment_status"] == "partial"
    assert "collection incomplete" not in render_markdown(report)


def test_finding_with_unassessed_asset_is_partial_and_discloses_gap():
    bundle = _bundle()
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    bundle["coverage"].append(
        {
            "scenario_id": bundle["findings"][0]["scenario_id"],
            "target": "10.0.0.6",
            "mode": "planning",
            "access": "unavailable",
            "result_id": None,
        }
    )
    report = build_assessment_report(bundle)
    finding = report["findings"][0]
    assert report["coverage"][1]["status"] == "not_assessed"
    assert finding["assessment_status"] == "partial"
    assert finding["evidence_strength"] == "limited"
    assert finding["limitations"] == ["Not assessed for assets: 10.0.0.6"]


def test_missing_envelope_downgrades_finding_and_coverage():
    bundle = _bundle()
    bundle["evidence_envelopes"] = []
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "not_assessed"
    assert report["findings"][0]["assessment_status"] == "not_assessed"
    assert report["findings"][0]["evidence_strength"] == "missing"
    assert any("missing validated evidence" in item for item in report["limitations"])


def test_contradictory_evidence_is_unresolved():
    bundle = _bundle()
    bundle["findings"][0]["verification"] = "contradicted"
    report = build_assessment_report(bundle)
    assert report["findings"][0]["assessment_status"] == "unresolved"
    assert report["findings"][0]["evidence_strength"] == "contradicted"
    assert report["findings"][0]["classification"] == "unresolved"
    assert "Contradicted" in render_markdown(report)


def test_contradiction_without_linked_evidence_remains_unresolved():
    bundle = _bundle()
    bundle["findings"][0]["verification"] = "contradicted"
    bundle["evidence_envelopes"] = []
    finding = build_assessment_report(bundle)["findings"][0]
    assert finding["assessment_status"] == "unresolved"
    assert finding["evidence_strength"] == "missing"


def test_input_contract_rejects_unknown_context_fields():
    bundle = _bundle()
    bundle["finding_contexts"][0]["source_payload"] = "secret"
    with pytest.raises(ReportError, match="invalid assessment_input contract"):
        build_assessment_report(bundle)


def test_historical_import_keeps_import_provenance_and_cannot_claim_reproduction():
    bundle = _bundle(mode="import")
    bundle["finding_contexts"][0]["reproducibility"] = "historical_import"
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["provenance"] == "imported"
    assert report["findings"][0]["evidence_strength"] == "limited"
    assert report["findings"][0]["assessment_status"] == "partial"
    bundle["finding_contexts"][0]["kind"] = "reproduced_attack_path"
    with pytest.raises(ReportError, match="reproduced attack path"):
        build_assessment_report(bundle)


def test_live_mode_requires_proven_result_and_evidence_for_live_validated_label():
    bundle = _bundle(mode="live")
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["provenance"] == "live_validated"
    bundle["evidence_envelopes"] = []
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["provenance"] == "live_unvalidated"


@pytest.mark.parametrize("observed_at", [None, "2026-10-02T10:04:59Z", "2026-10-02T10:05:31Z"])
def test_live_observation_must_be_within_run_window(observed_at):
    bundle = _bundle(mode="live")
    bundle["evidence_envelopes"] = [_envelope(observed_at=observed_at)]
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["provenance"] == "live_unvalidated"
    assert report["coverage"][0]["status"] == "not_assessed"
    assert report["findings"][0]["assessment_status"] == "not_assessed"


def test_scanner_only_result_cannot_be_assessed():
    bundle = _bundle()
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "partial"
    assert report["findings"][0]["assessment_status"] == "partial"
    assert report["findings"][0]["evidence_strength"] == "limited"


def test_scanner_claim_does_not_downgrade_other_asset_in_same_run():
    bundle = _bundle()
    bundle["engagement"]["scope"]["excluded_targets"] = []
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    bundle["action_plans"][0]["target"] = "10.0.0.0/24"
    from cops.contracts.validation import build_action_plan_digest

    bundle["action_plans"][0]["plan_digest"] = build_action_plan_digest(
        snapshot={
            key: value for key, value in bundle["action_plans"][0].items() if key not in {"status", "plan_digest"}
        }
    )
    second = _envelope(target="10.0.0.6")
    bundle["evidence_envelopes"].append(second)
    bundle["run_results"][0]["evidence_records"].append(second["record_id"])
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.6"})

    report = build_assessment_report(bundle)
    assert [row["status"] for row in report["coverage"]] == ["partial", "assessed"]
    validate_contract(report, "assessment_report")


def test_observation_on_other_asset_does_not_corroborate_broad_scanner_coverage():
    bundle = _bundle()
    bundle["engagement"]["scope"]["excluded_targets"] = []
    plan = bundle["action_plans"][0]
    plan["target"] = "10.0.0.0/24"
    from cops.contracts.validation import build_action_plan_digest

    plan["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in plan.items() if key not in {"status", "plan_digest"}}
    )
    broad_evidence = _envelope(target="10.0.0.0/24")
    other_evidence = _envelope(target="10.0.0.6")
    bundle["evidence_envelopes"] = [broad_evidence, other_evidence]
    bundle["run_results"][0]["evidence_records"] = [broad_evidence["record_id"], other_evidence["record_id"]]
    bundle["coverage"][0]["target"] = "10.0.0.0/24"
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.6"})
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    bundle["findings"][0]["evidence_references"] = [broad_evidence["record_id"]]
    observation = deepcopy(bundle["findings"][0])
    observation["finding_id"] = "find-other-asset-001"
    observation["evidence_references"] = [other_evidence["record_id"]]
    bundle["findings"].append(observation)
    context = deepcopy(bundle["finding_contexts"][0])
    context.update(
        {
            "finding_id": observation["finding_id"],
            "kind": "observed_behavior",
            "affected_assets": ["10.0.0.6"],
            "limitations": ["Not assessed for assets: 10.0.0.6"],
        }
    )
    bundle["finding_contexts"].append(context)

    report = build_assessment_report(bundle)
    assert [row["status"] for row in report["coverage"]] == ["partial", "assessed"]
    assert [finding["assessment_status"] for finding in report["findings"]] == ["partial", "assessed"]
    validate_contract(report, "assessment_report")
    report["coverage"][0]["status"] = "assessed"
    with pytest.raises(ContractError, match="scanner result lacks assessed corroboration"):
        validate_contract(report, "assessment_report")


def test_broad_scanner_row_downgrade_also_limits_other_findings_on_that_row():
    bundle = _bundle()
    bundle["engagement"]["scope"]["excluded_targets"] = []
    plan = bundle["action_plans"][0]
    plan["target"] = "10.0.0.0/24"
    from cops.contracts.validation import build_action_plan_digest

    plan["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in plan.items() if key not in {"status", "plan_digest"}}
    )
    broad_evidence = _envelope(target="10.0.0.0/24")
    other_evidence = _envelope(target="10.0.0.0/24", observation="HTTP service on 10.0.0.6")
    bundle["evidence_envelopes"] = [broad_evidence, other_evidence]
    bundle["run_results"][0]["evidence_records"] = [broad_evidence["record_id"], other_evidence["record_id"]]
    bundle["coverage"][0]["target"] = "10.0.0.0/24"
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    bundle["findings"][0]["evidence_references"] = [broad_evidence["record_id"]]
    observation = deepcopy(bundle["findings"][0])
    observation["finding_id"] = "find-other-asset-001"
    observation["evidence_references"] = [other_evidence["record_id"]]
    bundle["findings"].append(observation)
    context = deepcopy(bundle["finding_contexts"][0])
    context.update(
        {"finding_id": observation["finding_id"], "kind": "observed_behavior", "affected_assets": ["10.0.0.6"]}
    )
    bundle["finding_contexts"].append(context)

    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "partial"
    assert [finding["assessment_status"] for finding in report["findings"]] == ["partial", "partial"]
    assert report["findings"][1]["evidence_strength"] == "limited"
    assert report["findings"][1]["limitations"] == ["Not assessed for assets: 10.0.0.6"]
    validate_contract(report, "assessment_report")


def test_unverified_non_scanner_finding_does_not_promote_scanner_coverage():
    bundle = _bundle()
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    second = deepcopy(bundle["findings"][0])
    second["finding_id"] = "find-unverified-001"
    second["verification"] = "unverified"
    second["evidence_references"] = []
    bundle["findings"].append(second)
    context = deepcopy(bundle["finding_contexts"][0])
    context["finding_id"] = second["finding_id"]
    context["kind"] = "observed_behavior"
    bundle["finding_contexts"].append(context)
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "partial"
    assert all(finding["assessment_status"] != "assessed" for finding in report["findings"])
    validate_contract(report, "assessment_report")


@pytest.mark.parametrize("missing_field", ["finding_id", "result_id"])
def test_malformed_embedded_finding_is_rejected_as_report_error(missing_field):
    bundle = _bundle()
    del bundle["findings"][0][missing_field]
    with pytest.raises(ReportError, match="invalid finding contract"):
        build_assessment_report(bundle)


def test_evidence_for_one_asset_cannot_assess_another():
    bundle = _bundle()
    bundle["engagement"]["scope"]["excluded_targets"] = []
    bundle["action_plans"][0]["target"] = "10.0.0.0/24"
    from cops.contracts.validation import build_action_plan_digest

    bundle["action_plans"][0]["plan_digest"] = build_action_plan_digest(
        snapshot={
            key: value for key, value in bundle["action_plans"][0].items() if key not in {"status", "plan_digest"}
        }
    )
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.6"})
    report = build_assessment_report(bundle)
    assert report["coverage"][1]["status"] == "not_assessed"
    assert report["findings"][0]["assessment_status"] == "partial"
    assert report["findings"][0]["limitations"] == ["Not assessed for assets: 10.0.0.6"]


def test_distinct_evidence_for_each_asset_supports_multi_asset_finding():
    bundle = _bundle()
    bundle["engagement"]["scope"]["excluded_targets"] = []
    bundle["action_plans"][0]["target"] = "10.0.0.0/24"
    from cops.contracts.validation import build_action_plan_digest

    bundle["action_plans"][0]["plan_digest"] = build_action_plan_digest(
        snapshot={
            key: value for key, value in bundle["action_plans"][0].items() if key not in {"status", "plan_digest"}
        }
    )
    second = _envelope(target="10.0.0.6")
    bundle["evidence_envelopes"].append(second)
    bundle["run_results"][0]["evidence_records"].append(second["record_id"])
    bundle["findings"][0]["evidence_references"].append(second["record_id"])
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.6"})
    report = build_assessment_report(bundle)
    assert [row["status"] for row in report["coverage"]] == ["assessed", "assessed"]
    assert report["findings"][0]["assessment_status"] == "assessed"
    validate_contract(report, "assessment_report")


def test_orphan_action_plan_is_rejected():
    bundle = _bundle()
    extra = deepcopy(bundle["action_plans"][0])
    extra["plan_id"] = "plan-orphan-001"
    from cops.contracts.validation import build_action_plan_digest

    extra["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in extra.items() if key not in {"status", "plan_digest"}}
    )
    bundle["action_plans"].append(extra)
    with pytest.raises(ReportError, match="every action plan requires"):
        build_assessment_report(bundle)


def test_narrow_planning_row_does_not_represent_broad_action_plan():
    bundle = _bundle()
    bundle["engagement"]["scope"]["excluded_targets"] = []
    extra = deepcopy(bundle["action_plans"][0])
    extra["plan_id"] = "plan-broad-001"
    extra["target"] = "10.0.0.0/24"
    from cops.contracts.validation import build_action_plan_digest

    extra["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in extra.items() if key not in {"status", "plan_digest"}}
    )
    bundle["action_plans"].append(extra)
    bundle["coverage"].append(
        {
            "scenario_id": extra["scenario_id"],
            "target": "10.0.0.6",
            "mode": "planning",
            "access": "unavailable",
            "result_id": None,
        }
    )
    with pytest.raises(ReportError, match="every action plan requires"):
        build_assessment_report(bundle)


@pytest.mark.parametrize("duplicate_target", ["2001:0db8:0:0:0:0:0:5", "2001:db8::5/128"])
def test_canonical_ipv6_coverage_duplicate_is_rejected(duplicate_target):
    bundle = _bundle()
    bundle["engagement"]["scope"]["included_targets"] = ["2001:db8::/64"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    bundle["action_plans"][0]["target"] = "2001:db8::5"
    from cops.contracts.validation import build_action_plan_digest

    bundle["action_plans"][0]["plan_digest"] = build_action_plan_digest(
        snapshot={
            key: value for key, value in bundle["action_plans"][0].items() if key not in {"status", "plan_digest"}
        }
    )
    bundle["coverage"][0]["target"] = "2001:db8::5"
    bundle["coverage"].append({**bundle["coverage"][0], "target": duplicate_target})
    with pytest.raises(ReportError, match="duplicate coverage entry"):
        build_assessment_report(bundle)


def test_singleton_ipv4_network_is_duplicate_of_host_in_builder_and_saved_report():
    bundle = _bundle()
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.5/32"})
    with pytest.raises(ReportError, match="duplicate coverage entry"):
        build_assessment_report(bundle)

    report = build_assessment_report(_bundle())
    report["coverage"].append({**report["coverage"][0], "target": "10.0.0.5/32"})
    with pytest.raises(ContractError, match="duplicate report coverage entry"):
        validate_contract(report, "assessment_report")


def test_singleton_ipv6_network_is_duplicate_of_host_in_saved_report():
    report = build_assessment_report(_bundle())
    report["scope"]["included_targets"] = ["2001:db8::/64"]
    report["coverage"][0]["target"] = "2001:db8::5"
    report["coverage"].append({**report["coverage"][0], "target": "2001:db8::5/128"})
    with pytest.raises(ContractError, match="duplicate report coverage entry"):
        validate_contract(report, "assessment_report")


def test_saved_report_rejects_result_reuse_across_non_import_scenarios():
    report = build_assessment_report(_bundle())
    report["coverage"].append({**report["coverage"][0], "scenario_id": "COPS-E17.01-S02"})
    with pytest.raises(ContractError, match="conflicting coverage scenarios"):
        validate_contract(report, "assessment_report")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["coverage"][0].__setitem__("provenance", "live_validated"),
        lambda r: r["coverage"][0].__setitem__("evidence_records", []),
        lambda r: r["findings"][0].__setitem__("evidence_references", []),
        lambda r: r["findings"][0].__setitem__("affected_assets", ["10.0.0.6"]),
        lambda r: r["findings"][0].__setitem__("kind", "scanner_assertion"),
    ],
)
def test_standalone_report_rejects_promoted_or_misjoined_claims(mutation):
    report = build_assessment_report(_bundle())
    mutation(report)
    with pytest.raises(ContractError):
        validate_contract(report, "assessment_report")


@pytest.mark.parametrize(
    "status,strength,verification,classification",
    [
        ("assessed", "missing", "verified", "assessment"),
        ("partial", "missing", "verified", "assessment"),
        ("not_assessed", "recorded", "verified", "assessment"),
        ("not_assessed", "contradicted", "verified", "assessment"),
        ("unresolved", "limited", "contradicted", "unresolved"),
        ("unresolved", "missing", "verified", "unresolved"),
        ("unresolved", "recorded", "contradicted", "unresolved"),
    ],
)
def test_saved_report_rejects_inconsistent_finding_labels(status, strength, verification, classification):
    report = build_assessment_report(_bundle())
    finding = report["findings"][0]
    finding["assessment_status"] = status
    finding["evidence_strength"] = strength
    finding["verification"] = verification
    finding["classification"] = classification
    with pytest.raises(ContractError):
        validate_contract(report, "assessment_report")


def test_saved_report_requires_references_for_contradicted_strength():
    report = build_assessment_report(_bundle())
    finding = report["findings"][0]
    finding.update(
        assessment_status="unresolved",
        evidence_strength="contradicted",
        verification="contradicted",
        classification="unresolved",
        evidence_references=[],
    )
    with pytest.raises(ContractError):
        validate_contract(report, "assessment_report")


@pytest.mark.parametrize("status", ["partial", "not_assessed"])
def test_saved_report_requires_references_for_limited_strength(status):
    report = build_assessment_report(_bundle())
    finding = report["findings"][0]
    finding.update(assessment_status=status, evidence_strength="limited", evidence_references=[])
    with pytest.raises(ContractError):
        validate_contract(report, "assessment_report")


def test_saved_report_rejects_partial_finding_without_assessed_coverage():
    bundle = _bundle()
    bundle["coverage"][0]["access"] = "unavailable"
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "not_assessed"
    assert report["findings"][0]["assessment_status"] == "not_assessed"
    finding = report["findings"][0]
    finding.update(assessment_status="partial", evidence_strength="limited")
    with pytest.raises(ContractError, match="partial report finding lacks assessed or partial coverage"):
        validate_contract(report, "assessment_report")


@pytest.mark.parametrize("status", ["partial", "not_assessed"])
def test_saved_report_rejects_recorded_strength_without_assessed_evidence(status):
    report = build_assessment_report(_bundle())
    finding = report["findings"][0]
    finding["assessment_status"] = status
    finding["evidence_references"] = []
    with pytest.raises(ContractError):
        validate_contract(report, "assessment_report")


@pytest.mark.parametrize(
    "verification,status,strength",
    [
        ("verified", "partial", "contradicted"),
        ("verified", "unresolved", "limited"),
        ("contradicted", "unresolved", "limited"),
        ("contradicted", "unresolved", "recorded"),
        ("unverified", "partial", "missing"),
        ("verified", "not_assessed", "recorded"),
        ("verified", "assessed", "missing"),
    ],
)
def test_saved_report_rejects_conflicting_verification_status_and_strength(verification, status, strength):
    report = build_assessment_report(_bundle())
    finding = report["findings"][0]
    finding.update(verification=verification, assessment_status=status, evidence_strength=strength)
    if verification == "contradicted":
        finding["classification"] = "unresolved"
    with pytest.raises(ContractError):
        validate_contract(report, "assessment_report")


def test_saved_report_rejects_scanner_coverage_with_unverified_corroboration():
    bundle = _bundle()
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    report = build_assessment_report(bundle)
    report["coverage"][0]["status"] = "assessed"
    with pytest.raises(ContractError, match="scanner result lacks assessed corroboration"):
        validate_contract(report, "assessment_report")


def test_run_result_requires_matching_action_plan_except_historical_import():
    bundle = _bundle()
    bundle["action_plans"] = []
    with pytest.raises(ReportError, match="requires its action plan"):
        build_assessment_report(bundle)
    bundle["coverage"][0]["mode"] = "import"
    report = build_assessment_report(bundle)
    assert report["coverage"][0]["status"] == "partial"
    assert report["coverage"][0]["provenance"] == "imported"


def test_rejects_run_result_omitted_from_coverage():
    bundle = _bundle()
    bundle["coverage"] = []
    with pytest.raises(ReportError, match="every run result requires a coverage entry"):
        build_assessment_report(bundle)


def test_rejects_conflicting_or_planned_result_provenance():
    bundle = _bundle()
    bundle["coverage"].append({**bundle["coverage"][0], "mode": "import"})
    with pytest.raises(ReportError, match="conflicting coverage modes"):
        build_assessment_report(bundle)
    bundle["coverage"] = [{**bundle["coverage"][0], "mode": "planning"}]
    with pytest.raises(ReportError, match="planning coverage cannot reference"):
        build_assessment_report(bundle)


@pytest.mark.parametrize(
    "field,value",
    [
        ("scenario_id", "COPS-E17.01-S99"),
        ("target", "10.0.0.6"),
    ],
)
def test_rejects_action_plan_mismatch(field, value):
    bundle = _bundle()
    bundle["coverage"][0][field] = value
    with pytest.raises(ReportError, match="does not match its action plan"):
        build_assessment_report(bundle)


def test_cross_ip_version_scope_is_not_containment():
    bundle = _bundle()
    bundle["coverage"][0]["target"] = "::1"
    with pytest.raises(ReportError, match="outside engagement scope"):
        build_assessment_report(bundle)


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b["findings"][0].__setitem__("engagement_id", "eng-other-1234"),
        lambda b: b["finding_contexts"][0].__setitem__("affected_assets", ["10.0.0.1"]),
        lambda b: b["coverage"][0].__setitem__("target", "10.0.1.5"),
        lambda b: b["coverage"][0].__setitem__("result_id", "res-unknown-1234"),
    ],
)
def test_rejects_cross_engagement_or_out_of_scope_claims(change):
    bundle = _bundle()
    change(bundle)
    with pytest.raises(ReportError):
        build_assessment_report(bundle)


def test_reproduced_attack_path_requires_reproduction_evidence():
    bundle = _bundle()
    context = bundle["finding_contexts"][0]
    context["kind"] = "reproduced_attack_path"
    context["attack_path_dependencies"] = ["find-prerequisite-001"]
    prerequisite = deepcopy(bundle["findings"][0])
    prerequisite["finding_id"] = "find-prerequisite-001"
    bundle["findings"].append(prerequisite)
    prerequisite_context = deepcopy(context)
    prerequisite_context.update(
        {"finding_id": "find-prerequisite-001", "kind": "observed_behavior", "attack_path_dependencies": []}
    )
    bundle["finding_contexts"].append(prerequisite_context)
    report = build_assessment_report(bundle)
    assert report["findings"][0]["kind"] == "reproduced_attack_path"
    assert report["findings"][0]["attack_path_dependencies"] == ["find-prerequisite-001"]
    bundle["evidence_envelopes"] = []
    with pytest.raises(ReportError, match="reproduced attack path"):
        build_assessment_report(bundle)


def test_attack_path_dependencies_are_unique_and_acyclic_in_new_and_saved_reports():
    bundle = _bundle()
    context = bundle["finding_contexts"][0]
    context["kind"] = "reproduced_attack_path"
    context["attack_path_dependencies"] = ["find-prerequisite-001"]
    prerequisite = deepcopy(bundle["findings"][0])
    prerequisite["finding_id"] = "find-prerequisite-001"
    bundle["findings"].append(prerequisite)
    prerequisite_context = deepcopy(context)
    prerequisite_context.update(
        {"finding_id": "find-prerequisite-001", "kind": "observed_behavior", "attack_path_dependencies": []}
    )
    bundle["finding_contexts"].append(prerequisite_context)
    report = build_assessment_report(bundle)
    validate_contract(report, "assessment_report")

    bundle["finding_contexts"][1]["attack_path_dependencies"] = ["find-open-port-http-80"]
    with pytest.raises(ReportError, match="cyclic attack path"):
        build_assessment_report(bundle)
    report["findings"][1]["attack_path_dependencies"] = ["find-open-port-http-80"]
    with pytest.raises(ContractError, match="cyclic attack path"):
        validate_contract(report, "assessment_report")
    report["findings"][1]["attack_path_dependencies"] = []
    report["findings"][0]["attack_path_dependencies"].append("find-prerequisite-001")
    with pytest.raises(ContractError, match="duplicate attack path"):
        validate_contract(report, "assessment_report")


@pytest.mark.parametrize("dependency", ["find-absent-001", "find-open-port-http-80"])
def test_rejects_dangling_or_self_attack_path_dependency(dependency):
    bundle = _bundle()
    bundle["finding_contexts"][0]["kind"] = "reproduced_attack_path"
    bundle["finding_contexts"][0]["attack_path_dependencies"] = [dependency]
    with pytest.raises(ReportError, match="different included finding"):
        build_assessment_report(bundle)


def test_markdown_escapes_untrusted_text():
    bundle = _bundle()
    bundle["findings"][0]["title"] = "<script>alert(1)</script> | text"
    bundle["findings"][0]["claim"] = "<img src=x onerror=alert(1)>\n# forged heading"
    markdown = render_markdown(build_assessment_report(bundle))
    assert "<script>" not in markdown
    assert "<img" not in markdown
    assert "&#124;" in markdown
    assert "\n# forged heading" not in markdown


def test_markdown_removes_unicode_format_controls():
    bundle = _bundle()
    bundle["findings"][0]["title"] = "safe\u202eunsafe"
    markdown = render_markdown(build_assessment_report(bundle))
    assert "\u202e" not in markdown
    assert "safe unsafe" in markdown


def test_cli_writes_private_reports_and_refuses_overwrite(tmp_path: Path):
    import argparse

    source = tmp_path / "input.json"
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    source.write_text(json.dumps(_bundle()), encoding="utf-8")
    args = argparse.Namespace(input=source, json_output=json_path, markdown_output=markdown_path)
    assert command_engagement_report(args) == 0
    assert json_path.exists() and markdown_path.exists()
    assert json_path.stat().st_mode & 0o777 == 0o600
    assert markdown_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ReportError, match="already exists"):
        command_engagement_report(args)
