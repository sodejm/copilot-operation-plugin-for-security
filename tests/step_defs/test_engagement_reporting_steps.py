"""Acceptance steps for evidence-bounded offline engagement reports."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.contracts.lifecycle import ContractError
from cops.contracts.validation import build_action_plan_digest, validate_contract
from cops.evidence import build_envelope
from cops.evidence.canonical import digest
from cops.reporting.assessment import ReportError, build_assessment_report, render_markdown

scenarios("../../specs/features/engagement_reporting.feature")

FIXTURE = Path(__file__).resolve().parents[2] / "cops/contracts/fixtures/valid_assessment_input.json"


@pytest.fixture
def report_ctx():
    return {"bundle": None, "report": None, "error": None}


@given("a valid offline assessment bundle")
def valid_bundle(report_ctx):
    report_ctx["bundle"] = json.loads(FIXTURE.read_text(encoding="utf-8"))


@given("its finding is a scanner assertion")
def scanner_assertion(report_ctx):
    report_ctx["bundle"]["finding_contexts"][0]["kind"] = "scanner_assertion"


@given("its finding is a scanner assertion with an unverified observation")
def scanner_with_unverified_observation(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    observation = deepcopy(bundle["findings"][0])
    observation["finding_id"] = "find-unverified-bdd-001"
    observation["verification"] = "unverified"
    observation["evidence_references"] = []
    bundle["findings"].append(observation)
    context = deepcopy(bundle["finding_contexts"][0])
    context["finding_id"] = observation["finding_id"]
    context["kind"] = "observed_behavior"
    bundle["finding_contexts"].append(context)


@given("its finding has no result identifier")
def missing_result_identifier(report_ctx):
    del report_ctx["bundle"]["findings"][0]["result_id"]


@given("its live observation is after the run window")
def late_live_observation(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["mode"] = "live"
    bundle["coverage"][0]["mode"] = "live"
    bundle["action_plans"][0]["status"] = "fulfilled"
    evidence = build_envelope(
        acquisition_id="collection-1",
        product="offline-import",
        api="records/v1",
        tenant="tenant-1",
        scope=["10.0.0.5"],
        identity="host-5",
        locator="private-locator",
        payload={"observation": "HTTP service"},
        acquired_at="2026-10-02T10:05:00Z",
        transformed_at="2026-10-02T10:05:00Z",
        observed_at="2026-10-02T10:05:31Z",
        request_fingerprint="a" * 64,
        page=1,
        raw_reference={"store_id": "PRIVATE_STORE_ID", "sha256": "b" * 64},
    )
    bundle["evidence_envelopes"] = [evidence]
    bundle["run_results"][0]["evidence_records"] = [evidence["record_id"]]
    bundle["findings"][0]["evidence_references"] = [evidence["record_id"]]


@given("its live observation precedes the run window")
def early_live_observation(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["mode"] = "live"
    bundle["action_plans"][0]["status"] = "fulfilled"
    bundle["coverage"][0]["mode"] = "live"
    envelope = bundle["evidence_envelopes"][0]
    envelope["observed"] = {"at": "2026-10-02T10:04:59Z", "unknown_reason": None}
    envelope["content_hash"] = digest({key: value for key, value in envelope.items() if key != "content_hash"})


@given("its finding affects a second unassessed asset")
def unassessed_second_asset(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    bundle["coverage"].append(
        {
            "scenario_id": bundle["coverage"][0]["scenario_id"],
            "target": "10.0.0.6",
            "mode": "planning",
            "access": "unavailable",
            "result_id": None,
        }
    )


@given("its finding also affects a second asset without evidence")
def second_asset_without_evidence(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    plan = bundle["action_plans"][0]
    plan["target"] = "10.0.0.0/24"
    plan["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in plan.items() if key not in {"status", "plan_digest"}}
    )
    bundle["finding_contexts"][0]["affected_assets"].append("10.0.0.6")
    bundle["coverage"].append({**bundle["coverage"][0], "target": "10.0.0.6"})


@given("it contains an orphan action plan")
def orphan_action_plan(report_ctx):
    extra = deepcopy(report_ctx["bundle"]["action_plans"][0])
    extra["plan_id"] = "plan-orphan-001"
    extra["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in extra.items() if key not in {"status", "plan_digest"}}
    )
    report_ctx["bundle"]["action_plans"].append(extra)


@given("it contains a broad action plan with only narrow planning coverage")
def broad_plan_with_narrow_coverage(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    extra = deepcopy(bundle["action_plans"][0])
    extra["plan_id"] = "plan-broad-bdd-001"
    extra["target"] = "10.0.0.0/24"
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


@given("its scanner assertion has an observation on another asset")
def scanner_observation_on_other_asset(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    plan = bundle["action_plans"][0]
    plan["target"] = "10.0.0.0/24"
    plan["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in plan.items() if key not in {"status", "plan_digest"}}
    )
    evidence = build_envelope(
        acquisition_id="collection-1",
        product="offline-import",
        api="records/v1",
        tenant="tenant-1",
        scope=["10.0.0.0/24"],
        identity="network-10",
        locator="private-locator",
        payload={"observation": "HTTP service"},
        acquired_at="2026-10-02T10:05:00Z",
        transformed_at="2026-10-02T10:05:00Z",
        observed_at="2026-10-02T10:05:00Z",
        request_fingerprint="a" * 64,
        page=1,
        raw_reference={"store_id": "PRIVATE_STORE_ID", "sha256": "b" * 64},
    )
    bundle["evidence_envelopes"] = [evidence]
    bundle["run_results"][0]["evidence_records"] = [evidence["record_id"]]
    bundle["findings"][0]["evidence_references"] = [evidence["record_id"]]
    bundle["coverage"][0]["target"] = "10.0.0.0/24"
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    observation = deepcopy(bundle["findings"][0])
    observation["finding_id"] = "find-observed-bdd-001"
    bundle["findings"].append(observation)
    context = deepcopy(bundle["finding_contexts"][0])
    context.update(
        finding_id=observation["finding_id"],
        kind="observed_behavior",
        affected_assets=["10.0.0.6"],
    )
    bundle["finding_contexts"].append(context)


@given("it repeats host coverage as a singleton CIDR")
def duplicate_singleton_coverage(report_ctx):
    row = deepcopy(report_ctx["bundle"]["coverage"][0])
    row["target"] = "10.0.0.5/32"
    report_ctx["bundle"]["coverage"].append(row)


@given("its attack path has a supported prerequisite")
@given("its attack path has an assessed prerequisite")
def assessed_prerequisite(report_ctx):
    bundle = report_ctx["bundle"]
    context = bundle["finding_contexts"][0]
    context["kind"] = "reproduced_attack_path"
    context["attack_path_dependencies"] = ["find-prerequisite-001"]
    prerequisite = deepcopy(bundle["findings"][0])
    prerequisite["finding_id"] = "find-prerequisite-001"
    bundle["findings"].append(prerequisite)
    prerequisite_context = deepcopy(context)
    prerequisite_context.update(
        finding_id="find-prerequisite-001", kind="observed_behavior", attack_path_dependencies=[]
    )
    bundle["finding_contexts"].append(prerequisite_context)


@given("its finding title contains a Unicode direction control")
def unicode_direction_control(report_ctx):
    report_ctx["bundle"]["findings"][0]["title"] = "Expected \u202e reversed"


@given("it contains a broad action plan with only narrow planning coverage")
def broad_plan_narrow_coverage(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    extra = deepcopy(bundle["action_plans"][0])
    extra["plan_id"] = "plan-broad-bdd-001"
    extra["target"] = "10.0.0.0/24"
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


@given("a broad scanner row has a separate observation for another asset")
def broad_scanner_with_other_observation(report_ctx):
    bundle = report_ctx["bundle"]
    bundle["engagement"]["scope"]["excluded_targets"] = []
    plan = bundle["action_plans"][0]
    plan["target"] = "10.0.0.0/24"
    plan["plan_digest"] = build_action_plan_digest(
        snapshot={key: value for key, value in plan.items() if key not in {"status", "plan_digest"}}
    )
    source = bundle["evidence_envelopes"][0]
    scanner_evidence = build_envelope(
        acquisition_id="collection-scanner-bdd",
        product="offline-import",
        api="records/v1",
        tenant="tenant-1",
        scope=["10.0.0.0/24"],
        identity="scanner-row",
        locator="private-locator",
        payload={"observation": "scanner assertion"},
        acquired_at=source["acquired_at"],
        transformed_at=source["transformed_at"],
        observed_at=source["observed"]["at"],
        request_fingerprint="a" * 64,
        page=1,
        raw_reference={"store_id": "PRIVATE_STORE_ID", "sha256": "b" * 64},
    )
    other_evidence = build_envelope(
        acquisition_id="collection-other-bdd",
        product="offline-import",
        api="records/v1",
        tenant="tenant-1",
        scope=["10.0.0.0/24"],
        identity="other-asset",
        locator="private-locator",
        payload={"observation": "HTTP service on 10.0.0.6"},
        acquired_at=source["acquired_at"],
        transformed_at=source["transformed_at"],
        observed_at=source["observed"]["at"],
        request_fingerprint="c" * 64,
        page=2,
        raw_reference={"store_id": "PRIVATE_STORE_ID", "sha256": "d" * 64},
    )
    bundle["evidence_envelopes"] = [scanner_evidence, other_evidence]
    bundle["run_results"][0]["evidence_records"] = [scanner_evidence["record_id"], other_evidence["record_id"]]
    bundle["coverage"][0]["target"] = "10.0.0.0/24"
    bundle["finding_contexts"][0]["kind"] = "scanner_assertion"
    bundle["findings"][0]["evidence_references"] = [scanner_evidence["record_id"]]
    observation = deepcopy(bundle["findings"][0])
    observation["finding_id"] = "find-other-asset-bdd-001"
    observation["evidence_references"] = [other_evidence["record_id"]]
    bundle["findings"].append(observation)
    context = deepcopy(bundle["finding_contexts"][0])
    context.update(finding_id=observation["finding_id"], kind="observed_behavior", affected_assets=["10.0.0.6"])
    bundle["finding_contexts"].append(context)


@when("the assessment report is built")
def build_report(report_ctx):
    try:
        report_ctx["report"] = build_assessment_report(report_ctx["bundle"])
    except ReportError as error:
        report_ctx["error"] = error


@when("the saved finding is changed to unsupported recorded evidence")
def unsupported_recorded_evidence(report_ctx):
    finding = report_ctx["report"]["findings"][0]
    finding["assessment_status"] = "partial"
    finding["evidence_references"] = []


@when("the saved scanner coverage is changed to assessed")
def unsupported_scanner_coverage(report_ctx):
    report_ctx["report"]["coverage"][0]["status"] = "assessed"


@when("the saved result is reused in another scenario")
def reused_result(report_ctx):
    row = deepcopy(report_ctx["report"]["coverage"][0])
    row["scenario_id"] = "COPS-E17.01-S02"
    report_ctx["report"]["coverage"].append(row)


@when("the saved attack path repeats its prerequisite")
def duplicate_dependency(report_ctx):
    report_ctx["report"]["findings"][0]["attack_path_dependencies"].append("find-prerequisite-001")


@when("the saved prerequisite points back to the attack path")
@when("the saved prerequisite depends on the attack path")
def dependency_cycle(report_ctx):
    report_ctx["report"]["findings"][1]["attack_path_dependencies"] = ["find-open-port-http-80"]


@when("the saved verified finding claims partial status and contradicted strength")
def verified_partial_contradicted_strength(report_ctx):
    finding = report_ctx["report"]["findings"][0]
    finding["assessment_status"] = "partial"
    finding["evidence_strength"] = "contradicted"


@when("the saved verified finding claims unresolved status and limited strength")
def verified_unresolved_limited_strength(report_ctx):
    finding = report_ctx["report"]["findings"][0]
    finding["assessment_status"] = "unresolved"
    finding["evidence_strength"] = "limited"


@when("the saved contradicted finding claims limited strength")
def contradicted_limited_strength(report_ctx):
    finding = report_ctx["report"]["findings"][0]
    finding.update(verification="contradicted", classification="unresolved", assessment_status="unresolved")
    finding["evidence_strength"] = "limited"


@when("the saved resultless coverage retains evidence")
def resultless_coverage_retains_evidence(report_ctx):
    row = report_ctx["report"]["coverage"][0]
    row.update(
        result_id=None,
        status="not_assessed",
        mode="planning",
        provenance="planned",
        access="unavailable",
    )


@when("the saved evidence notice is replaced")
def replace_evidence_notice(report_ctx):
    report_ctx["report"]["evidence_notice"] = "Evidence was validated."


@when("the saved asset limitation is replaced")
def replace_asset_limitation(report_ctx):
    report_ctx["report"]["findings"][0]["limitations"] = ["Some coverage was incomplete."]


@when("the saved finding claims partial status over only unassessed coverage")
def partial_finding_over_unassessed_coverage(report_ctx):
    row = report_ctx["report"]["coverage"][0]
    row.update(status="not_assessed", provenance="laboratory")
    finding = report_ctx["report"]["findings"][0]
    finding.update(
        assessment_status="partial",
        evidence_strength="limited",
        limitations=["Not assessed for assets: 10.0.0.5"],
    )


@when("saved coverage repeats an IPv6 host as a single-address network")
def repeated_ipv6_saved_coverage(report_ctx):
    report = report_ctx["report"]
    report["scope"]["included_targets"] = ["2001:db8::/64"]
    report["coverage"][0]["target"] = "2001:db8::5"
    report["coverage"].append({**report["coverage"][0], "target": "2001:db8::5/128"})


@when("the saved assessed finding claims missing evidence strength")
def assessed_with_missing_strength(report_ctx):
    report_ctx["report"]["findings"][0]["evidence_strength"] = "missing"


@when("saved resultless coverage borrows execution evidence")
def resultless_coverage_with_evidence(report_ctx):
    row = deepcopy(report_ctx["report"]["coverage"][0])
    row.update(
        scenario_id="COPS-E17.01-S02", mode="planning", provenance="planned", status="not_assessed", result_id=None
    )
    report_ctx["report"]["coverage"].append(row)


@when("the saved evidence notice claims source authenticity")
def false_evidence_notice(report_ctx):
    report_ctx["report"]["evidence_notice"] = "Record hashes prove source authenticity and authorization."


@when("the saved finding removes its asset gap")
def removed_asset_gap(report_ctx):
    report_ctx["report"]["findings"][0]["limitations"] = []


@then("its coverage and finding are assessed")
def assessed_claims(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["status"] == "assessed"
    assert report_ctx["report"]["findings"][0]["assessment_status"] == "assessed"


@then("its coverage is partial")
def partial_coverage(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["status"] == "partial"


@then("its live coverage and finding are not assessed")
def unassessed_live_claims(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["coverage"][0]["provenance"] == "live_unvalidated"
    assert report_ctx["report"]["coverage"][0]["status"] == "not_assessed"
    assert report_ctx["report"]["findings"][0]["assessment_status"] == "not_assessed"


@then("its finding is partial with an asset limitation")
def partial_asset_claim(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["findings"][0]["assessment_status"] == "partial"
    assert report_ctx["report"]["findings"][0]["limitations"] == ["Not assessed for assets: 10.0.0.6"]


@then("the second asset is not assessed and the finding is partial")
def second_asset_not_assessed(report_ctx):
    assert report_ctx["error"] is None
    assert [row["status"] for row in report_ctx["report"]["coverage"]] == ["assessed", "not_assessed"]
    finding = report_ctx["report"]["findings"][0]
    assert finding["assessment_status"] == "partial"
    assert finding["limitations"] == ["Not assessed for assets: 10.0.0.6"]


@then("both findings are partial and the second asset gap is disclosed")
def broad_row_limits_both_findings(report_ctx):
    assert report_ctx["error"] is None
    report = report_ctx["report"]
    assert report["coverage"][0]["status"] == "partial"
    assert [finding["assessment_status"] for finding in report["findings"]] == ["partial", "partial"]
    assert report["findings"][1]["limitations"] == ["Not assessed for assets: 10.0.0.6"]


@then("its attack path and prerequisite validate")
def supported_attack_path(report_ctx):
    assert report_ctx["error"] is None
    assert report_ctx["report"]["findings"][0]["attack_path_dependencies"] == ["find-prerequisite-001"]
    validate_contract(report_ctx["report"], "assessment_report")


@then("report building fails with an orphan action plan")
def orphan_plan_rejected(report_ctx):
    assert isinstance(report_ctx["error"], ReportError)
    assert "every action plan requires" in str(report_ctx["error"])


@then("report building fails with duplicate coverage")
def duplicate_coverage_rejected(report_ctx):
    assert isinstance(report_ctx["error"], ReportError)
    assert "duplicate coverage entry" in str(report_ctx["error"])


@then("the rendered report omits the direction control")
def render_without_direction_control(report_ctx):
    assert report_ctx["error"] is None
    markdown = render_markdown(report_ctx["report"])
    assert "\u202e" not in markdown
    assert "Expected   reversed" in markdown


@then("the saved assessment report validates")
def valid_saved_report(report_ctx):
    validate_contract(report_ctx["report"], "assessment_report")


@then("report building fails with an invalid finding contract")
def invalid_finding(report_ctx):
    assert isinstance(report_ctx["error"], ReportError)
    assert "invalid finding contract" in str(report_ctx["error"])


@then("the saved assessment report is rejected")
def invalid_saved_report(report_ctx):
    with pytest.raises(ContractError):
        validate_contract(report_ctx["report"], "assessment_report")
