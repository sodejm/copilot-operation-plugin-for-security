"""Acceptance steps for evidence-bounded engagement retest review."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.contracts.models import CleanupReceipt
from cops.evidence.canonical import digest
from cops.reporting.assessment import build_assessment_report
from cops.reporting.retest import build_retest_report
from cops.reporting.retest_execution import (
    RetestExecutionEvidenceError,
    TrustedLaboratoryContext,
    verify_retest_execution_evidence,
    verify_retest_execution_evidence_reference,
)
from tests.laboratory_testkit import case_observation, remote_run, supervisor_exchange
from tests.test_laboratory_harness import _ready_case

scenarios("../../specs/features/engagement-retest-and-closure.feature")

FIXTURE = Path(__file__).resolve().parents[2] / "cops/contracts/fixtures/valid_assessment_input.json"


def _receipt(plan_id: str, suffix: str, *, status: str = "not_required") -> dict:
    receipt = {
        "schema_version": "cops.cleanup-receipt/v1",
        "receipt_id": f"cln-retest-{suffix}",
        "plan_id": plan_id,
        "engagement_id": "eng-secops-20261002",
        "worker_identity": "worker-1",
        "status": status,
        "created_at": "2026-10-03T12:00:00Z",
        "completed_at": "2026-10-03T12:01:00Z",
        "cleaned_effects": [],
        "unresolved_effects": [
            {"effect_id": "artifact-1", "resource_type": "file", "target": "lab-host", "reason": "pending"}
        ]
        if status == "failed"
        else [],
    }
    receipt["evidence_hash"] = digest(
        {
            key: receipt[key]
            for key in (
                "receipt_id",
                "plan_id",
                "engagement_id",
                "worker_identity",
                "cleaned_effects",
                "unresolved_effects",
            )
        }
    )
    return receipt


def _input() -> dict:
    source = json.loads(FIXTURE.read_text(encoding="utf-8"))
    baseline = build_assessment_report(source)
    retest = deepcopy(baseline)
    retest["report_id"] = "report-retest-001"
    retest["generated_at"] = "2026-10-03T12:00:00Z"
    retest_record = "e" * 64
    retest["coverage"][0]["evidence_records"] = [retest_record]
    retest["findings"] = []
    return {
        "schema_version": "cops.retest-input/v1",
        "retest_id": "retest-service-001",
        "generated_at": "2026-10-03T13:00:00Z",
        "baseline_report": baseline,
        "retest_report": retest,
        "baseline_plan_id": "plan-scan-10-0-0-5",
        "retest_plan_id": "plan-scan-10-0-0-5",
        "owner_reference": "owner-ticket-123",
        "owner_acknowledged": True,
        "residual_risks": [],
        "cleanup_receipts": [_receipt("plan-scan-10-0-0-5", "same")],
        "checks": [
            {
                "finding_id": "find-open-port-http-80",
                "asset": "10.0.0.5",
                "retest_asset": "10.0.0.5",
                "outcome": "absent",
                "evidence_records": [retest_record],
            }
        ],
    }


@pytest.fixture
def retest_ctx():
    return {"bundle": None, "reports": [], "execution": None}


def _create_laboratory_bundle(retest_ctx, tmp_path):
    harness, inventory, environment, plan, auth, trust, engagement, worker_inventory, guard = _ready_case(tmp_path)
    run = remote_run(plan, auth.authorization_id, environment.owner)
    started = datetime.fromisoformat(auth.issued_at.replace("Z", "+00:00")) + timedelta(seconds=2)
    cleaned = started + timedelta(seconds=1)
    run = replace(
        run,
        result=replace(
            run.result,
            started_at=started.isoformat().replace("+00:00", "Z"),
            finished_at=started.isoformat().replace("+00:00", "Z"),
        ),
        cleanup_receipt=CleanupReceipt(
            schema_version="cops.cleanup-receipt/v1",
            receipt_id="cln-bdd-test-01",
            plan_id=plan.plan_id,
            engagement_id=plan.engagement_id,
            worker_identity=environment.owner,
            status="completed",
            created_at=started.isoformat().replace("+00:00", "Z"),
            completed_at=cleaned.isoformat().replace("+00:00", "Z"),
            cleaned_effects=[],
            unresolved_effects=[],
            evidence_hash="0" * 64,
        ),
    )
    with patch(
        "cops.laboratory.harness.SSHExecutionDispatcher.execute_with_evidence",
        side_effect=lambda **kwargs: supervisor_exchange(
            run,
            plan,
            auth.authorization_id,
            environment.owner,
            inventory,
            request_id=kwargs["request_id"],
        ),
    ):
        dispatched = harness.execute_case(
            environment,
            plan,
            auth,
            "positive",
            trust_store=trust,
            engagement=engagement,
            worker_inventory=worker_inventory,
            endpoint_inventory=inventory,
            scope_guard=guard,
        )
    observation = case_observation(
        environment,
        plan,
        auth.authorization_id,
        dispatched,
        inventory,
        request_nonce=harness.case_observation_challenge(dispatched),
        canary_token_detected=True,
        control_blocked=False,
        observed_at=(cleaned + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
    )
    harness.classify_case(
        environment,
        plan,
        dispatched,
        auth.authorization_id,
        "positive",
        case_observation=observation,
        endpoint_inventory=inventory,
        baseline_finding_id="find-bdd-lab",
        asset_id="asset-bdd-lab",
    )
    reference = harness.retest_evidence_reference(dispatched.result.result_id)
    journal_record = next(
        record for record in harness.recorded_cases() if record.get("result_id") == dispatched.result.result_id
    )
    retest_ctx["execution"] = {
        "harness": harness,
        "inventory": inventory,
        "environment": environment,
        "plan": plan,
        "auth": auth,
        "trust": trust,
        "engagement": engagement,
        "reference": reference,
        "terminal_journal_digest": digest(journal_record),
    }


@given(
    "a disposable laboratory case with a signed authorization, attested worker result, observation, cleanup receipt, and exact journal record"
)
def verified_laboratory_bundle(retest_ctx, tmp_path):
    _create_laboratory_bundle(retest_ctx, tmp_path)


@given("a persisted laboratory retest evidence bundle")
def persisted_laboratory_bundle(retest_ctx, tmp_path):
    _create_laboratory_bundle(retest_ctx, tmp_path)


@when("the content-addressed bundle is verified against the exact baseline finding and asset")
def verify_laboratory_bundle(retest_ctx):
    ctx = retest_ctx["execution"]
    retest_ctx["review"] = verify_retest_execution_evidence_reference(
        ctx["reference"],
        evidence_store=ctx["harness"].evidence_store,
        trust_store=ctx["trust"],
        endpoint_inventory=ctx["inventory"],
        observation_trust_store=ctx["harness"].observation_trust_store,
        engagement=ctx["engagement"],
        finding_id="find-bdd-lab",
        asset_id="asset-bdd-lab",
        trusted_context=TrustedLaboratoryContext(
            environment=ctx["environment"],
            plan=ctx["plan"],
            target=ctx["plan"].target,
            provenance="verified fixture registration and expected baseline plan",
        ),
        trusted_terminal_journal_record_digest=ctx["terminal_journal_digest"],
        previously_consumed_authorization_ids=[],
    )


@when(
    "its plan, identity, authorization consumption, supervisor attestation, observation, cleanup, or journal binding differs"
)
def reject_changed_laboratory_bundle(retest_ctx):
    ctx = retest_ctx["execution"]
    bundle = ctx["harness"].evidence_store.read_json(ctx["reference"])
    bundle["action_plan_sha256"] = "0" * 64
    with pytest.raises(RetestExecutionEvidenceError):
        verify_retest_execution_evidence(
            bundle,
            trust_store=ctx["trust"],
            endpoint_inventory=ctx["inventory"],
            observation_trust_store=ctx["harness"].observation_trust_store,
            engagement=ctx["engagement"],
            finding_id="find-bdd-lab",
            asset_id="asset-bdd-lab",
            trusted_context=TrustedLaboratoryContext(
                environment=ctx["environment"],
                plan=ctx["plan"],
                target=ctx["plan"].target,
                provenance="verified fixture registration and expected baseline plan",
            ),
            trusted_terminal_journal_record_digest=ctx["terminal_journal_digest"],
            previously_consumed_authorization_ids=[],
            evidence_store=ctx["harness"].evidence_store,
        )


@given("a baseline finding and a later assessed retest of the same engagement and exact asset")
@given("a baseline finding")
@given("an otherwise supported candidate_fixed finding")
@given("an assessed live retest using the baseline plan ID")
def baseline_retest(retest_ctx):
    retest_ctx["bundle"] = _input()


@when("an absent observation references retest evidence for that scenario and asset")
def compare_supported_absence(retest_ctx):
    retest_ctx["reports"] = [build_retest_report(retest_ctx["bundle"])]


@when("the retest target is inaccessible or has a different identity")
def compare_inaccessible_and_changed(retest_ctx):
    inaccessible = deepcopy(retest_ctx["bundle"])
    inaccessible["checks"][0]["outcome"] = "inaccessible"
    changed = deepcopy(retest_ctx["bundle"])
    changed["checks"][0]["retest_asset"] = "10.0.0.6"
    retest_ctx["reports"] = [build_retest_report(inaccessible), build_retest_report(changed)]


@when("cleanup remains unresolved or the live retest plan differs from the baseline plan")
def compare_cleanup_and_changed_plan(retest_ctx):
    unresolved = deepcopy(retest_ctx["bundle"])
    unresolved["cleanup_receipts"] = [_receipt("plan-scan-10-0-0-5", "failed", status="failed")]
    changed = deepcopy(retest_ctx["bundle"])
    changed["retest_report"]["coverage"][0]["mode"] = "live"
    changed["retest_report"]["coverage"][0]["provenance"] = "live_validated"
    changed["retest_plan_id"] = "plan-retest-new-001"
    changed["cleanup_receipts"].append(_receipt("plan-retest-new-001", "new"))
    retest_ctx["reports"] = [build_retest_report(unresolved), build_retest_report(changed)]


@when("the comparison finds an absent observation")
def compare_live_absence(retest_ctx):
    bundle = retest_ctx["bundle"]
    bundle["retest_report"]["coverage"][0]["mode"] = "live"
    bundle["retest_report"]["coverage"][0]["provenance"] = "live_validated"
    retest_ctx["reports"] = [build_retest_report(bundle)]


@then("the comparison labels the finding candidate_fixed and blocks closure pending independent verification")
def supported_absence_is_review_only(retest_ctx):
    report = retest_ctx["reports"][0]
    assert report["results"][0]["status"] == "candidate_fixed"
    assert report["closure_status"] == "blocked"
    assert {"source_verification_required", "owner_verification_required", "cleanup_verification_required"} <= set(
        report["closure_gates"]
    )


@then("the comparison does not label the finding candidate_fixed")
def no_fixed_label(retest_ctx):
    assert all(report["results"][0]["status"] != "candidate_fixed" for report in retest_ctx["reports"])


@then("the comparison requires further review and never closes the engagement")
def cleanup_and_plan_require_review(retest_ctx):
    unresolved, changed = retest_ctx["reports"]
    assert unresolved["closure_status"] == changed["closure_status"] == "blocked"
    assert "cleanup_incomplete" in unresolved["closure_gates"]
    assert "fresh_authorization_required" in changed["closure_gates"]


@then("it still requires verification of the run authority and cleanup binding")
def live_retest_requires_bindings(retest_ctx):
    gates = retest_ctx["reports"][0]["closure_gates"]
    assert "live_authority_binding_required" in gates
    assert "cleanup_run_binding_required" in gates


@then("it yields a candidate retest input and closure remains blocked pending independent review")
def laboratory_evidence_is_review_only(retest_ctx):
    review = retest_ctx["review"]
    assert review.outcome == "candidate_still_vulnerable"
    assert review.closure_status == "blocked"
    assert review.independent_review_required is True


@then("verification fails closed and no retest review input is produced")
def changed_laboratory_evidence_is_rejected(retest_ctx):
    assert "review" not in retest_ctx
