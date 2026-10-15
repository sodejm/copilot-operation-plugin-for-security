# Repository and shared acceptance fixture path setup precedes imports.
# ruff: noqa: E402
"""Executable BDD bindings for the service-validation dispatcher boundary."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenario, then, when

ROOT = Path(__file__).resolve().parents[2]
for import_path in (ROOT, ROOT / "tests"):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from test_service_validation_execution import (
    ExactApprovalGate,
    LoopbackEvidenceVerifier,
    LoopbackProvider,
    attempt,
    budget_ledger,
    loopback_service,
    plan_for,
)
from test_service_validation_lab import EXPECTED_ROUTES, assert_complete_public_journey

from cops.assessment_budget import BudgetDenied
from cops.discovery import (
    ValidationSelection,
    execute_service_validation_action,
    lab_service_provider_registry,
    run_loopback_service_validation_journey,
)

FEATURE = "../../specs/features/service_entry_validation.feature"


@scenario(FEATURE, "A low-impact specialist probe records a benign service assessment")
def test_low_impact_benign_service_assessment():
    pass


@scenario(FEATURE, "Controlled proof confirms a versioned configuration flaw and cleanup")
def test_controlled_proof_confirms_candidate_and_cleanup():
    pass


@scenario(FEATURE, "A remediated protected service remains a non-finding")
def test_protected_service_remains_non_finding():
    pass


@scenario(FEATURE, "Missing independent evidence fails closed")
def test_missing_independent_evidence_fails_closed():
    pass


@scenario(FEATURE, "Provider availability is an explicit pre-dispatch gate")
def test_provider_availability_gate():
    pass


@scenario(FEATURE, "Every retry is a new bounded and approved action")
def test_retry_requires_new_budget_and_approval():
    pass


@scenario(FEATURE, "Operator runs the public seven-family loopback service-validation journey")
def test_public_seven_family_loopback_service_validation_journey():
    pass


@pytest.fixture
def service_ctx(tmp_path):
    ctx = {
        "tmp_path": tmp_path,
        "servers": [],
        "provider": None,
        "verifier": None,
        "plan": None,
        "ledger": None,
        "gate": None,
        "result": None,
        "prior_result": None,
    }
    try:
        yield ctx
    finally:
        for manager in reversed(ctx["servers"]):
            manager.__exit__(None, None, None)


def _start_service(service_ctx, banner: bytes, proof_response: bytes = b""):
    manager = loopback_service(banner, proof_response)
    server = manager.__enter__()
    service_ctx["servers"].append(manager)
    return server


def _configure_execution(service_ctx, server, *, service="redis", skill_id="network-data-services"):
    service_ctx["server"] = server
    service_ctx["plan"] = plan_for(server.server_address[1], service=service, skill_id=skill_id)
    service_ctx["ledger"] = budget_ledger(service_ctx["tmp_path"])
    service_ctx["gate"] = ExactApprovalGate()
    service_ctx["provider"] = LoopbackProvider()
    service_ctx["verifier"] = LoopbackEvidenceVerifier(server)


def _execute(service_ctx, action, attempt_id, *, prior_result=None, provider_marker=True, verifier_marker=True):
    provider = service_ctx["provider"] if provider_marker else None
    verifier = service_ctx["verifier"] if verifier_marker else None
    service_ctx["result"] = execute_service_validation_action(
        service_ctx["plan"],
        ValidationSelection(service_ctx["plan"].plan_id, action),
        ledger=service_ctx["ledger"],
        request=attempt(attempt_id),
        authorization_gate=service_ctx["gate"],
        provider=provider,
        evidence_verifier=verifier,
        prior_result=prior_result,
    )


@given("an authorized exact plan for a disposable loopback SSH service on a nonstandard port")
def given_benign_ssh_plan(service_ctx):
    server = _start_service(service_ctx, b"SSH-2.0-OpenSSH_9.0 lab\r\n")
    _configure_execution(
        service_ctx,
        server,
        service="ssh",
        skill_id="network-remote-and-file-services",
    )


@given("a bounded specialist provider is registered")
def given_provider_registered(service_ctx):
    assert service_ctx["provider"] is not None
    assert service_ctx["verifier"] is not None


@when("the operator selects low-impact validation with a fresh attempt budget and approval receipt")
def when_low_impact_selected(service_ctx):
    _execute(service_ctx, "low_impact_validation", "bdd-benign")


@then("the provider connects only to that exact endpoint")
def then_provider_uses_exact_endpoint(service_ctx):
    assert service_ctx["provider"].calls == [(service_ctx["plan"].endpoint, "low_impact_validation")]


@then("independent protocol evidence records exposure, authentication, configuration, version, and trust")
def then_independent_dimensions_are_recorded(service_ctx):
    result = service_ctx["result"]
    assert result.protocol_evidence
    assert set(result.dimensions) == {"exposure", "authentication", "configuration", "version", "trust"}
    assert all(result.dimensions.values())


@then("the result is benign without a verified finding or successful authorized use")
def then_result_is_benign(service_ctx):
    result = service_ctx["result"]
    assert result.status == "completed"
    assert not result.candidate
    assert not result.verified_finding
    assert not result.successful_authorized_use


@given("low-impact validation found a Redis candidate with a versioned issue 143 reproduction")
def given_versioned_redis_candidate(service_ctx):
    server = _start_service(
        service_ctx,
        b"-ERR Redis 5.0 no password configured\r\n",
        b"+PONG\r\n",
    )
    _configure_execution(service_ctx, server)
    _execute(service_ctx, "low_impact_validation", "bdd-candidate")
    service_ctx["prior_result"] = service_ctx["result"]
    assert service_ctx["prior_result"].candidate
    assert service_ctx["prior_result"].reproduction_reference == "#143"


@when("the operator separately selects controlled proof with a fresh attempt budget and approval receipt")
def when_controlled_proof_selected(service_ctx):
    _execute(
        service_ctx,
        "controlled_proof",
        "bdd-proof",
        prior_result=service_ctx["prior_result"],
    )


@then("protocol evidence and independent effect evidence are both retained")
def then_protocol_and_effect_evidence_retained(service_ctx):
    result = service_ctx["result"]
    assert result.protocol_evidence
    assert result.effect_evidence == ("fixture audit recorded PING and returned +PONG",)


@then("cleanup evidence is retained before the finding becomes verified")
def then_cleanup_precedes_verification(service_ctx):
    result = service_ctx["result"]
    assert result.cleanup_evidence
    assert result.verified_finding


@then("the report separates observed exposure, candidate, verified finding, and successful authorized use")
def then_report_separates_states(service_ctx):
    result = service_ctx["result"]
    assert result.observed_exposure
    assert result.candidate
    assert result.verified_finding
    assert not result.successful_authorized_use
    assert result.authorized_use_evidence == ()


@then("ATT&CK mappings state their evidence limits and finding coverage records tested and untested dimensions")
def then_attack_and_coverage_are_bounded(service_ctx):
    result = service_ctx["result"]
    assert {mapping.technique_id for mapping in result.attack_mappings} == {"T1046", "T1210"}
    assert all(mapping.evidence_limit for mapping in result.attack_mappings)
    assert result.coverage["effect"] == "tested"
    assert result.coverage["authorized_use"] == "untested"


@then("the report retains the issue 143 reproduction, version, remediation, approval receipt, and attempt provenance")
def then_reproduction_and_approval_provenance_are_retained(service_ctx):
    result = service_ctx["result"]
    assert result.reproduction_reference == "#143"
    assert result.observed_version == "redis-lab-5.0"
    assert result.remediation == "Require authentication and upgrade to the protected fixture."
    assert result.action == "controlled_proof"
    assert result.approval_receipt_id == "approval-bdd-proof"
    assert result.attempt_id == "bdd-proof"


@given("an authorized exact plan for a disposable loopback service requiring authentication")
def given_protected_service_plan(service_ctx):
    server = _start_service(service_ctx, b"-ERR Redis 7.2 authentication required; remediated\r\n")
    _configure_execution(service_ctx, server)


@when("a bounded low-impact specialist probe receives the protected response")
def when_protected_service_is_probed(service_ctx):
    _execute(service_ctx, "low_impact_validation", "bdd-protected")


@then("the result records the authentication boundary and remediation state")
def then_protected_state_is_recorded(service_ctx):
    result = service_ctx["result"]
    assert result.status == "completed"
    assert result.observed_version == "redis-lab-7.2-protected"
    assert result.dimensions["authentication"] == "required"
    assert result.dimensions["configuration"] == "protected fixture"


@then("it does not claim a finding or successful authorized use")
def then_no_finding_or_use_is_claimed(service_ctx):
    result = service_ctx["result"]
    assert not result.candidate
    assert not result.verified_finding
    assert not result.successful_authorized_use


@given("a specialist provider returns no independently collected protocol evidence")
def given_no_independent_protocol_evidence(service_ctx):
    server = _start_service(service_ctx, b"SSH-2.0-OpenSSH_9.0 lab\r\n")
    _configure_execution(
        service_ctx,
        server,
        service="ssh",
        skill_id="network-remote-and-file-services",
    )
    service_ctx["verifier"] = LoopbackEvidenceVerifier(server, incomplete=True)


@when("the operator selects low-impact validation")
def when_low_impact_selected_without_evidence(service_ctx):
    _execute(service_ctx, "low_impact_validation", "bdd-incomplete")


@then("the result is insufficient evidence")
def then_result_is_insufficient(service_ctx):
    assert service_ctx["result"].status == "insufficient_evidence"


@then("it does not claim a candidate, verified finding, or successful authorized use")
def then_no_validation_state_is_claimed(service_ctx):
    result = service_ctx["result"]
    assert not result.candidate
    assert not result.verified_finding
    assert not result.successful_authorized_use


@given("no native or approved specialist provider is registered")
def given_provider_unavailable(service_ctx):
    service_ctx["plan"] = plan_for(65530, service="ssh", skill_id="network-remote-and-file-services")
    service_ctx["ledger"] = budget_ledger(service_ctx["tmp_path"])
    service_ctx["gate"] = ExactApprovalGate()
    service_ctx["provider"] = None
    service_ctx["verifier"] = None


@when("the operator selects a validation action")
def when_action_selected_without_provider(service_ctx):
    _execute(
        service_ctx,
        "low_impact_validation",
        "bdd-no-provider",
        provider_marker=False,
        verifier_marker=False,
    )


@then("the result is provider unavailable")
def then_provider_unavailable(service_ctx):
    assert service_ctx["result"].status == "provider_unavailable"


@then("no attempt is reserved, approved, or dispatched")
def then_no_attempt_or_dispatch(service_ctx):
    with pytest.raises(BudgetDenied, match="attempt not found"):
        service_ctx["ledger"].get_attempt("bdd-no-provider")
    assert service_ctx["gate"].calls == []


@given("a validation attempt has a terminal receipt")
def given_terminal_attempt(service_ctx):
    server = _start_service(service_ctx, b"SSH-2.0-OpenSSH_9.0 lab\r\n")
    _configure_execution(
        service_ctx,
        server,
        service="ssh",
        skill_id="network-remote-and-file-services",
    )
    _execute(service_ctx, "low_impact_validation", "bdd-terminal")
    assert service_ctx["result"].status == "completed"
    service_ctx["provider"].calls.clear()
    service_ctx["gate"].calls.clear()


@when("the operator retries the validation")
def when_attempt_is_retried(service_ctx):
    _execute(service_ctx, "low_impact_validation", "bdd-retry-fresh")
    service_ctx["fresh_result"] = service_ctx["result"]
    service_ctx["fresh_provider_calls"] = tuple(service_ctx["provider"].calls)
    service_ctx["fresh_gate_calls"] = tuple(service_ctx["gate"].calls)
    service_ctx["provider"].calls.clear()
    service_ctx["gate"].calls.clear()
    _execute(service_ctx, "low_impact_validation", "bdd-terminal")
    service_ctx["reused_result"] = service_ctx["result"]


@then("the retry uses a new attempt identifier, budget reservation, and approval receipt")
def then_retry_requirements_are_stated(service_ctx):
    assert service_ctx["fresh_result"].status == "completed"
    assert service_ctx["fresh_result"].action == "low_impact_validation"
    assert service_ctx["fresh_result"].approval_receipt_id == "approval-bdd-retry-fresh"
    assert service_ctx["fresh_provider_calls"] == ((service_ctx["plan"].endpoint, "low_impact_validation"),)
    assert len(service_ctx["fresh_gate_calls"]) == 1
    assert service_ctx["fresh_gate_calls"][0][2] == "bdd-retry-fresh"


@then("a reused attempt identifier fails before provider dispatch")
def then_reused_attempt_fails_before_dispatch(service_ctx):
    assert service_ctx["reused_result"].status == "budget_denied"
    assert "fresh reservation" in service_ctx["reused_result"].reason
    assert service_ctx["provider"].calls == []
    assert service_ctx["gate"].calls == []


@given("a disposable seven-family loopback laboratory")
def given_seven_family_loopback_laboratory(service_ctx):
    adapters = lab_service_provider_registry()
    assert {adapter.service: adapter.skill_id for adapter in adapters} == EXPECTED_ROUTES
    assert all(adapter.evidence_scope == "disposable loopback fixture only" for adapter in adapters)


@when("the operator runs the public service-validation journey")
def when_public_service_validation_journey_runs(service_ctx):
    service_ctx["journey_report"] = run_loopback_service_validation_journey(service_ctx["tmp_path"] / "public-journey")


@then("the journey discovers, routes, investigates, validates, and reports every fixture")
def then_public_journey_is_complete(service_ctx):
    assert_complete_public_journey(service_ctx["journey_report"])


@then("the report retains independent evidence, authorization, budget, and cleanup provenance")
def then_public_journey_retains_provenance(service_ctx):
    report = service_ctx["journey_report"]
    assert len(report["approvals"]) == 9
    assert report["budget"] == {
        "charged_attempts": 9,
        "charged_tokens": 45,
        "charged_cost_microunits": 450,
        "charged_output_bytes": 2304,
        "active_concurrency": 0,
        "over_budget": False,
    }
    assert all(entry["all_connections_closed"] for entry in report["cleanup"])
    assert report["controlled_proof"]["effect_evidence"]
    assert report["controlled_proof"]["authorized_use_evidence"]


@then("external provider coverage remains explicitly unsupported")
def then_external_targets_remain_unsupported(service_ctx):
    report = service_ctx["journey_report"]
    assert report["external_targets_supported"] is False
    assert all(entry["evidence_scope"] == "disposable loopback fixture only" for entry in report["registry"])
