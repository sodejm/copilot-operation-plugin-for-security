"""Executable acceptance scenarios for engagement, action, result, and finding contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.contracts import (
    ContractError,
    evaluate_run_result,
    validate_contract,
    validate_transition,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"

scenarios("../../specs/features/engagement_contracts.feature")


@pytest.fixture
def contract_context():
    return {}


@given(parsers.parse('a valid engagement document from "{filename}"'))
def load_valid_engagement(contract_context, filename):
    path = FIXTURES / filename
    contract_context["document"] = json.loads(path.read_text(encoding="utf-8"))


@when("the engagement is validated against the contract schema")
def validate_engagement_doc(contract_context):
    contract_context["validated"] = validate_contract(contract_context["document"])


@then(parsers.parse('validation succeeds with schema version "{expected_version}"'))
def verify_schema_version(contract_context, expected_version):
    assert contract_context["validated"]["schema_version"] == expected_version


@then(parsers.parse('transitioning the engagement from "{current}" to "{target}" succeeds'))
def transition_succeeds(contract_context, current, target):
    validate_transition(current, target, "engagement")


@given(parsers.parse('an engagement in state "{state}"'))
def engagement_in_state(contract_context, state):
    contract_context["current_state"] = state
    contract_context["contract_type"] = "engagement"


@when(parsers.parse('attempting to transition the engagement to "{target}"'))
def transition_engagement(contract_context, target):
    contract_context["target_state"] = target
    try:
        validate_transition(contract_context["current_state"], target, "engagement")
        contract_context["error"] = None
    except ContractError as err:
        contract_context["error"] = err


@then(parsers.parse('the transition is rejected with error code "{code}"'))
def transition_rejected(contract_context, code):
    assert contract_context["error"] is not None
    assert contract_context["error"].code == code


@given(parsers.parse('an action plan in state "{state}"'))
def action_plan_in_state(contract_context, state):
    contract_context["current_state"] = state
    contract_context["contract_type"] = "action_plan"


@when(parsers.parse('attempting to transition the action plan to "{target}"'))
def transition_action_plan(contract_context, target):
    contract_context["target_state"] = target
    try:
        validate_transition(contract_context["current_state"], target, "action_plan")
        contract_context["error"] = None
    except ContractError as err:
        contract_context["error"] = err


@given(parsers.parse('a run result with status "{status}" and reason "{reason}"'))
def run_result_with_status(contract_context, status, reason):
    path = FIXTURES / "valid_run_result_partial.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["status"] = status
    doc["status_details"]["reason"] = reason
    contract_context["run_result"] = doc


@when("evaluating whether the run result was successful")
def eval_run_result(contract_context):
    contract_context["is_success"] = evaluate_run_result(contract_context["run_result"])


@then("the result evaluates to unsuccessful")
def verify_unsuccessful(contract_context):
    assert contract_context["is_success"] is False


@then("validation confirms the non-empty reason is present")
def verify_reason_present(contract_context):
    validated = validate_contract(contract_context["run_result"])
    assert validated["status_details"]["reason"]


@given(parsers.parse('a finding claiming verification "{verification}" with no evidence references'))
def finding_without_evidence(contract_context, verification):
    path = FIXTURES / "invalid_finding_verified_missing_evidence.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["verification"] = verification
    doc["evidence_references"] = []
    contract_context["finding"] = doc


@when("the finding is validated against the contract schema")
def validate_finding(contract_context):
    try:
        validate_contract(contract_context["finding"])
        contract_context["error"] = None
    except ContractError as err:
        contract_context["error"] = err


@then(parsers.parse('validation is rejected with error code "{code}"'))
def validation_rejected(contract_context, code):
    assert contract_context["error"] is not None
    assert contract_context["error"].code == code


@given("a contract document with a malformed identifier")
def malformed_id_doc(contract_context):
    path = FIXTURES / "malformed_identifier.json"
    contract_context["doc_malformed"] = json.loads(path.read_text(encoding="utf-8"))


@when("the contract is validated")
def validate_malformed(contract_context):
    try:
        validate_contract(contract_context["doc_malformed"])
        contract_context["error"] = None
    except ContractError as err:
        contract_context["error"] = err


@given("an action plan document with a tampered plan digest")
def tampered_plan_doc(contract_context):
    path = FIXTURES / "invalid_action_plan_tampered_digest.json"
    contract_context["doc_tampered"] = json.loads(path.read_text(encoding="utf-8"))


@when("the action plan is validated")
def validate_tampered(contract_context):
    try:
        validate_contract(contract_context["doc_tampered"])
        contract_context["error"] = None
    except ContractError as err:
        contract_context["error"] = err
