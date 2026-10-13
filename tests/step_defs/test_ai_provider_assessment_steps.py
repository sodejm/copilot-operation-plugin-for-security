"""Executable acceptance scenarios for synthetic AI provider assessments."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops import provider_assessment
from cops.provider_assessment import ProviderAssessmentError, assess, main, read_json, report_case_id

FIXTURES = Path(__file__).resolve().parents[2] / "plugins/offensive-security/foundry-agent-harness/provider_fixtures"

scenarios("../../specs/features/ai_provider_assessment.feature")


@pytest.fixture
def context():
    return {}


def _inputs():
    return (
        read_json(FIXTURES / "plan.json", "provider-plan.schema.json"),
        read_json(FIXTURES / "cases.json", "provider-cases.schema.json"),
    )


@given("an offline synthetic provider plan for OpenAI, Azure, AWS, and GCP")
def all_providers(context):
    context["plan"], context["cases"] = _inputs()
    assert {item["provider"] for item in context["plan"]["environments"]} == {"openai", "azure", "aws", "gcp"}


@when("the approved response fixtures are assessed")
def run_approved(context):
    context["report"] = assess(context["plan"], context["cases"])


@then("every family has a completed result with known synthetic usage")
def four_completions(context):
    results = {item["case_id"]: item for item in context["report"]["results"]}
    assert context["report"]["all_expectations_met"]
    for provider in ("openai", "azure", "aws", "gcp"):
        result = results[report_case_id(f"{provider}-completed")]
        assert result["outcome"] == "completed"
        assert result["usage_state"] == "known_synthetic"


@then("no provider content or endpoint appears in the report")
def no_content(context):
    report = json.dumps(context["report"])
    assert "SYNTHETIC_SECRET_DO_NOT_REPORT" not in report
    assert ".invalid" not in report


@given("a case with a changed tenant, endpoint, model, request, or tool")
def changed_boundaries(context):
    context["plan"], cases = _inputs()
    names = {"tenant-denied", "endpoint-denied", "model-denied", "request-denied", "tool-denied"}
    context["cases"] = {**cases, "cases": [item for item in cases["cases"] if item["case_id"] in names]}
    assert len(context["cases"]["cases"]) == len(names)


@when("the case is assessed against the plan")
def run_boundaries(context):
    context["report"] = assess(context["plan"], context["cases"])


@then("the gate denies it without a budget attempt or provider effect")
def denied_without_effect(context):
    assert context["report"]["budget"]["charged_attempts"] == 0
    assert all(
        item["decision"] == "denied" and item["response_state"] == "not_processed" and item["outcome"] == "no_effect"
        for item in context["report"]["results"]
    )


@given("an approved partial response with no usage")
def partial_response(context):
    context["plan"], context["cases"] = _inputs()
    partial = next(item for item in context["cases"]["cases"] if item["case_id"] == "openai-partial")
    assert "usage" not in partial["response"]


@when("the case is assessed")
def run_partial(context):
    context["report"] = assess(context["plan"], context["cases"])


@then("its budget attempt remains usage unknown")
def unknown_usage(context):
    results = {item["case_id"]: item for item in context["report"]["results"]}
    assert results[report_case_id("openai-partial")]["ledger_state"] == "usage_unknown"
    assert results[report_case_id("openai-partial")]["usage_state"] == "unknown"


@then("a later attempt beyond the budget is denied")
def exhausted_budget(context):
    results = {item["case_id"]: item for item in context["report"]["results"]}
    assert results[report_case_id("budget-denied")]["decision"] == "budget_denied"
    assert results[report_case_id("budget-denied")]["response_state"] == "not_processed"


@given("a provider assessment plan requesting live or paid execution")
def unsupported_modes(context):
    context["plan"], context["cases"] = _inputs()


@when("the plan is loaded")
def load_unsupported(context):
    plans = [{**context["plan"], "mode": "live"}, {**context["plan"], "paid_execution_opt_in": True}]
    context["rejected"] = []
    for plan in plans:
        with pytest.raises(ProviderAssessmentError):
            assess(plan, context["cases"])
        context["rejected"].append(True)


@then("the runner rejects it before credential or network access")
def no_live_execution(context):
    assert context["rejected"] == [True, True]


@given("a provider case file with NaN or Infinity in a denied response")
def nonfinite_denied_file(context, tmp_path):
    _, cases = _inputs()
    denied = next(item for item in cases["cases"] if item["case_id"] == "endpoint-denied")
    source = json.dumps({"schema_version": cases["schema_version"], "cases": [denied]})
    context["case_path"] = tmp_path / "cases.json"
    context["case_path"].write_text(source.replace('"response": {', '"response": {"nonfinite": NaN, ', 1), encoding="utf-8")


@when("the case file is loaded")
def load_nonfinite_denied_file(context):
    with pytest.raises(ProviderAssessmentError, match="non-finite JSON constant"):
        read_json(context["case_path"], "provider-cases.schema.json")
    context["nonfinite_rejected"] = True


@then("the runner rejects the nonstandard JSON constant")
def nonfinite_is_rejected(context):
    assert context["nonfinite_rejected"] is True


@given("an otherwise completed provider assessment whose temporary ledger cannot be deleted")
def cleanup_failure(monkeypatch):
    original = provider_assessment.tempfile.TemporaryDirectory

    class FailingCleanup:
        def __init__(self, *args, **kwargs):
            self._directory = original(*args, **kwargs)
            self.name = self._directory.name

        def cleanup(self):
            self._directory.cleanup()
            raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(provider_assessment.tempfile, "TemporaryDirectory", FailingCleanup)


@when("the assessment completes")
def run_cleanup_failure(context, capsys):
    context["exit_code"] = main([])
    context["report"] = json.loads(capsys.readouterr().out)


@then("its report marks cleanup unverified and the command exits nonzero")
def cleanup_is_unverified(context):
    assert context["exit_code"] == 1
    assert context["report"]["all_expectations_met"] is True
    assert context["report"]["cleanup_verified"] is False
