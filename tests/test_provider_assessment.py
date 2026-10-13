"""Offline AI provider assessment acceptance and boundary checks."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from cops import provider_assessment
from cops._schema_validation import SchemaValidationError, validate
from cops.provider_assessment import ProviderAssessmentError, assess, main, read_json, report_case_id

FIXTURES = Path(__file__).resolve().parents[1] / "plugins/offensive-security/foundry-agent-harness/provider_fixtures"


@pytest.mark.parametrize("number", (0, 0.0))
def test_schema_const_does_not_equate_false_with_zero(number: int | float) -> None:
    with pytest.raises(SchemaValidationError):
        validate(number, {"const": False})
    with pytest.raises(SchemaValidationError):
        validate(number, {"enum": [False]})
    validate([False, number], {"uniqueItems": True})


def test_schema_preserves_draft_integer_and_date_annotation_semantics() -> None:
    validate(1.0, {"type": "integer"})
    validate("invalid-date", {"type": "string", "format": "date"})
    with pytest.raises(SchemaValidationError):
        validate([1, 1.0], {"uniqueItems": True})


def inputs() -> tuple[dict, dict]:
    return (
        read_json(FIXTURES / "plan.json", "provider-plan.schema.json"),
        read_json(FIXTURES / "cases.json", "provider-cases.schema.json"),
    )


def test_bundled_provider_cases_preserve_budget_gate_and_redaction() -> None:
    plan, cases = inputs()
    report = assess(plan, cases)
    results = {item["case_id"]: item for item in report["results"]}

    def result(case_id: str) -> dict:
        return results[report_case_id(case_id)]

    assert len(results) == 14
    assert report["all_expectations_met"] and report["cleanup_verified"]
    assert report["budget"]["charged_attempts"] == 7
    assert report["budget"]["active_concurrency"] == 0
    for provider in ("openai", "azure", "aws", "gcp"):
        assert result(f"{provider}-completed")["outcome"] == "completed"
        assert result(f"{provider}-completed")["ledger_state"] == "settled"

    assert result("endpoint-denied")["response_state"] == "not_processed"
    assert result("endpoint-denied")["ledger_state"] == "none"
    assert result("endpoint-remediated")["outcome"] == "completed"
    assert result("aws-tool-proposal")["outcome"] == "tool_proposal"
    assert result("openai-partial")["usage_state"] == "unknown"
    assert result("openai-partial")["ledger_state"] == "usage_unknown"
    assert result("budget-denied")["response_state"] == "not_processed"
    assert result("budget-denied")["ledger_state"] == "none"

    serialized = json.dumps(report)
    for secret in (
        "SYNTHETIC_SECRET_DO_NOT_REPORT",
        "api.openai.invalid",
        "synthetic-openai-completed",
        "CANARY_SYNTHETIC",
        "openai-completed",
    ):
        assert secret not in serialized


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("account_id", "synthetic-other-account"),
        ("project_id", "synthetic-other-project"),
        ("region", "other-region"),
        ("endpoint", "https://other.openai.invalid/v1/responses"),
        ("model", "fixture-other-model"),
    ),
)
def test_scope_mismatch_denied_before_response_or_budget(field: str, value: str) -> None:
    plan, cases = inputs()
    case = copy.deepcopy(cases["cases"][0])
    case["scope"][field] = value
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})
    assert report["results"][0]["decision"] == "denied"
    assert report["results"][0]["response_state"] == "not_processed"
    assert report["budget"]["charged_attempts"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("requested_tools", ["write_fixture"]),
        ("request", {"canary_id": "CANARY_OTHER", "prompt_id": "synthetic-openai-completed", "max_output_tokens": 32}),
        ("request", {"canary_id": "CANARY_SYNTHETIC", "prompt_id": "synthetic-changed", "max_output_tokens": 32}),
        ("estimate", {"tokens": 101, "cost_microunits": 1000, "output_bytes": 1000}),
        ("estimate", {"tokens": 100, "cost_microunits": 1001, "output_bytes": 1000}),
    ),
)
def test_tool_canary_request_and_estimate_are_bound_to_plan(field: str, value: object) -> None:
    plan, cases = inputs()
    case = copy.deepcopy(cases["cases"][0])
    case[field] = value
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})
    assert report["results"][0]["decision"] == "denied"
    assert report["results"][0]["response_state"] == "not_processed"
    assert report["budget"]["charged_attempts"] == 0


def test_paid_or_live_plan_and_real_endpoint_are_rejected() -> None:
    plan, cases = inputs()
    for field, value in (("paid_execution_opt_in", True), ("mode", "live")):
        changed = copy.deepcopy(plan)
        changed[field] = value
        with pytest.raises(ProviderAssessmentError):
            assess(changed, cases)

    changed_cases = copy.deepcopy(cases)
    changed_cases["cases"][0]["scope"]["endpoint"] = "https://api.openai.com/v1/responses"
    with pytest.raises(ProviderAssessmentError):
        assess(plan, changed_cases)


def test_bounded_parser_rejects_duplicate_keys_and_excessive_nesting(tmp_path: Path) -> None:
    source = (FIXTURES / "cases.json").read_text(encoding="utf-8")
    duplicate = source.replace('"schema_version":', '"schema_version": "duplicate", "schema_version":', 1)
    path = tmp_path / "cases.json"
    path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(ProviderAssessmentError, match="duplicate JSON key"):
        read_json(path, "provider-cases.schema.json")

    cases = json.loads(source)
    nested: object = {"text": "synthetic"}
    for _ in range(20):
        nested = {"nested": nested}
    cases["cases"][0]["response"] = nested
    path.write_text(json.dumps(cases), encoding="utf-8")
    with pytest.raises(ProviderAssessmentError, match="nesting"):
        read_json(path, "provider-cases.schema.json")

    path.write_text('{"x":' * 1200 + '"value"' + "}" * 1200, encoding="utf-8")
    with pytest.raises(ProviderAssessmentError, match="nesting limit exceeded"):
        read_json(path, "provider-cases.schema.json")


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_nonfinite_constant_in_denied_response_is_rejected_before_gate(tmp_path: Path, constant: str) -> None:
    _, cases = inputs()
    denied = next(item for item in cases["cases"] if item["case_id"] == "endpoint-denied")
    source = json.dumps({"schema_version": cases["schema_version"], "cases": [denied]})
    source = source.replace('"response": {', f'"response": {{"nonfinite": {constant}, ', 1)
    path = tmp_path / "cases.json"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ProviderAssessmentError, match="non-finite JSON constant"):
        read_json(path, "provider-cases.schema.json")


def test_bounded_parser_rejects_oversized_and_nonregular_sources(tmp_path: Path) -> None:
    path = tmp_path / "cases.json"
    path.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(ProviderAssessmentError, match="input size limit exceeded"):
        read_json(path, "provider-cases.schema.json")

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "cases.fifo"
        os.mkfifo(fifo)
        with pytest.raises(ProviderAssessmentError, match="input must be a regular file"):
            read_json(fifo, "provider-cases.schema.json")


def test_partial_response_with_claimed_usage_still_stays_unknown() -> None:
    plan, cases = inputs()
    partial = copy.deepcopy(next(case for case in cases["cases"] if case["case_id"] == "openai-partial"))
    partial["response"]["usage"] = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [partial]})
    result = report["results"][0]
    assert result["decision"] == "approved"
    assert result["outcome"] == "no_effect"
    assert result["usage_state"] == "unknown"
    assert result["ledger_state"] == "usage_unknown"


def test_partial_response_rejects_output_usage_above_approved_limit() -> None:
    plan, cases = inputs()
    partial = copy.deepcopy(next(case for case in cases["cases"] if case["case_id"] == "openai-partial"))
    output_tokens = partial["request"]["max_output_tokens"] + 1
    partial["response"]["usage"] = {
        "input_tokens": 10,
        "output_tokens": output_tokens,
        "total_tokens": 10 + output_tokens,
    }
    with pytest.raises(ProviderAssessmentError, match="provider output token limit exceeded"):
        assess(plan, {"schema_version": cases["schema_version"], "cases": [partial]})


@pytest.mark.parametrize(
    ("case_id", "field", "value"),
    (
        ("openai-completed", "stopReason", "end_turn"),
        ("openai-completed", "incomplete_details", {"reason": "max_output_tokens"}),
        ("aws-completed", "status", "completed"),
        ("gcp-completed", "status", "completed"),
        ("gcp-completed", "candidates", [{"finishReason": "STOP"}, {"finishReason": "MAX_TOKENS"}]),
    ),
)
def test_approved_provider_response_rejects_mixed_or_contradictory_envelope(
    case_id: str, field: str, value: object
) -> None:
    plan, cases = inputs()
    case = copy.deepcopy(next(item for item in cases["cases"] if item["case_id"] == case_id))
    case["response"][field] = value
    with pytest.raises(ProviderAssessmentError, match="provider-response"):
        assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})


def test_actual_usage_over_global_budget_fails_report_and_blocks_later_case() -> None:
    plan, cases = inputs()
    plan["budget"]["limits"]["max_estimated_tokens"] = 100
    first = copy.deepcopy(cases["cases"][0])
    first["response"]["usage"] = {"input_tokens": 80, "output_tokens": 21, "total_tokens": 101}
    second = copy.deepcopy(next(item for item in cases["cases"] if item["case_id"] == "endpoint-remediated"))
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [first, second]})
    assert report["budget"]["charged_tokens"] == 101
    assert report["budget"]["over_budget"]
    assert not report["all_expectations_met"]
    assert report["results"][0]["ledger_state"] == "settled"
    assert report["results"][1]["decision"] == "budget_denied"
    assert report["results"][1]["response_state"] == "not_processed"


def test_cli_exits_nonzero_on_actual_budget_overrun(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plan, cases = inputs()
    plan["budget"]["limits"]["max_estimated_tokens"] = 100
    case = copy.deepcopy(cases["cases"][0])
    case["response"]["usage"] = {"input_tokens": 80, "output_tokens": 21, "total_tokens": 101}
    plan_path, cases_path = tmp_path / "plan.json", tmp_path / "cases.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    cases_path.write_text(json.dumps({"schema_version": cases["schema_version"], "cases": [case]}), encoding="utf-8")
    assert main(["--plan", str(plan_path), "--cases", str(cases_path)]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["budget"]["over_budget"]


def test_cli_reports_temporary_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    original = provider_assessment.tempfile.TemporaryDirectory

    class FailingCleanup:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._directory = original(*args, **kwargs)
            self.name = self._directory.name

        def cleanup(self) -> None:
            self._directory.cleanup()
            raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(provider_assessment.tempfile, "TemporaryDirectory", FailingCleanup)
    assert main([]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["all_expectations_met"] is True
    assert report["cleanup_verified"] is False


@pytest.mark.parametrize(
    "usage",
    (
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 14},
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "extra": 1},
        {"input_tokens": -1, "output_tokens": 5, "total_tokens": 4},
        {"input_tokens": True, "output_tokens": 5, "total_tokens": 6},
        {"input_tokens": 10.5, "output_tokens": 5, "total_tokens": 15.5},
        {"input_tokens": 9223372036854775808, "output_tokens": 5, "total_tokens": 9223372036854775813},
    ),
)
def test_malformed_approved_usage_fails_closed(usage: dict) -> None:
    plan, cases = inputs()
    case = copy.deepcopy(cases["cases"][0])
    case["response"]["usage"] = usage
    with pytest.raises(ProviderAssessmentError):
        assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})


@pytest.mark.parametrize(
    ("case_id", "usage_field", "input_key", "output_key", "total_key"),
    (
        ("openai-completed", "usage", "input_tokens", "output_tokens", "total_tokens"),
        ("azure-completed", "usage", "input_tokens", "output_tokens", "total_tokens"),
        ("aws-completed", "usage", "inputTokens", "outputTokens", "totalTokens"),
        ("gcp-completed", "usageMetadata", "promptTokenCount", "candidatesTokenCount", "totalTokenCount"),
    ),
)
@pytest.mark.parametrize("over_limit", (False, True))
def test_provider_output_usage_respects_approved_request_limit(
    case_id: str, usage_field: str, input_key: str, output_key: str, total_key: str, over_limit: bool
) -> None:
    plan, cases = inputs()
    case = copy.deepcopy(next(item for item in cases["cases"] if item["case_id"] == case_id))
    usage = case["response"][usage_field]
    usage[output_key] = case["request"]["max_output_tokens"] + int(over_limit)
    usage[total_key] = usage[input_key] + usage[output_key]
    bundle = {"schema_version": cases["schema_version"], "cases": [case]}
    if over_limit:
        with pytest.raises(ProviderAssessmentError, match="provider output token limit exceeded"):
            assess(plan, bundle)
    else:
        report = assess(plan, bundle)
        assert report["results"][0]["ledger_state"] == "settled"
        assert report["all_expectations_met"]


def test_terminal_response_without_usage_remains_unknown() -> None:
    plan, cases = inputs()
    case = copy.deepcopy(cases["cases"][0])
    case["response"].pop("usage")
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})
    assert report["results"][0]["response_state"] == "completed"
    assert report["results"][0]["usage_state"] == "unknown"
    assert report["results"][0]["ledger_state"] == "usage_unknown"
    assert not report["all_expectations_met"]


def test_denied_case_does_not_parse_response_envelope() -> None:
    plan, cases = inputs()
    case = copy.deepcopy(next(item for item in cases["cases"] if item["case_id"] == "endpoint-denied"))
    case["response"] = {"invalid": "synthetic"}
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})
    assert report["results"][0]["decision"] == "denied"
    assert report["results"][0]["response_state"] == "not_processed"


def test_provider_tool_proposal_must_match_approved_request() -> None:
    plan, cases = inputs()
    case = copy.deepcopy(next(item for item in cases["cases"] if item["case_id"] == "aws-tool-proposal"))
    content = case["response"]["output"]["message"]["content"]
    tool_use = next(item["toolUse"] for item in content if "toolUse" in item)
    tool_use["name"] = "unapproved_tool"
    with pytest.raises(ProviderAssessmentError, match="unapproved provider tool proposal"):
        assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})


def test_expectation_checks_usage_and_ledger_states() -> None:
    plan, cases = inputs()
    case = copy.deepcopy(cases["cases"][0])
    case["expected"]["usage_state"] = "unknown"
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})
    assert not report["all_expectations_met"]
    assert not report["results"][0]["expectation_met"]


def test_case_id_is_redacted_from_report() -> None:
    plan, cases = inputs()
    case = copy.deepcopy(cases["cases"][0])
    original_id = case["case_id"]
    case["case_id"] = "sk-proj-SYNTHETIC_SECRET_DO_NOT_REPORT"
    environment = next(item for item in plan["environments"] if item["environment_id"] == case["environment_id"])
    environment["approved_requests"][case["case_id"]] = environment["approved_requests"][original_id]
    report = assess(plan, {"schema_version": cases["schema_version"], "cases": [case]})
    assert report["results"][0]["case_id"] == report_case_id(case["case_id"])
    assert case["case_id"] not in json.dumps(report)
