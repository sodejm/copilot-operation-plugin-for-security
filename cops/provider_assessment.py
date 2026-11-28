"""Offline, synthetic AI provider assessment under an exact plan and budget.

This module has no provider client, credential lookup, or live execution mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cops._schema_validation import SchemaValidationError, validate
from cops.assessment_budget import (
    AssessmentBudgetLedger,
    AttemptRequest,
    BudgetDenied,
    BudgetLimits,
    BudgetPolicy,
    Receipt,
    dispatch_fixture,
)

_PLUGIN = Path(__file__).resolve().parents[1] / "plugins/offensive-security/foundry-agent-harness"
_MAX_INPUT_BYTES = 256 * 1024
_MAX_DEPTH = 16
_PROVIDERS = frozenset({"openai", "azure", "aws", "gcp"})


class ProviderAssessmentError(ValueError):
    """An input fails the offline assessment contract."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderAssessmentError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> Any:
    raise ProviderAssessmentError("non-finite JSON constant")


def _bounded(value: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ProviderAssessmentError("JSON nesting limit exceeded")
    if isinstance(value, dict):
        for item in value.values():
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1)


def _schema(name: str) -> dict[str, Any]:
    return json.loads((_PLUGIN / "schemas" / name).read_text(encoding="utf-8"))


def _validate(value: Any, name: str) -> None:
    try:
        validate(value, _schema(name))
    except SchemaValidationError as exc:
        raise ProviderAssessmentError("input does not match " + name) from exc


def read_json(path: Path, schema_name: str) -> Any:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ProviderAssessmentError("input must be a regular file")
            content = source.read(_MAX_INPUT_BYTES + 1)
        if len(content) > _MAX_INPUT_BYTES:
            raise ProviderAssessmentError("input size limit exceeded")
        value = json.loads(
            content.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_reject_json_constant
        )
    except RecursionError as exc:
        raise ProviderAssessmentError("JSON nesting limit exceeded") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderAssessmentError("invalid JSON input") from exc
    _bounded(value)
    _validate(value, schema_name)
    return value


def request_digest(case: dict[str, Any]) -> str:
    """Bind the exact scope, tools, request, and budget estimate to a plan."""
    bound = {key: case[key] for key in ("provider", "scope", "requested_tools", "request", "estimate")}
    canonical = json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def report_case_id(case_id: str) -> str:
    """Keep untrusted case identifiers out of exported evidence."""
    return "case-" + hashlib.sha256(case_id.encode("ascii")).hexdigest()


def _environment_gate(plan: dict[str, Any], case: dict[str, Any]) -> bool:
    environments = {item["environment_id"]: item for item in plan["environments"]}
    environment = environments.get(case["environment_id"])
    if environment is None or case["provider"] != environment["provider"]:
        return False
    if case["scope"] != environment["scope"]:
        return False
    endpoint = urlsplit(case["scope"]["endpoint"])
    if endpoint.scheme != "https" or not endpoint.hostname or not endpoint.hostname.endswith(".invalid"):
        return False
    if not set(case["requested_tools"]).issubset(environment["allowed_tools"]):
        return False
    if case["request"]["canary_id"] not in environment["canary_ids"]:
        return False
    return environment["approved_requests"].get(case["case_id"]) == request_digest(case)


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**63 - 1


def _usage(payload: Any, input_key: str, output_key: str, total_key: str) -> tuple[int, int] | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ProviderAssessmentError("invalid provider usage")
    values = [payload.get(key) for key in (input_key, output_key, total_key)]
    if not all(_nonnegative_int(value) for value in values):
        raise ProviderAssessmentError("invalid provider usage")
    if values[0] + values[1] != values[2]:
        raise ProviderAssessmentError("invalid provider usage")
    return values[2], values[1]


def normalize_response(provider: str, response: dict[str, Any]) -> tuple[str, int | None, int | None]:
    """Return a conservative state and token counts; no response content escapes."""
    if provider in {"openai", "azure"}:
        status = response.get("status")
        state = "completed" if status == "completed" else "partial"
        usage = _usage(response.get("usage"), "input_tokens", "output_tokens", "total_tokens")
    elif provider == "aws":
        reason = response.get("stopReason")
        state = "tool_proposal" if reason == "tool_use" else "completed" if reason == "end_turn" else "partial"
        usage = _usage(response.get("usage"), "inputTokens", "outputTokens", "totalTokens")
    elif provider == "gcp":
        candidates = response.get("candidates")
        first = candidates[0] if isinstance(candidates, list) and candidates else None
        reason = first.get("finishReason") if isinstance(first, dict) else None
        state = "completed" if reason == "STOP" else "partial"
        usage = _usage(response.get("usageMetadata"), "promptTokenCount", "candidatesTokenCount", "totalTokenCount")
    else:
        raise ProviderAssessmentError("unsupported provider")
    # Partial responses cannot be treated as completed even when they claim usage.
    return state, usage[0] if usage is not None else None, usage[1] if usage is not None else None


def _policy(plan: dict[str, Any]) -> BudgetPolicy:
    budget = plan["budget"]
    return BudgetPolicy(
        engagement_id=plan["engagement_id"],
        limits=BudgetLimits(**budget["limits"]),
        currency=budget["currency"],
        price_source=budget["price_source"],
        price_version=budget["price_version"],
        price_effective_date=budget["price_effective_date"],
    )


def _fixture_receipt(
    case: dict[str, Any],
    result: dict[str, Any],
    _: AttemptRequest,
    __: Any,
) -> Receipt:
    _validate({"provider": case["provider"], "response": case["response"]}, "provider-response.schema.json")
    state, tokens, output_tokens = normalize_response(case["provider"], case["response"])
    if output_tokens is not None and output_tokens > case["request"]["max_output_tokens"]:
        raise ProviderAssessmentError("provider output token limit exceeded")
    if state == "tool_proposal":
        content = case["response"]["output"]["message"]["content"]
        proposed_tools = {item["toolUse"]["name"] for item in content if "toolUse" in item}
        if not proposed_tools.issubset(case["requested_tools"]):
            raise ProviderAssessmentError("unapproved provider tool proposal")
    result["response_state"] = state
    result["outcome"] = state if state in {"completed", "tool_proposal"} else "no_effect"
    result["usage_state"] = "known_synthetic" if tokens is not None and state != "partial" else "unknown"
    return Receipt(
        receipt_id="r-" + hashlib.sha256(case["case_id"].encode("ascii")).hexdigest(),
        attempt_id=case["case_id"],
        outcome="completed" if state in {"completed", "tool_proposal"} else "failed",
        tokens=tokens if state != "partial" else None,
        cost_microunits=case["estimate"]["cost_microunits"] if tokens is not None and state != "partial" else None,
        retained_output_bytes=0 if tokens is not None and state != "partial" else None,
    )


def assess(plan: dict[str, Any], case_bundle: dict[str, Any]) -> dict[str, Any]:
    """Assess fixed fixtures; report only allowlisted, non-content evidence."""
    _bounded(plan)
    _bounded(case_bundle)
    _validate(plan, "provider-plan.schema.json")
    _validate(case_bundle, "provider-cases.schema.json")
    if plan["mode"] != "offline_fixture" or plan["paid_execution_opt_in"] is not False:
        raise ProviderAssessmentError("live or paid execution is unavailable")
    cases = case_bundle["cases"]
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ProviderAssessmentError("duplicate case ID")
    if len({item["environment_id"] for item in plan["environments"]}) != len(plan["environments"]):
        raise ProviderAssessmentError("duplicate environment ID")
    if any(item["provider"] not in _PROVIDERS for item in plan["environments"]):
        raise ProviderAssessmentError("unsupported provider")
    results: list[dict[str, Any]] = []
    temporary = tempfile.TemporaryDirectory(prefix="cops-provider-fixture-")
    try:
        ledger = AssessmentBudgetLedger(Path(temporary.name) / "budget.sqlite3", _policy(plan))
        for case in cases:
            result = {
                "case_id": report_case_id(case["case_id"]),
                "provider": case["provider"],
                "decision": "denied",
                "outcome": "no_effect",
                "response_state": "not_processed",
                "usage_state": "not_charged",
                "ledger_state": "none",
            }
            if _environment_gate(plan, case):
                estimate = case["estimate"]
                request = AttemptRequest(
                    attempt_id=case["case_id"],
                    parent_id=None,
                    estimated_tokens=estimate["tokens"],
                    estimated_cost_microunits=estimate["cost_microunits"],
                    reserved_output_bytes=estimate["output_bytes"],
                )

                try:
                    attempt = dispatch_fixture(ledger, request, partial(_fixture_receipt, case, result))
                except BudgetDenied:
                    result["decision"] = "budget_denied"
                else:
                    result["decision"] = "approved"
                    result["ledger_state"] = attempt.state
            result["expectation_met"] = all(
                result[key] == case["expected"][key]
                for key in ("decision", "outcome", "response_state", "usage_state", "ledger_state")
            )
            results.append(result)
        budget_snapshot = asdict(ledger.snapshot())
    finally:
        try:
            temporary.cleanup()
        except OSError:
            cleanup_verified = False
        else:
            cleanup_verified = not Path(temporary.name).exists()
    report = {
        "schema_version": "cops.ai-provider-assessment-report/v1",
        "mode": "offline_fixture",
        "all_expectations_met": all(result["expectation_met"] for result in results)
        and not budget_snapshot["over_budget"],
        "cleanup_verified": cleanup_verified,
        "budget": budget_snapshot,
        "results": results,
    }
    _validate(report, "provider-report.schema.json")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic AI provider fixtures offline")
    parser.add_argument("--plan", type=Path, default=_PLUGIN / "provider_fixtures" / "plan.json")
    parser.add_argument("--cases", type=Path, default=_PLUGIN / "provider_fixtures" / "cases.json")
    args = parser.parse_args(argv)
    try:
        report = assess(
            read_json(args.plan, "provider-plan.schema.json"), read_json(args.cases, "provider-cases.schema.json")
        )
    except (OSError, ProviderAssessmentError, ValueError) as exc:
        # Never echo input data or paths supplied by an untrusted fixture.
        parser.exit(2, "provider assessment input or execution failed: " + type(exc).__name__ + "\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["all_expectations_met"] and report["cleanup_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
