from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

SCHEMA_DIR = (
    Path(__file__).resolve().parents[1] / "plugins" / "offensive-security" / "foundry-agent-harness" / "schemas"
)
PLAN_SCHEMA_PATH = SCHEMA_DIR / "provider-live-plan.schema.json"
CASES_SCHEMA_PATH = SCHEMA_DIR / "provider-live-cases.schema.json"
RESPONSE_SCHEMA_PATH = SCHEMA_DIR / "provider-live-response.schema.json"
OFFLINE_RESPONSE_SCHEMA_PATH = SCHEMA_DIR / "provider-response.schema.json"
BODY = '{"input":"COPS_CANARY_001"}'
BODY_SHA256 = "a" * 64
PLAN_DIGEST = "b" * 64


def _load_schema(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _dispatch_grant() -> dict[str, Any]:
    return {
        "schema_version": "cops.operator-gateway-dispatch/v2",
        "dispatch_id": "dispatch-001",
        "authorization_id": "authorization-001",
        "action_plan_id": "action-plan-001",
        "plan_digest": PLAN_DIGEST,
        "worker_spiffe_id": "spiffe://example.test/worker/live",
        "provider": "openai",
        "account_or_project_kind": "project",
        "account_or_project": "project-test",
        "region": "us-east-1",
        "model": "gpt-5-mini",
        "gateway_endpoint_id": "gateway-lab",
        "request_target": "https://api.openai.com/v1/responses",
        "body_sha256": BODY_SHA256,
        "body_bytes": len(BODY.encode()),
        "issued_at": "2026-10-16T12:00:00Z",
        "expires_at": "2026-10-16T12:05:00Z",
        "key_id": "operator-key-001",
        "algorithm": "ed25519",
        "signature": "c" * 128,
    }


def _plan() -> dict[str, Any]:
    return {
        "schema_version": "cops.ai-provider-live-assessment-plan/v2",
        "mode": "live_gateway",
        "paid_execution_opt_in": True,
        "engagement_id": "engagement-001",
        "action_plan_id": "action-plan-001",
        "shared_budget": {
            "currency": "USD",
            "price_source": "approved-price-catalog",
            "price_version": "2026-10-16",
            "price_effective_date": "2026-10-16",
            "limits": {
                "max_attempts": 4,
                "max_estimated_tokens": 4000,
                "max_estimated_cost_microunits": 1000000,
                "max_elapsed_ms": 60000,
                "max_concurrency": 1,
                "max_retained_output_bytes": 65536,
                "max_depth": 1,
                "max_children_per_parent": 4,
            },
        },
        "environments": [
            {
                "environment_id": "openai-emulator",
                "provider": "openai",
                "account_or_project_kind": "project",
                "account_or_project": "project-test",
                "region": "us-east-1",
                "model": "gpt-5-mini",
                "request_target": "https://api.openai.com/v1/responses",
                "endpoint_origin": "https://gateway.example.test:443",
                "gateway_path": "/v1/dispatch",
                "gateway_endpoint_id": "gateway-lab",
                "gateway_spiffe_id": "spiffe://example.test/gateway/live",
                "allowed_tools": [],
                "approved_requests": [
                    {
                        "request_id": "request-001",
                        "canary_id": "canary-001",
                        "request_sha256": BODY_SHA256,
                        "max_output_tokens": 128,
                        "estimate": {
                            "input_tokens": 32,
                            "output_tokens": 128,
                            "cost_microunits": 1000,
                            "request_bytes": len(BODY.encode()),
                            "response_bytes": 4096,
                            "elapsed_ms": 5000,
                        },
                        "dispatch_grant": _dispatch_grant(),
                    }
                ],
            }
        ],
    }


def _cases() -> dict[str, Any]:
    return {
        "schema_version": "cops.ai-provider-live-assessment-cases/v2",
        "cases": [
            {
                "case_id": "case-001",
                "environment_id": "openai-emulator",
                "provider": "openai",
                "account_or_project_kind": "project",
                "account_or_project": "project-test",
                "region": "us-east-1",
                "model": "gpt-5-mini",
                "request_target": "https://api.openai.com/v1/responses",
                "endpoint_origin": "https://gateway.example.test:443",
                "gateway_path": "/v1/dispatch",
                "gateway_endpoint_id": "gateway-lab",
                "gateway_spiffe_id": "spiffe://example.test/gateway/live",
                "requested_tools": [],
                "request": {
                    "request_id": "request-001",
                    "canary_id": "canary-001",
                    "prompt_id": "prompt-001",
                    "synthetic_only": True,
                    "body_canonical_json": BODY,
                    "body_sha256": BODY_SHA256,
                    "body_size_bytes": len(BODY.encode()),
                    "max_output_tokens": 128,
                },
                "estimate": {
                    "input_tokens": 32,
                    "output_tokens": 128,
                    "cost_microunits": 1000,
                    "request_bytes": len(BODY.encode()),
                    "response_bytes": 4096,
                    "elapsed_ms": 5000,
                },
                "dispatch_grant": _dispatch_grant(),
            }
        ],
    }


PLAN_SCHEMA = _load_schema(PLAN_SCHEMA_PATH)
CASES_SCHEMA = _load_schema(CASES_SCHEMA_PATH)
RESPONSE_SCHEMA = _load_schema(RESPONSE_SCHEMA_PATH)
PLAN_VALIDATOR = Draft202012Validator(PLAN_SCHEMA)
CASES_VALIDATOR = Draft202012Validator(CASES_SCHEMA)
RESPONSE_VALIDATOR = Draft202012Validator(RESPONSE_SCHEMA)


def test_live_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(PLAN_SCHEMA)
    Draft202012Validator.check_schema(CASES_SCHEMA)
    Draft202012Validator.check_schema(RESPONSE_SCHEMA)


def test_live_plan_accepts_explicit_opt_in_and_empty_tool_allowlist() -> None:
    PLAN_VALIDATOR.validate(_plan())


def test_live_cases_accept_bounded_synthetic_request_and_empty_tools() -> None:
    CASES_VALIDATOR.validate(_cases())


def test_live_plan_requires_paid_execution_opt_in() -> None:
    plan = _plan()
    plan["paid_execution_opt_in"] = False

    with pytest.raises(ValidationError):
        PLAN_VALIDATOR.validate(plan)


@pytest.mark.parametrize(
    "field",
    [
        "provider",
        "account_or_project_kind",
        "account_or_project",
        "region",
        "model",
        "request_target",
        "endpoint_origin",
        "gateway_path",
        "gateway_endpoint_id",
        "gateway_spiffe_id",
    ],
)
def test_live_plan_requires_exact_scope_and_gateway_identity(field: str) -> None:
    plan = _plan()
    del plan["environments"][0][field]

    with pytest.raises(ValidationError):
        PLAN_VALIDATOR.validate(plan)


def test_live_plan_requires_one_dispatch_grant_per_approved_request() -> None:
    plan = _plan()
    del plan["environments"][0]["approved_requests"][0]["dispatch_grant"]

    with pytest.raises(ValidationError):
        PLAN_VALIDATOR.validate(plan)


def test_live_plan_requires_positive_approved_estimate() -> None:
    plan = _plan()
    plan["environments"][0]["approved_requests"][0]["estimate"]["cost_microunits"] = 0

    with pytest.raises(ValidationError):
        PLAN_VALIDATOR.validate(plan)


def test_live_case_rejects_request_body_over_256_kib() -> None:
    cases = _cases()
    cases["cases"][0]["request"]["body_canonical_json"] = "x" * 262145
    cases["cases"][0]["request"]["body_size_bytes"] = 262145

    with pytest.raises(ValidationError):
        CASES_VALIDATOR.validate(cases)


def test_live_case_rejects_response_estimate_over_gateway_limit() -> None:
    cases = _cases()
    cases["cases"][0]["estimate"]["response_bytes"] = 1048577

    with pytest.raises(ValidationError):
        CASES_VALIDATOR.validate(cases)

    plan = _plan()
    plan["environments"][0]["approved_requests"][0]["estimate"]["response_bytes"] = 1048577
    with pytest.raises(ValidationError):
        PLAN_VALIDATOR.validate(plan)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_target", "https://api.openai.com/v1/responses?unsafe=true"),
        ("endpoint_origin", "http://gateway.example.test"),
        ("gateway_path", "/v1/../dispatch"),
        ("gateway_spiffe_id", "https://example.test/gateway"),
    ],
)
def test_live_case_rejects_malformed_endpoint_identity(field: str, value: str) -> None:
    cases = _cases()
    cases["cases"][0][field] = value

    with pytest.raises(ValidationError):
        CASES_VALIDATOR.validate(cases)


def test_live_case_rejects_unrecognized_fields() -> None:
    cases = copy.deepcopy(_cases())
    cases["cases"][0]["unreviewed_override"] = True

    with pytest.raises(ValidationError):
        CASES_VALIDATOR.validate(cases)


@pytest.mark.parametrize(
    ("provider", "response"),
    [
        ("openai", {"status": "completed", "output": [{"type": "function_call", "name": "inspect"}]}),
        ("azure", {"status": "completed", "output": [{"type": "function_call", "name": "inspect"}]}),
        ("aws", {"stopReason": "tool_use", "output": {"message": {"content": [{"toolUse": {"name": "inspect"}}]}}}),
        (
            "gcp",
            {"candidates": [{"content": {"parts": [{"functionCall": {"name": "inspect"}}]}, "finishReason": "STOP"}]},
        ),
    ],
)
def test_live_projection_accepts_inert_tool_proposals(provider: str, response: dict[str, Any]) -> None:
    RESPONSE_VALIDATOR.validate({"provider": provider, "response": response})


def test_offline_response_schema_still_rejects_openai_tool_proposal() -> None:
    offline_validator = Draft202012Validator(_load_schema(OFFLINE_RESPONSE_SCHEMA_PATH))
    envelope = {
        "provider": "openai",
        "response": {"status": "completed", "output": [{"type": "function_call", "name": "inspect"}]},
    }
    with pytest.raises(ValidationError):
        offline_validator.validate(envelope)


def test_live_projection_rejects_tool_arguments() -> None:
    envelope = {
        "provider": "openai",
        "response": {
            "status": "completed",
            "output": [{"type": "function_call", "name": "inspect", "arguments": "secret"}],
        },
    }
    with pytest.raises(ValidationError):
        RESPONSE_VALIDATOR.validate(envelope)
