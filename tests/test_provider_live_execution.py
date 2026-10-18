"""The live capability exercises only a signed, one-use gateway emulator."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_provider_live_request_shapes import _case
from test_provider_live_schemas import _cases, _plan

from cops.assessment_budget import AssessmentBudgetLedger
from cops.evidence.canonical import canonical
from cops.execution.gateway_credentials import (
    LIVE_PROVIDER_TRANSPORT,
    GatewayCredentialBinding,
    GatewayScopedProviderHandler,
)
from cops.execution.gateway_dispatch import (
    GatewayDispatchEmulator,
    GatewayDispatchEndpoint,
    GatewayDispatchGrant,
    GatewayDispatchReplayStore,
    GatewayDispatchResponse,
    GatewayDispatchTransportAuthorizer,
    GatewayDispatchTrustStore,
    sign_gateway_dispatch,
)
from cops.provider_live import ProviderLiveError, _policy, execute_live_case, live_plan_digest


def _response(provider: str) -> dict:
    secret = "PRIVATE_CANARY_RESPONSE"
    if provider in {"openai", "azure"}:
        return {
            "status": "completed",
            "output": [{"text": secret}],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        }
    if provider == "aws":
        return {
            "stopReason": "end_turn",
            "output": {"message": {"content": [{"text": secret}]}},
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        }
    return {
        "candidates": [{"content": {"parts": [{"text": secret}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
    }


def _setup(
    tmp_path,
    provider: str,
    *,
    handler=None,
    max_cost: int = 1000000,
    scoped_handler: bool = False,
    allowed_tools: tuple[str, ...] = (),
):
    plan, case = _plan(), _cases()["cases"][0]
    sample, body = _case(provider)
    raw = canonical(body)
    digest = hashlib.sha256(raw).hexdigest()
    for target in (plan["environments"][0], case):
        for field in ("provider", "account_or_project_kind", "account_or_project", "region", "model", "request_target"):
            target[field] = sample[field]
    plan["environments"][0]["allowed_tools"] = list(allowed_tools)
    case["requested_tools"] = list(allowed_tools)
    case["request"].update(
        body_canonical_json=raw.decode(), body_sha256=digest, body_size_bytes=len(raw), max_output_tokens=32
    )
    approved = plan["environments"][0]["approved_requests"][0]
    approved.update(request_sha256=digest, max_output_tokens=32)
    estimate = {
        "input_tokens": len(raw),
        "output_tokens": 32,
        "cost_microunits": 1000,
        "request_bytes": len(raw),
        "response_bytes": 4096,
        "elapsed_ms": 5000,
    }
    approved["estimate"] = deepcopy(estimate)
    case["estimate"] = deepcopy(estimate)
    plan["shared_budget"]["limits"]["max_estimated_cost_microunits"] = max_cost
    now = datetime.now(UTC)
    issued = (now - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fields = dict(approved["dispatch_grant"])
    fields.update(
        plan_digest=live_plan_digest(plan),
        provider=provider,
        account_or_project_kind=case["account_or_project_kind"],
        account_or_project=case["account_or_project"],
        region=case["region"],
        model=case["model"],
        request_target=case["request_target"],
        body_sha256=digest,
        body_bytes=len(raw),
        issued_at=issued,
        expires_at=expires,
        signature="",
    )
    grant = sign_gateway_dispatch(GatewayDispatchGrant(**fields), private).to_dict()
    approved["dispatch_grant"] = grant
    case["dispatch_grant"] = deepcopy(grant)
    env = plan["environments"][0]
    endpoint = GatewayDispatchEndpoint(
        **{
            key: env[key]
            for key in (
                "gateway_endpoint_id",
                "endpoint_origin",
                "gateway_path",
                "provider",
                "account_or_project_kind",
                "account_or_project",
                "region",
                "model",
                "request_target",
            )
        },
        gateway_identity=env["gateway_spiffe_id"],
    )
    authorizer = GatewayDispatchTransportAuthorizer(
        trust_store=GatewayDispatchTrustStore({"operator-key-001": public}),
        endpoints={env["gateway_endpoint_id"]: endpoint},
    )
    called = []
    if scoped_handler:
        assert handler is None

        def transport(transport_endpoint, transport_body, credential):
            assert transport_endpoint == endpoint
            assert transport_body == raw
            assert credential == "fixture-credential"
            called.append("dispatch-001")
            return GatewayDispatchResponse(200, "application/json", canonical(_response(provider)))

        handler = GatewayScopedProviderHandler(
            bindings={endpoint.gateway_endpoint_id: GatewayCredentialBinding(endpoint, "fixture-ref")},
            credential_resolver=lambda ref: "fixture-credential" if ref == "fixture-ref" else None,
            transports={LIVE_PROVIDER_TRANSPORT[provider]: transport},
        )
    elif handler is None:

        def handler(invocation):
            called.append(invocation.dispatch_id)
            return GatewayDispatchResponse(200, "application/json", canonical(_response(provider)))

    gateway = GatewayDispatchEmulator(
        authorizer=authorizer,
        replay_store=GatewayDispatchReplayStore(tmp_path / "replay" / "store.sqlite3"),
        action_plan_id=plan["action_plan_id"],
        plan_digest=live_plan_digest(plan),
        worker_spiffe_id=grant["worker_spiffe_id"],
        endpoint_origin=env["endpoint_origin"],
        gateway_path=env["gateway_path"],
        handler=handler,
    )
    ledger = AssessmentBudgetLedger(tmp_path / "budget" / "ledger.sqlite3", _policy(plan))
    args = dict(
        gateway=gateway,
        ledger=ledger,
        trusted_gateway_origin=env["endpoint_origin"],
        trusted_gateway_identity=env["gateway_spiffe_id"],
        worker_spiffe_id=grant["worker_spiffe_id"],
    )
    return plan, case, args, called


@pytest.mark.parametrize("provider", ["openai", "azure", "aws", "gcp"])
def test_signed_emulator_dispatch_is_one_use_and_redacted(tmp_path, provider):
    plan, case, args, called = _setup(tmp_path, provider, scoped_handler=True)
    result = execute_live_case(plan, case, **args)
    assert result["outcome"] == "completed"
    assert result["ledger_state"] == "uncertain"
    assert result["billing_state"] == "unreconciled"
    assert called == ["dispatch-001"]
    assert "PRIVATE_CANARY_RESPONSE" not in json.dumps(result)
    assert case["account_or_project"] not in json.dumps(result)
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert called == ["dispatch-001"]


def test_scope_identity_and_budget_fail_before_dispatch(tmp_path):
    plan, case, args, called = _setup(tmp_path, "openai")
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **dict(args, trusted_gateway_identity="spiffe://example.test/gateway/wrong"))
    bad_case = deepcopy(case)
    bad_case["region"] = "other-region"
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, bad_case, **args)
    assert called == []
    plan, case, args, called = _setup(tmp_path / "small", "openai", max_cost=1)
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert called == []


def test_partial_response_and_cancel_hold_reservation_and_cleanup(tmp_path):
    cleaned = []

    def incomplete(_invocation):
        return GatewayDispatchResponse(200, "application/json", b'{"status":"incomplete"}')

    plan, case, args, _ = _setup(tmp_path / "partial", "openai", handler=incomplete)
    result = execute_live_case(plan, case, cleanup=lambda: cleaned.append(True) or True, **args)
    assert result["outcome"] == "uncertain"
    assert result["ledger_state"] == "uncertain"
    assert cleaned == [True]

    def cancelled(_invocation):
        raise KeyboardInterrupt()

    plan, case, args, _ = _setup(tmp_path / "cancel", "openai", handler=cancelled)
    with pytest.raises(KeyboardInterrupt):
        execute_live_case(plan, case, cleanup=lambda: cleaned.append(True) or True, **args)
    assert args["ledger"].snapshot().charged_attempts == 1
    assert cleaned == [True, True]
