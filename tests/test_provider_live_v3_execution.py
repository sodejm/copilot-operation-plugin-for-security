"""Production-class dispatch qualification uses local fakes, never a provider."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_provider_live_execution import _response, _setup
from test_provider_live_request_shapes import _case
from test_provider_live_schemas import CASES_VALIDATOR, PLAN_VALIDATOR, _v3_documents

from cops.assessment_budget import AssessmentBudgetLedger
from cops.evidence.canonical import canonical
from cops.execution import gateway_dispatch
from cops.provider_live import ProviderLiveError, _approved_request, _policy, execute_live_case, live_plan_digest

_PRODUCTION_DRIFT = [
    ("execution_class", "emulator"),
    ("auth_profile_id", "other-auth-profile"),
    ("credential_reference_id", "other-credential-reference"),
    ("transport_version", "openai-responses/v2"),
    ("endpoint_policy_digest", "f" * 64),
    ("worker_evidence_digest", "f" * 64),
]
_SCOPE_DRIFT = _PRODUCTION_DRIFT + [
    ("provider", "azure"),
    ("account_or_project_kind", "tenant"),
    ("account_or_project", "other-project"),
    ("region", "other-region"),
    ("model", "other-model"),
    ("request_target", "https://other.example.test/v1/responses"),
]


def _documents(provider="openai"):
    """Bind schema-valid documents to a current, independently signed v3 grant."""
    plan, cases = _v3_documents()
    case = cases["cases"][0]
    environment = plan["environments"][0]
    approved = environment["approved_requests"][0]
    sample, body = _case(provider)
    transport_versions = {
        "openai": "openai-responses/v1",
        "azure": "azure-openai-responses/v1",
        "aws": "bedrock-converse/v1",
        "gcp": "vertex-generate-content/v1",
    }
    raw = canonical(body)
    digest = hashlib.sha256(raw).hexdigest()
    for document in (environment, case):
        for key in ("provider", "account_or_project_kind", "account_or_project", "region", "model", "request_target"):
            document[key] = sample[key]
        document["transport_version"] = transport_versions[provider]
    case["request"].update(
        body_canonical_json=raw.decode(), body_sha256=digest, body_size_bytes=len(raw), max_output_tokens=32
    )
    estimate = dict(
        input_tokens=len(raw),
        output_tokens=32,
        cost_microunits=1000,
        request_bytes=len(raw),
        response_bytes=4096,
        elapsed_ms=5000,
    )
    case["estimate"] = deepcopy(estimate)
    approved.update(request_sha256=digest, max_output_tokens=32, estimate=deepcopy(estimate))
    grant = approved["dispatch_grant"]
    grant["transport_version"] = transport_versions[provider]
    for key in ("provider", "account_or_project_kind", "account_or_project", "region", "model", "request_target"):
        grant[key] = case[key]
    now = datetime.now(UTC)
    grant.update(
        body_sha256=digest,
        body_bytes=len(raw),
        max_output_tokens=32,
        issued_at=(now - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    key = Ed25519PrivateKey.generate()
    _resign(plan, case, key)
    PLAN_VALIDATOR.validate(plan)
    CASES_VALIDATOR.validate(dict(schema_version=cases["schema_version"], cases=[case]))
    return plan, case, key


def _resign(plan, case, private, *, update_digest=True):
    grant = plan["environments"][0]["approved_requests"][0]["dispatch_grant"]
    if update_digest:
        grant["plan_digest"] = live_plan_digest(plan)
    unsigned = {name: value for name, value in grant.items() if name != "signature"}
    grant["signature"] = private.sign(canonical(unsigned)).hex()
    case["dispatch_grant"] = deepcopy(grant)


def _production_setup(tmp_path, monkeypatch, provider="openai", *, endpoint_changes=None, response=None):
    """Keep the real credential, signature, replay, and dispatcher boundaries."""
    from cops.execution import gateway_credentials, provider_transport

    plan, case, private = _documents(provider)
    env = plan["environments"][0]
    grant = case["dispatch_grant"]
    endpoint_fields = {
        name: env[name]
        for name in (
            "gateway_endpoint_id",
            "endpoint_origin",
            "gateway_path",
            "provider",
            "account_or_project_kind",
            "account_or_project",
            "region",
            "model",
            "request_target",
            "auth_profile_id",
            "credential_reference_id",
            "transport_version",
            "endpoint_policy_digest",
            "worker_evidence_digest",
        )
    }
    endpoint_fields.update(
        {
            name: grant[name]
            for name in (
                "max_output_tokens",
                "max_response_bytes",
                "max_elapsed_ms",
            )
        }
    )
    endpoint_fields.update(endpoint_changes or {})
    endpoint = gateway_dispatch.GatewayProductionEndpoint(
        **endpoint_fields,
        gateway_identity=env["gateway_spiffe_id"],
    )
    credentials = {
        "openai": lambda: gateway_credentials.OpenAIResponseCredential("SYNTHETIC_PRIVATE_CREDENTIAL"),
        "azure": lambda: gateway_credentials.AzureOpenAIResponseCredential("SYNTHETIC_PRIVATE_CREDENTIAL"),
        "aws": lambda: gateway_credentials.BedrockCredential("SYNTHETIC_PRIVATE_ID", "SYNTHETIC_PRIVATE_CREDENTIAL"),
        "gcp": lambda: gateway_credentials.VertexCredential("SYNTHETIC_PRIVATE_CREDENTIAL"),
    }
    resolved, sent = [], []
    credential = credentials[provider]()

    def resolver(reference):
        resolved.append(reference)
        assert reference == endpoint.credential_reference_id
        return credential

    def fake_transport(transport, transport_endpoint, body, supplied_credential):
        assert transport_endpoint == endpoint
        assert supplied_credential is credential
        assert body == case["request"]["body_canonical_json"].encode()
        assert transport.transport_version == grant["transport_version"]
        assert transport.max_response_bytes == grant["max_response_bytes"]
        assert transport.max_elapsed_ms == grant["max_elapsed_ms"]
        sent.append(grant["dispatch_id"])
        return gateway_dispatch.GatewayDispatchResponse(
            200,
            "application/json",
            canonical(_response(provider) if response is None else response),
        )

    monkeypatch.setattr(provider_transport.GatewayProviderTransport, "__call__", fake_transport)
    handler = gateway_credentials.GatewayProductionProviderHandler(
        bindings={
            endpoint.gateway_endpoint_id: gateway_credentials.GatewayCredentialBinding(
                endpoint,
                endpoint.credential_reference_id,
            )
        },
        credential_resolver=resolver,
    )
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    authorizer = gateway_dispatch.GatewayDispatchTransportAuthorizer(
        trust_store=gateway_dispatch.GatewayDispatchTrustStore({grant["key_id"]: public}),
        endpoints={endpoint.gateway_endpoint_id: endpoint},
    )
    gateway = gateway_dispatch.GatewayProductionDispatcher(
        authorizer=authorizer,
        replay_store=gateway_dispatch.GatewayDispatchReplayStore(tmp_path / "replay.sqlite3"),
        action_plan_id=plan["action_plan_id"],
        plan_digest=live_plan_digest(plan),
        worker_spiffe_id=grant["worker_spiffe_id"],
        endpoint_origin=env["endpoint_origin"],
        gateway_path=env["gateway_path"],
        handler=handler,
    )
    args = dict(
        gateway=gateway,
        ledger=AssessmentBudgetLedger(tmp_path / "budget.sqlite3", _policy(plan)),
        trusted_gateway_origin=env["endpoint_origin"],
        trusted_gateway_identity=env["gateway_spiffe_id"],
        worker_spiffe_id=grant["worker_spiffe_id"],
    )
    return plan, case, args, resolved, sent, private


@pytest.mark.parametrize(("field", "value"), _SCOPE_DRIFT)
@pytest.mark.parametrize("boundary", ["case", "environment"])
def test_v3_approved_request_requires_exact_environment_scope(field, value, boundary):
    plan, case, _ = _documents()
    assert _approved_request(plan, case)[0] is plan["environments"][0]
    target = case if boundary == "case" else plan["environments"][0]
    target[field] = value
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        _approved_request(plan, case)


def test_v3_signed_grant_parser_preserves_every_production_binding():
    _, case, _ = _documents()
    grant = gateway_dispatch.GatewayDispatchGrant.from_dict(case["dispatch_grant"])
    assert grant.to_dict() == case["dispatch_grant"]


@pytest.mark.parametrize("extra", ["credential", "access_token", "unreviewed_option"])
def test_v3_signed_grant_parser_rejects_unknown_fields(extra):
    _, case, _ = _documents()
    malformed = dict(case["dispatch_grant"], **{extra: "SYNTHETIC_PRIVATE_VALUE"})
    with pytest.raises(gateway_dispatch.GatewayDispatchError) as caught:
        gateway_dispatch.GatewayDispatchGrant.from_dict(malformed)
    assert "SYNTHETIC_PRIVATE_VALUE" not in str(caught.value)


def test_v2_remains_executable_through_emulator_only(tmp_path):
    plan, case, args, called = _setup(tmp_path, "openai")
    result = execute_live_case(plan, case, **args)
    assert result["outcome"] == "completed"
    assert called == ["dispatch-001"]
    assert plan["schema_version"].endswith("/v2")
    assert case["dispatch_grant"]["schema_version"].endswith("/v2")
    assert "PRIVATE_CANARY_RESPONSE" not in json.dumps(result)


@pytest.mark.parametrize("provider", ["openai", "azure", "aws", "gcp"])
def test_v3_production_dispatch_is_one_use_bounded_and_redacted(tmp_path, monkeypatch, caplog, provider):
    plan, case, args, resolved, sent, _ = _production_setup(tmp_path, monkeypatch, provider)
    result = execute_live_case(plan, case, **args)
    assert result["outcome"] == "completed"
    assert result["ledger_state"] == "uncertain"
    assert result["billing_state"] == "unreconciled"
    assert resolved == [case["credential_reference_id"]]
    assert sent == [case["dispatch_grant"]["dispatch_id"]]
    evidence = json.dumps(result) + caplog.text
    for private in (
        "PRIVATE_CANARY_RESPONSE",
        "SYNTHETIC_PRIVATE_CREDENTIAL",
        case["credential_reference_id"],
        case["account_or_project"],
        case["request"]["body_canonical_json"],
    ):
        assert private not in evidence
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert len(resolved) == len(sent) == 1


_SIGNED_DRIFT = _PRODUCTION_DRIFT + [
    ("max_output_tokens", 31),
    ("max_output_tokens", 33),
    ("max_response_bytes", 4095),
    ("max_response_bytes", 4097),
    ("max_elapsed_ms", 4999),
    ("max_elapsed_ms", 5001),
    ("body_bytes", 2),
    ("body_sha256", "f" * 64),
    ("worker_spiffe_id", "spiffe://workers.example.test/worker/other"),
]


@pytest.mark.parametrize(("field", "value"), _SIGNED_DRIFT)
def test_v3_signed_grant_drift_is_denied_before_credential_resolution(tmp_path, monkeypatch, field, value):
    plan, case, args, resolved, sent, private = _production_setup(tmp_path, monkeypatch)
    plan["environments"][0]["approved_requests"][0]["dispatch_grant"][field] = value
    # Grants are excluded from the plan digest. Sign the intentionally malformed
    # scope without asking schema validation to authorize it as a plan first.
    _resign(plan, case, private, update_digest=False)
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert resolved == sent == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_profile_id", "other-auth-profile"),
        ("credential_reference_id", "other-credential-reference"),
        ("endpoint_policy_digest", "f" * 64),
        ("worker_evidence_digest", "f" * 64),
        ("max_output_tokens", 31),
        ("max_output_tokens", 33),
        ("max_response_bytes", 4095),
        ("max_response_bytes", 4097),
        ("max_elapsed_ms", 4999),
        ("max_elapsed_ms", 5001),
    ],
)
def test_v3_configured_endpoint_requires_exact_signed_scope(tmp_path, monkeypatch, field, value):
    plan, case, args, resolved, sent, _ = _production_setup(
        tmp_path,
        monkeypatch,
        endpoint_changes={field: value},
    )
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert resolved == sent == []


def test_v3_provider_failure_redacts_private_payload_after_single_send(tmp_path, monkeypatch, caplog):
    plan, case, args, resolved, sent, _ = _production_setup(
        tmp_path,
        monkeypatch,
        response={"private": "SYNTHETIC_PRIVATE_PROVIDER_PAYLOAD"},
    )
    with pytest.raises(ProviderLiveError, match="dispatch denied") as caught:
        execute_live_case(plan, case, **args)
    assert len(resolved) == len(sent) == 1
    assert "SYNTHETIC_PRIVATE_PROVIDER_PAYLOAD" not in str(caught.value) + caplog.text
    assert caught.value.__context__ is None or caught.value.__suppress_context__
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert len(resolved) == len(sent) == 1


def test_v2_signed_evidence_is_ineligible_for_production_dispatch(tmp_path, monkeypatch):
    _, _, args, resolved, sent, _ = _production_setup(tmp_path / "production", monkeypatch)
    plan, case, _, _ = _setup(tmp_path / "legacy", "openai")
    PLAN_VALIDATOR.validate(plan)
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert resolved == sent == []


def test_v3_production_documents_are_ineligible_for_emulator_dispatch(tmp_path):
    _, _, args, sent = _setup(tmp_path, "openai")
    plan, case, _ = _documents()
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, **args)
    assert sent == []
