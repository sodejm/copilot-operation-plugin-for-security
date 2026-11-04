"""Offline tests of the v3 gateway credential and one-use dispatch boundary."""

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cops.execution import provider_transport
from cops.execution.gateway_credentials import (
    AzureOpenAIResponseCredential,
    BedrockCredential,
    GatewayCredentialBinding,
    GatewayProductionProviderHandler,
    GatewayScopedProviderHandler,
    OpenAIResponseCredential,
    VertexCredential,
)
from cops.execution.gateway_dispatch import (
    GATEWAY_DISPATCH_ALGORITHM,
    GATEWAY_DISPATCH_SCHEMA,
    GATEWAY_PRODUCTION_DISPATCH_SCHEMA,
    GatewayDispatchEmulator,
    GatewayDispatchError,
    GatewayDispatchGrant,
    GatewayDispatchReplayError,
    GatewayDispatchReplayStore,
    GatewayDispatchResponse,
    GatewayDispatchTransportAuthorizer,
    GatewayDispatchTrustStore,
    GatewayProductionDispatcher,
    GatewayProductionEndpoint,
    decode_gateway_dispatch_envelope,
    encode_gateway_dispatch_envelope,
    sign_gateway_dispatch,
)

SECRET = "synthetic-secret-do-not-release"
VERSIONS = {
    "openai": "openai-responses/v1",
    "azure": "azure-openai-responses/v1",
    "aws": "bedrock-converse/v1",
    "gcp": "vertex-generate-content/v1",
}
ALIASES = {"openai": "openai", "azure": "azure_openai", "aws": "bedrock", "gcp": "vertex"}
CREDENTIALS = {
    "openai": OpenAIResponseCredential(SECRET),
    "azure": AzureOpenAIResponseCredential(SECRET),
    "aws": BedrockCredential("fixture-access", SECRET),
    "gcp": VertexCredential(SECRET),
}
TARGETS = {
    "openai": "https://api.openai.com/v1/responses",
    "azure": "https://fixture.openai.azure.com/openai/v1/responses",
    "aws": "https://bedrock-runtime.us-east-1.amazonaws.com/model/model-1/converse",
    "gcp": "https://us-east1-aiplatform.googleapis.com/v1/projects/project-1/locations/us-east1/publishers/google/models/model-1:generateContent",
}


def setup_dispatch(tmp_path, monkeypatch, provider="openai"):
    endpoint = GatewayProductionEndpoint(
        gateway_endpoint_id="endpoint-1",
        gateway_identity="spiffe://gateway.test/runtime",
        endpoint_origin="https://gateway.test",
        gateway_path="/dispatch",
        provider=provider,
        account_or_project_kind="project",
        account_or_project="project-1",
        region="us-east-1" if provider == "aws" else "us-east1",
        model="model-1",
        request_target=TARGETS[provider],
        auth_profile_id="auth-1",
        credential_reference_id="credential-1",
        transport_version=VERSIONS[provider],
        endpoint_policy_digest="b" * 64,
        worker_evidence_digest="c" * 64,
        max_output_tokens=10,
        max_response_bytes=1024,
        max_elapsed_ms=1000,
    )
    if provider in {"openai", "azure"}:
        request = {
            "model": "model-1",
            "input": "fixture input",
            "max_output_tokens": 10,
            "store": False,
            "stream": False,
        }
    elif provider == "aws":
        request = {
            "messages": [{"role": "user", "content": [{"text": "fixture input"}]}],
            "inferenceConfig": {"maxTokens": 10},
        }
    else:
        request = {
            "contents": [{"role": "user", "parts": [{"text": "fixture input"}]}],
            "generationConfig": {"maxOutputTokens": 10},
        }
    body = json.dumps(request).encode()
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    grant = sign_gateway_dispatch(
        GatewayDispatchGrant(
            schema_version=GATEWAY_PRODUCTION_DISPATCH_SCHEMA,
            dispatch_id="dispatch-1",
            authorization_id="approval-1",
            action_plan_id="plan-1",
            plan_digest="a" * 64,
            worker_spiffe_id="spiffe://worker.test/approved",
            provider=provider,
            account_or_project_kind=endpoint.account_or_project_kind,
            account_or_project=endpoint.account_or_project,
            region=endpoint.region,
            model=endpoint.model,
            gateway_endpoint_id=endpoint.gateway_endpoint_id,
            request_target=endpoint.request_target,
            body_sha256=hashlib.sha256(body).hexdigest(),
            body_bytes=len(body),
            issued_at=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            expires_at=(now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            key_id="fixture-key",
            algorithm=GATEWAY_DISPATCH_ALGORITHM,
            execution_class="production",
            **{
                name: getattr(endpoint, name)
                for name in GatewayDispatchGrant._PRODUCTION_FIELDS
                if name != "execution_class"
            },
        ),
        key,
    )
    trust = GatewayDispatchTrustStore(
        {"fixture-key": key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)}
    )
    replay_path = tmp_path / "replay.sqlite3"
    events = []

    class FakeTransport:
        production_only = True
        transport_version = VERSIONS[provider]
        failure = False

        def validate_endpoint(self, checked):
            assert checked == endpoint
            events.append("validate")

        def __call__(self, checked, sent_body, credential):
            assert checked == endpoint and sent_body == body and credential is CREDENTIALS[provider]
            events.append("send")
            if self.failure:
                raise RuntimeError(SECRET)
            return GatewayDispatchResponse(200, "application/json", b'{"status":"completed","output":[]}')

    transport = FakeTransport()

    def registry(**caps):
        assert caps == {"max_response_bytes": 1024, "max_elapsed_ms": 1000}
        return {ALIASES[provider]: transport}

    monkeypatch.setattr(provider_transport, "registered_provider_transports", registry)

    def resolve(reference):
        assert reference == "credential-1"
        with sqlite3.connect(replay_path) as connection:
            assert connection.execute("SELECT count(*) FROM consumed_dispatches").fetchone() == (1,)
        events.append("resolve")
        return CREDENTIALS[provider]

    handler = GatewayProductionProviderHandler(
        bindings={"endpoint-1": GatewayCredentialBinding(endpoint, "credential-1")},
        credential_resolver=resolve,
    )
    options = dict(
        authorizer=GatewayDispatchTransportAuthorizer(trust_store=trust, endpoints={"endpoint-1": endpoint}),
        replay_store=GatewayDispatchReplayStore(replay_path),
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id=grant.worker_spiffe_id,
        endpoint_origin=endpoint.endpoint_origin,
        gateway_path=endpoint.gateway_path,
        handler=handler,
    )
    dispatcher = GatewayProductionDispatcher(**options)
    return dispatcher, grant, body, key, events, transport, options


def dispatch(dispatcher, grant, body, *, preflight=False):
    method = dispatcher.preflight if preflight else dispatcher.dispatch
    return method(
        grant=grant, body=body, presented_worker_spiffe_id=grant.worker_spiffe_id, request_target=grant.request_target
    )


@pytest.mark.parametrize("provider", VERSIONS)
def test_production_resolves_typed_credential_only_after_consume(tmp_path, monkeypatch, provider):
    dispatcher, grant, body, _, events, _, _ = setup_dispatch(tmp_path, monkeypatch, provider)
    assert dispatcher.execution_class == "production"
    dispatch(dispatcher, grant, body, preflight=True)
    assert events == ["validate"]
    receipt = dispatch(dispatcher, grant, body)
    assert events == ["validate", "validate", "validate", "resolve", "send"]
    assert receipt.response.body == b'{"status":"completed","output":[]}'
    assert SECRET not in repr(receipt)
    with pytest.raises(GatewayDispatchReplayError):
        dispatch(dispatcher, grant, body)
    assert events.count("resolve") == events.count("send") == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_profile_id", "other-auth"),
        ("credential_reference_id", "other-credential"),
        ("endpoint_policy_digest", "d" * 64),
        ("worker_evidence_digest", "d" * 64),
        ("max_output_tokens", 9),
        ("max_response_bytes", 512),
        ("max_elapsed_ms", 999),
        ("account_or_project", "other-project"),
        ("region", "other-region"),
        ("model", "other-model"),
        ("request_target", "https://api.openai.com/other"),
    ],
)
def test_signed_binding_drift_fails_before_credential_or_consume(tmp_path, monkeypatch, field, value):
    dispatcher, grant, body, key, events, _, options = setup_dispatch(tmp_path, monkeypatch)
    changed = sign_gateway_dispatch(replace(grant, **{field: value}, signature=""), key)
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, changed, body)
    assert events == []
    # The authorized original can still consume its one-use identifier.
    assert dispatch(dispatcher, grant, body).decision == "accepted"
    assert options["handler"].production_only


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_profile_id", "other-auth"),
        ("credential_reference_id", "other-ref"),
        ("worker_evidence_digest", "d" * 64),
        ("max_elapsed_ms", 999),
    ],
)
def test_new_fields_are_cryptographically_bound(tmp_path, monkeypatch, field, value):
    dispatcher, grant, body, _, events, _, _ = setup_dispatch(tmp_path, monkeypatch)
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, replace(grant, **{field: value}), body)
    assert events == []
    dispatch(dispatcher, grant, body)


@pytest.mark.parametrize("failure", ["expiry", "worker", "origin"])
def test_transport_authorization_fails_before_resolution(tmp_path, monkeypatch, failure):
    dispatcher, grant, body, _, events, _, options = setup_dispatch(tmp_path, monkeypatch)
    arguments = dict(
        grant=grant, body=body, presented_worker_spiffe_id=grant.worker_spiffe_id, request_target=grant.request_target
    )
    if failure == "expiry":
        arguments["current_time_iso"] = (datetime.now(UTC) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    elif failure == "worker":
        arguments["presented_worker_spiffe_id"] = "spiffe://worker.test/other"
    else:
        dispatcher = GatewayProductionDispatcher(**{**options, "endpoint_origin": "https://other.test"})
    with pytest.raises(GatewayDispatchError):
        dispatcher.dispatch(**arguments)
    assert events == []


def test_production_rejects_caller_clock_and_expired_grant(tmp_path, monkeypatch):
    dispatcher, grant, body, key, events, _, _ = setup_dispatch(tmp_path, monkeypatch)
    issued = datetime.now(UTC) - timedelta(hours=2)
    expired = sign_gateway_dispatch(
        replace(
            grant,
            issued_at=issued.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            expires_at=(issued + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            signature="",
        ),
        key,
    )
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, expired, body)
    with pytest.raises(GatewayDispatchError):
        dispatcher.dispatch(
            grant=expired,
            body=body,
            presented_worker_spiffe_id=expired.worker_spiffe_id,
            request_target=expired.request_target,
            current_time_iso=expired.issued_at,
        )
    assert events == []


@pytest.mark.parametrize("mutation", ["tools", "stream", "store", "model", "tokens", "duplicate", "nan", "empty"])
def test_no_tool_json_grammar_fails_before_consumption(tmp_path, monkeypatch, mutation):
    dispatcher, grant, body, key, events, _, _ = setup_dispatch(tmp_path, monkeypatch)
    request = json.loads(body)
    if mutation == "duplicate":
        bad_body = body[:-1] + b',"input":"duplicate"}'
    elif mutation == "nan":
        bad_body = body.replace(b"10", b"NaN")
    else:
        field, value = {
            "tools": ("tools", []),
            "stream": ("stream", True),
            "store": ("store", True),
            "model": ("model", "other"),
            "tokens": ("max_output_tokens", True),
            "empty": ("input", " "),
        }[mutation]
        request[field] = value
        bad_body = json.dumps(request).encode()
    changed = sign_gateway_dispatch(
        replace(grant, body_sha256=hashlib.sha256(bad_body).hexdigest(), body_bytes=len(bad_body), signature=""), key
    )
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, changed, bad_body)
    assert events == []
    dispatch(dispatcher, grant, body)


def test_failed_send_consumes_without_retry_and_redacts_error(tmp_path, monkeypatch):
    dispatcher, grant, body, _, events, transport, _ = setup_dispatch(tmp_path, monkeypatch)
    transport.failure = True
    with pytest.raises(GatewayDispatchError) as raised:
        dispatch(dispatcher, grant, body)
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    assert SECRET not in str(raised.value)
    with pytest.raises(GatewayDispatchReplayError):
        dispatch(dispatcher, grant, body)
    assert events.count("send") == events.count("resolve") == 1


@pytest.mark.parametrize(
    "attribute,value", [("production_only", False), ("transport_version", "other/v1"), ("validate_endpoint", None)]
)
def test_unregistered_transport_contract_fails_before_resolution(tmp_path, monkeypatch, attribute, value):
    dispatcher, grant, body, _, events, transport, _ = setup_dispatch(tmp_path, monkeypatch)
    monkeypatch.setattr(transport, attribute, value)
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, grant, body)
    assert events == []


def test_endpoint_validation_fails_before_consume_and_redacts(tmp_path, monkeypatch):
    dispatcher, grant, body, _, events, transport, _ = setup_dispatch(tmp_path, monkeypatch)

    def invalid(endpoint):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(transport, "validate_endpoint", invalid)
    with pytest.raises(GatewayDispatchError) as raised:
        dispatch(dispatcher, grant, body)
    assert events == [] and SECRET not in str(raised.value) and raised.value.__context__ is None


@pytest.mark.parametrize("credential", [SECRET, SECRET.encode(), None, VertexCredential(SECRET)])
def test_production_denies_untyped_or_wrong_provider_credential(tmp_path, monkeypatch, credential):
    dispatcher, grant, body, _, events, _, options = setup_dispatch(tmp_path, monkeypatch)
    options["handler"]._credential_resolver = lambda reference: credential
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, grant, body)
    assert "send" not in events
    with pytest.raises(GatewayDispatchReplayError):
        dispatch(dispatcher, grant, body)


def test_production_handler_cannot_be_installed_in_emulator(tmp_path, monkeypatch):
    _, _, _, _, _, transport, options = setup_dispatch(tmp_path, monkeypatch)
    with pytest.raises(GatewayDispatchError):
        GatewayDispatchEmulator(**options)
    with pytest.raises(GatewayDispatchError):
        GatewayScopedProviderHandler(
            bindings=options["handler"]._bindings,
            credential_resolver=lambda ref: SECRET,
            transports={"openai": transport},
        )
    with pytest.raises(GatewayDispatchError):
        GatewayProductionDispatcher(**{**options, "handler": lambda invocation: None})


def test_v3_envelope_roundtrip_and_v2_rejection(tmp_path, monkeypatch):
    dispatcher, grant, body, key, events, _, _ = setup_dispatch(tmp_path, monkeypatch)
    envelope = encode_gateway_dispatch_envelope(grant=grant, body=body)
    assert decode_gateway_dispatch_envelope(envelope) == (grant, body)
    assert json.loads(envelope)["schema_version"] == "cops.operator-gateway-envelope/v3"
    legacy = replace(
        grant,
        schema_version=GATEWAY_DISPATCH_SCHEMA,
        signature="",
        **{name: None for name in GatewayDispatchGrant._PRODUCTION_FIELDS},
    )
    legacy = sign_gateway_dispatch(legacy, key)
    with pytest.raises(GatewayDispatchError):
        dispatch(dispatcher, legacy, body)
    assert events == []
    assert dispatcher.dispatch_envelope(envelope=envelope, presented_worker_spiffe_id=grant.worker_spiffe_id).response


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_output_tokens", True),
        ("max_response_bytes", 1048577),
        ("max_elapsed_ms", 30001),
        ("auth_profile_id", "bad/ref"),
        ("credential_reference_id", "bad/ref"),
        ("transport_version", "wrong/v1"),
    ],
)
def test_production_configuration_bounds(tmp_path, monkeypatch, field, value):
    _, _, _, _, _, _, options = setup_dispatch(tmp_path, monkeypatch)
    endpoint = options["handler"]._bindings["endpoint-1"].endpoint
    with pytest.raises(GatewayDispatchError):
        replace(endpoint, **{field: value})
