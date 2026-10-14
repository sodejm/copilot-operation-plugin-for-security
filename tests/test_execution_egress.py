"""Adversarial tests for execution-time HTTPS egress mediation."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cops.execution.egress import (
    BROKER_PROTOCOL,
    GATEWAY_POST_BROKER_PROTOCOL,
    AuthenticatedResourceScopeError,
    AuthenticatedServiceAllowlist,
    AuthenticatedServiceIdentity,
    CertificateURIIdentityVerifier,
    DirectTLSConnector,
    EgressMediationError,
    EgressProtocolError,
    ExecutionEgressBroker,
    GatewayBrokerConfig,
    GatewayPostEgressPolicy,
    HTTPSExecutionMediator,
    ResolvedEndpoint,
    ServiceIdentityVerifier,
    _MetadataBoundedReader,
)
from cops.execution.gateway_credentials import GatewayCredentialBinding, GatewayScopedProviderHandler
from cops.execution.gateway_dispatch import (
    GATEWAY_DISPATCH_ALGORITHM,
    GATEWAY_DISPATCH_SCHEMA,
    GatewayDispatchEmulator,
    GatewayDispatchEndpoint,
    GatewayDispatchError,
    GatewayDispatchGrant,
    GatewayDispatchReplayError,
    GatewayDispatchReplayStore,
    GatewayDispatchResponse,
    GatewayDispatchStoreError,
    GatewayDispatchTransportAuthorizer,
    GatewayDispatchTrustStore,
    GatewayDispatchValidationError,
    decode_gateway_dispatch_envelope,
    sign_gateway_dispatch,
)
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard, ScopeViolationError

IDENTITY = AuthenticatedServiceIdentity(
    provider="aws",
    service="eks",
    account="account-a",
    tenant="tenant-a",
    cluster="cluster-a",
    namespace="namespace-a",
    resource="resource-a",
)
TRUST_DOMAIN = "identity.example.test"
DEFAULT_REQUEST_TARGETS = frozenset(
    {
        "/",
        "/again",
        "/private/path?token=do-not-record",
        "/private?token=secret",
        "/secret?value=hidden",
        "/start?token=hidden",
        "/status",
        "/v1/status",
        "/v2/dispatch",
    }
)


def _identity_uri(identity: AuthenticatedServiceIdentity = IDENTITY) -> str:
    parts: list[str] = []
    for name, value in identity.as_dict().items():
        parts.extend((name, value))
    return f"spiffe://{TRUST_DOMAIN}/cops/v1/{'/'.join(parts)}"


def _dispatch_grant(
    *,
    dispatch_id: str = "dispatch-1",
    authorization_id: str = "approval-1",
    provider: str = "openai",
    request_target: str = "https://api.openai.com/v1/responses",
) -> tuple[GatewayDispatchGrant, GatewayDispatchTrustStore, bytes]:
    body = b'{"model":"approved"}'
    now = datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    grant = GatewayDispatchGrant(
        schema_version=GATEWAY_DISPATCH_SCHEMA,
        dispatch_id=dispatch_id,
        authorization_id=authorization_id,
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id="spiffe://identity.example.test/worker/approved",
        provider=provider,
        account_or_project_kind="project",
        account_or_project="project-1",
        region="us-east-1",
        model="model-1",
        gateway_endpoint_id="endpoint-1",
        request_target=request_target,
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        expires_at=(now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        key_id="test-key",
        algorithm=GATEWAY_DISPATCH_ALGORITHM,
    )
    trust = GatewayDispatchTrustStore(
        {
            "test-key": key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        }
    )
    return sign_gateway_dispatch(grant, key), trust, body


def _dispatch_endpoint(
    *,
    provider: str = "openai",
    request_target: str = "https://api.openai.com/v1/responses",
) -> GatewayDispatchEndpoint:
    return GatewayDispatchEndpoint(
        gateway_endpoint_id="endpoint-1",
        gateway_identity=_identity_uri(),
        provider=provider,
        account_or_project_kind="project",
        account_or_project="project-1",
        region="us-east-1",
        model="model-1",
        request_target=request_target,
    )


def _dispatch_authorizer(trust: GatewayDispatchTrustStore) -> GatewayDispatchTransportAuthorizer:
    endpoint = _dispatch_endpoint()
    return GatewayDispatchTransportAuthorizer(trust_store=trust, endpoints={"endpoint-1": endpoint})


@pytest.mark.parametrize(
    "target",
    [
        "https://API.openai.com/v1/responses",
        "https://api.openai.com:443/v1/responses",
        "https://api.openai.com:invalid/v1/responses",
        "https://api.openai.com\\@attacker.example/v1/responses",
    ],
)
def test_gateway_dispatch_rejects_noncanonical_provider_target(target: str) -> None:
    grant, _, _ = _dispatch_grant()
    with pytest.raises(GatewayDispatchValidationError):
        replace(grant, request_target=target, signature="").validate(require_signature=False)


@pytest.mark.parametrize(
    "identity",
    [
        "spiffe://IDENTITY.example.test/worker/approved",
        "spiffe://identity.example.test:443/worker/approved",
        "spiffe://user@identity.example.test/worker/approved",
        "spiffe://[identity.example.test/worker/approved",
        "spiffe://identity.example.test/",
    ],
)
def test_gateway_dispatch_rejects_noncanonical_worker_identity(identity: str) -> None:
    grant, _, _ = _dispatch_grant()
    with pytest.raises(GatewayDispatchValidationError):
        replace(grant, worker_spiffe_id=identity, signature="").validate(require_signature=False)


def test_gateway_dispatch_rejects_malformed_endpoint_mapping() -> None:
    _, trust, _ = _dispatch_grant()
    with pytest.raises(GatewayDispatchValidationError):
        GatewayDispatchTransportAuthorizer(trust_store=trust, endpoints={"endpoint-1": object()})  # type: ignore[arg-type]


def _certificate(*uris: str) -> dict[str, object]:
    return {
        "subjectAltName": (
            ("DNS", "api.example.test"),
            *(("URI", uri) for uri in uris),
        )
    }


def _endpoint(ip: str) -> ResolvedEndpoint:
    parsed = ipaddress.ip_address(ip)
    if parsed.version == 6:
        canonical = str(parsed.ipv4_mapped) if parsed.ipv4_mapped else str(parsed)
        return ResolvedEndpoint(socket.AF_INET6, socket.SOCK_STREAM, 0, (ip, 443, 0, 0), canonical)
    return ResolvedEndpoint(socket.AF_INET, socket.SOCK_STREAM, 0, (ip, 443), ip)


class ScriptedResolver:
    def __init__(self, scripts: Mapping[str, list[object]], *, delay_seconds: float = 0.0) -> None:
        self._scripts = {hostname: list(script) for hostname, script in scripts.items()}
        self._delay_seconds = delay_seconds
        self.calls: list[str] = []

    def __call__(self, hostname: str, port: int) -> tuple[ResolvedEndpoint, ...]:
        del port
        time.sleep(self._delay_seconds)
        self.calls.append(hostname)
        script = self._scripts.get(hostname)
        if not script:
            raise RuntimeError("unscripted resolver call")
        result = script.pop(0)
        if isinstance(result, Exception):
            raise result
        assert isinstance(result, tuple)
        return result


class FakeConnection:
    def __init__(
        self,
        *,
        peer_ip: str = "192.0.2.10",
        certificate: Mapping[str, object] | None = None,
        response: tuple[object, object, object] = (200, (("Content-Type", "application/json"),), b"{}"),
        request_error: Exception | None = None,
        request_delay_seconds: float = 0.0,
        close_delay_seconds: float = 0.0,
        request_events: list[str] | None = None,
    ) -> None:
        self.peer_ip = peer_ip
        self.peer_certificate_der = b"authenticated-peer"
        self.peer_certificate = certificate or _certificate(_identity_uri())
        self.response = response
        self.request_error = request_error
        self.request_delay_seconds = request_delay_seconds
        self.close_delay_seconds = close_delay_seconds
        self.request_events = request_events
        self.requests: list[tuple[str, str, dict[str, str], int]] = []
        self.request_bodies: list[bytes] = []
        self.closed = False

    def request(
        self,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes = b"",
        max_response_bytes: int,
        max_response_header_bytes: int,
        timeout_seconds: float,
    ) -> tuple[object, object, object]:
        del max_response_header_bytes, timeout_seconds
        self.requests.append((method, target, dict(headers), max_response_bytes))
        self.request_bodies.append(body)
        if self.request_events is not None:
            self.request_events.append("request")
        time.sleep(self.request_delay_seconds)
        if self.request_error is not None:
            raise self.request_error
        return self.response

    def close(self) -> None:
        time.sleep(self.close_delay_seconds)
        self.closed = True


class FakeConnector:
    def __init__(self, *connections: object, delay_seconds: float = 0.0) -> None:
        self.connections = list(connections)
        self.delay_seconds = delay_seconds
        self.opened: list[tuple[ResolvedEndpoint, str, int]] = []

    def open(
        self,
        endpoint: ResolvedEndpoint,
        *,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> FakeConnection:
        del timeout_seconds
        time.sleep(self.delay_seconds)
        self.opened.append((endpoint, hostname, port))
        if not self.connections:
            raise RuntimeError("unscripted connector call")
        connection = self.connections.pop(0)
        if isinstance(connection, Exception):
            raise connection
        assert isinstance(connection, FakeConnection)
        return connection


class HangingIdentityVerifier:
    def verify(
        self,
        *,
        hostname: str,
        peer_certificate_der: bytes,
        peer_certificate: Mapping[str, object],
    ) -> AuthenticatedServiceIdentity:
        del hostname, peer_certificate_der, peer_certificate
        time.sleep(60)
        return IDENTITY


class RecordingMetadataStream:
    def __init__(self) -> None:
        self.readline_limits: list[int] = []

    def readline(self, limit: int = -1) -> bytes:
        self.readline_limits.append(limit)
        return b"x" * limit


def _scope(*domains: str) -> ScopeGuard:
    return ScopeGuard(
        ScopeDefinition(
            included_networks=[
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("2001:db8::/32"),
            ],
            included_domains=set(domains or ("api.example.test",)),
            egress_allowed=True,
        )
    )


def _mediator(
    resolver: ScriptedResolver,
    connector: FakeConnector,
    *,
    domains: tuple[str, ...] = ("api.example.test",),
    max_redirects: int = 3,
    request_targets: frozenset[str] = DEFAULT_REQUEST_TARGETS,
    timeout_seconds: float = 15.0,
    max_response_bytes: int = 1_048_576,
    max_response_header_bytes: int = 65_536,
    identity_verifier: ServiceIdentityVerifier | None = None,
    approved_origin: tuple[str, int] | None = None,
) -> HTTPSExecutionMediator:
    return HTTPSExecutionMediator(
        scope_guard=_scope(*domains),
        identity_verifier=identity_verifier or CertificateURIIdentityVerifier(trust_domain=TRUST_DOMAIN),
        identity_allowlist=AuthenticatedServiceAllowlist({IDENTITY: request_targets}),
        approved_origin=approved_origin,
        resolver=resolver,
        connector=connector,
        max_redirects=max_redirects,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        max_response_header_bytes=max_response_header_bytes,
    )


def _gateway_policy(
    body: bytes,
    *,
    gateway_url: str = "https://api.example.test/v2/dispatch",
    request_target: str = "/v2/dispatch",
    expected_identity: AuthenticatedServiceIdentity = IDENTITY,
    expected_spiffe_id: str | None = None,
    body_sha256: str | None = None,
    body_bytes: int | None = None,
    max_body_bytes: int = 4_096,
) -> GatewayPostEgressPolicy:
    return GatewayPostEgressPolicy(
        protocol=GATEWAY_POST_BROKER_PROTOCOL,
        gateway_url=gateway_url,
        request_target=request_target,
        expected_identity=expected_identity,
        expected_spiffe_id=expected_spiffe_id or _identity_uri(expected_identity),
        body_sha256=hashlib.sha256(body).hexdigest() if body_sha256 is None else body_sha256,
        body_bytes=len(body) if body_bytes is None else body_bytes,
        max_body_bytes=max_body_bytes,
    )


def test_gateway_post_preflights_then_calls_one_use_callback_immediately_before_send() -> None:
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    events: list[str] = []
    connection = FakeConnection(request_events=events)
    mediator = _mediator(
        resolver,
        FakeConnector(connection),
        request_targets=frozenset({"/v2/dispatch"}),
        approved_origin=("api.example.test", 443),
    )
    body = b'{"dispatch":"opaque"}'

    response = mediator.post_gateway(
        policy=_gateway_policy(body),
        body=body,
        headers={"Content-Type": "application/json"},
        before_send=lambda: events.append("callback"),
    )

    assert response.status == 200
    assert resolver.calls == ["api.example.test", "api.example.test"]
    assert events == ["callback", "request"]
    assert connection.requests == [
        (
            "POST",
            "/v2/dispatch",
            {
                "Host": "api.example.test",
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
            },
            1_048_576,
        )
    ]
    assert connection.request_bodies == [body]
    assert "opaque" not in repr(mediator.observations)


def test_gateway_post_rejects_wrong_body_digest_before_callback_or_connection() -> None:
    resolver = ScriptedResolver({})
    connection = FakeConnection()
    mediator = _mediator(
        resolver,
        FakeConnector(connection),
        request_targets=frozenset({"/v2/dispatch"}),
        approved_origin=("api.example.test", 443),
    )
    body = b"dispatch"

    with pytest.raises(EgressProtocolError, match="body digest"):
        mediator.post_gateway(
            policy=_gateway_policy(body, body_sha256="0" * 64),
            body=body,
            before_send=lambda: pytest.fail("callback must not be called"),
        )

    assert resolver.calls == []
    assert connection.requests == []
    assert mediator.observations[-1].decision == "blocked"


def test_gateway_post_rejects_wrong_authenticated_gateway_identity_before_callback() -> None:
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    actual_identity = replace(IDENTITY, resource="resource-b")
    connection = FakeConnection(certificate=_certificate(_identity_uri(actual_identity)))
    mediator = _mediator(
        resolver,
        FakeConnector(connection),
        request_targets=frozenset({"/v2/dispatch"}),
        approved_origin=("api.example.test", 443),
    )
    body = b"dispatch"

    with pytest.raises(AuthenticatedResourceScopeError, match="configured gateway"):
        mediator.post_gateway(
            policy=_gateway_policy(body),
            body=body,
            before_send=lambda: pytest.fail("callback must not be called"),
        )

    assert connection.requests == []
    assert mediator.observations[-1].decision == "blocked"


def test_gateway_post_refuses_redirect_without_retrying_or_following_location() -> None:
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    events: list[str] = []
    connection = FakeConnection(response=(302, (("Location", "/again"),), b""), request_events=events)
    mediator = _mediator(
        resolver,
        FakeConnector(connection),
        request_targets=frozenset({"/v2/dispatch"}),
        approved_origin=("api.example.test", 443),
    )
    body = b"dispatch"

    with pytest.raises(EgressMediationError, match="terminal response"):
        mediator.post_gateway(
            policy=_gateway_policy(body),
            body=body,
            before_send=lambda: events.append("callback"),
        )

    assert events == ["callback", "request"]
    assert len(connection.requests) == 1
    assert connection.request_bodies == [body]
    assert mediator.observations[-1].decision == "blocked"


def test_gateway_post_callback_failure_leaves_request_unsent() -> None:
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    connection = FakeConnection()
    mediator = _mediator(
        resolver,
        FakeConnector(connection),
        request_targets=frozenset({"/v2/dispatch"}),
        approved_origin=("api.example.test", 443),
    )
    body = b"dispatch"

    with pytest.raises(EgressMediationError, match="authorization callback"):
        mediator.post_gateway(
            policy=_gateway_policy(body),
            body=body,
            before_send=lambda: (_ for _ in ()).throw(RuntimeError("grant rejected")),
        )

    assert connection.requests == []
    assert mediator.observations[-1].decision == "blocked"


@pytest.mark.parametrize(
    "url",
    (
        "https://peer.example.test/v1/status",
        "https://api.example.test:8443/v1/status",
    ),
    ids=("different-host", "different-port"),
)
def test_mediator_rejects_scope_allowed_origin_outside_exact_operation(url: str) -> None:
    resolver = ScriptedResolver({})
    mediator = _mediator(
        resolver,
        FakeConnector(FakeConnection()),
        domains=("api.example.test", "peer.example.test"),
        approved_origin=("api.example.test", 443),
    )

    with pytest.raises(EgressProtocolError, match="approved operation"):
        mediator.request(method="GET", url=url)

    assert resolver.calls == []
    assert mediator.observations[-1].decision == "blocked"


def _request_document(url: str = "https://api.example.test/v1/status") -> dict[str, object]:
    return {"version": BROKER_PROTOCOL, "method": "GET", "url": url, "headers": {}}


def test_mediator_dispatches_only_after_destination_and_exact_identity_checks() -> None:
    endpoints = (_endpoint("192.0.2.10"), _endpoint("2001:db8::10"))
    resolver = ScriptedResolver({"api.example.test": [endpoints, endpoints]})
    connection = FakeConnection()
    mediator = _mediator(resolver, FakeConnector(connection))

    response = mediator.request(
        method="GET",
        url="https://api.example.test/private/path?token=do-not-record",
        headers={"Authorization": "Bearer not-persisted", "X-Request-ID": "request-1"},
    )

    assert response.status == 200
    assert response.identity == IDENTITY
    assert resolver.calls == ["api.example.test", "api.example.test"]
    assert connection.requests == [
        (
            "GET",
            "/private/path?token=do-not-record",
            {
                "Host": "api.example.test",
                "Authorization": "Bearer not-persisted",
                "X-Request-ID": "request-1",
            },
            1_048_576,
        )
    ]
    assert connection.closed
    assert mediator.observations[0].origin == "https://api.example.test"
    assert "token" not in repr(mediator.observations)
    assert "Bearer" not in repr(mediator.observations)


@pytest.mark.parametrize(
    ("first", "second", "peer_ip", "error_type"),
    [
        (("192.0.2.10",), ("192.0.2.11",), "192.0.2.10", EgressMediationError),
        (("192.0.2.10",), ("192.0.2.10",), "192.0.2.11", EgressMediationError),
        (("192.0.2.10", "169.254.169.254"), (), "192.0.2.10", ScopeViolationError),
        (("192.0.2.10", "fd00:ec2::254"), (), "192.0.2.10", ScopeViolationError),
        (("192.0.2.10", "2001:db9::10"), (), "192.0.2.10", ScopeViolationError),
    ],
    ids=("dns-rebinding", "peer-pivot", "ipv4-metadata", "ipv6-metadata", "mixed-family-out-of-scope"),
)
def test_mediator_fails_closed_for_dns_peer_and_address_set_ambiguity(
    first: tuple[str, ...],
    second: tuple[str, ...],
    peer_ip: str,
    error_type: type[Exception],
) -> None:
    scripts: list[object] = [tuple(_endpoint(ip) for ip in first)]
    if second:
        scripts.append(tuple(_endpoint(ip) for ip in second))
    resolver = ScriptedResolver({"api.example.test": scripts})
    connection = FakeConnection(peer_ip=peer_ip)
    mediator = _mediator(resolver, FakeConnector(connection))

    with pytest.raises(error_type):
        mediator.request(method="GET", url="https://api.example.test/secret?value=hidden")

    assert mediator.observations[-1].decision == "blocked"
    assert mediator.observations[-1].origin == "https://api.example.test"
    assert "secret" not in repr(mediator.observations)


def test_network_inclusion_never_substitutes_for_hostname_allowlist() -> None:
    endpoints = (_endpoint("192.0.2.10"),)
    resolver = ScriptedResolver({"unlisted.example.test": [endpoints]})
    mediator = _mediator(resolver, FakeConnector(FakeConnection()))

    with pytest.raises(ScopeViolationError, match="included domain"):
        mediator.request(method="GET", url="https://unlisted.example.test/")

    assert mediator.observations[-1].decision == "blocked"


@pytest.mark.parametrize(
    ("url", "host", "endpoint_ip"),
    [
        ("https://192.0.2.10/status", "192.0.2.10", "192.0.2.10"),
        ("https://[::ffff:192.0.2.10]/status", "::ffff:192.0.2.10", "::ffff:192.0.2.10"),
    ],
    ids=("ipv4", "ipv4-mapped-ipv6"),
)
def test_explicit_ip_literals_use_canonical_ip_scope_and_tls_identity(
    url: str,
    host: str,
    endpoint_ip: str,
) -> None:
    endpoints = (_endpoint(endpoint_ip),)
    resolver = ScriptedResolver({host: [endpoints, endpoints]})
    connection = FakeConnection(peer_ip="192.0.2.10")
    mediator = _mediator(resolver, FakeConnector(connection))

    response = mediator.request(method="GET", url=url)

    assert response.status == 200
    assert connection.requests[0][2]["Host"] in {"192.0.2.10", "[::ffff:192.0.2.10]"}
    assert mediator.observations[-1].decision == "allowed"


@pytest.mark.parametrize(
    ("url", "host", "metadata_ip"),
    [
        ("https://169.254.169.254/", "169.254.169.254", "169.254.169.254"),
        ("https://[::ffff:169.254.169.254]/", "::ffff:169.254.169.254", "::ffff:169.254.169.254"),
    ],
    ids=("ipv4", "ipv4-mapped-ipv6"),
)
def test_execution_mediator_always_blocks_metadata_even_if_scope_flag_is_disabled(
    url: str,
    host: str,
    metadata_ip: str,
) -> None:
    endpoints = (_endpoint(metadata_ip),)
    permissive_guard = ScopeGuard(
        ScopeDefinition(
            included_networks=[ipaddress.ip_network("169.254.0.0/16")],
            block_cloud_metadata=False,
            egress_allowed=True,
        )
    )
    mediator = HTTPSExecutionMediator(
        scope_guard=permissive_guard,
        identity_verifier=CertificateURIIdentityVerifier(trust_domain=TRUST_DOMAIN),
        identity_allowlist=AuthenticatedServiceAllowlist({IDENTITY: frozenset({"/"})}),
        resolver=ScriptedResolver({host: [endpoints]}),
        connector=FakeConnector(FakeConnection(peer_ip="169.254.169.254")),
    )

    with pytest.raises(ScopeViolationError, match="metadata"):
        mediator.request(method="GET", url=url)

    assert mediator.observations[-1].decision == "blocked"


@pytest.mark.parametrize(
    ("response_headers", "max_redirects", "headers", "expected_origin"),
    [
        ((), 3, {}, "https://api.example.test"),
        ((("Location", "/one"), ("Location", "/two")), 3, {}, "https://api.example.test"),
        ((("Location", "/again"),), 0, {}, "https://api.example.test"),
        (
            (("Location", "https://redirect.example.test/next?credential=hidden"),),
            3,
            {"Authorization": "Bearer hidden"},
            "https://redirect.example.test",
        ),
    ],
    ids=("missing-location", "multiple-location", "redirect-limit", "cross-origin-authorization"),
)
def test_redirect_policy_failures_always_record_redacted_blocked_observations(
    response_headers: tuple[tuple[str, str], ...],
    max_redirects: int,
    headers: dict[str, str],
    expected_origin: str,
) -> None:
    endpoints = (_endpoint("192.0.2.10"),)
    resolver = ScriptedResolver({"api.example.test": [endpoints, endpoints]})
    connection = FakeConnection(response=(302, response_headers, b""))
    mediator = _mediator(
        resolver,
        FakeConnector(connection),
        domains=("api.example.test", "redirect.example.test"),
        max_redirects=max_redirects,
    )

    with pytest.raises(EgressProtocolError):
        mediator.request(
            method="GET",
            url="https://api.example.test/start?token=hidden",
            headers=headers,
        )

    observation = mediator.observations[-1]
    assert observation.decision == "blocked"
    assert observation.origin == expected_origin
    assert "hidden" not in repr(mediator.observations)


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Length": "0"},
        {"Expect": "100-continue"},
        {"Proxy-Authorization": "secret"},
        {"Transfer-Encoding": "chunked"},
        {"Bad Header": "value"},
        {"X-Test": "line\r\nbreak"},
        {"X-Test": "non-ascii-\N{SNOWMAN}"},
        {"Authorization": "one", "authorization": "two"},
    ],
    ids=("content-length", "expect", "proxy", "transfer", "bad-name", "control", "non-ascii", "duplicate"),
)
def test_request_headers_cannot_change_framing_proxy_or_encoding(headers: dict[str, str]) -> None:
    mediator = _mediator(ScriptedResolver({}), FakeConnector())

    with pytest.raises(EgressProtocolError):
        mediator.request(method="GET", url="https://api.example.test/", headers=headers)

    assert mediator.observations[-1].decision == "blocked"


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("CONNECT", "https://api.example.test/"),
        ("POST", "https://api.example.test/"),
        ("GET", "http://api.example.test/"),
        ("GET", "https://user:pass@api.example.test/"),
        ("GET", "https://api.example.test/path#fragment"),
        ("GET", "https://api.example.test/path with space"),
        ("GET", "https://api.example.test/path\\pivot"),
        ("GET", "https://api.example.test/path\nheader"),
        ("GET", "https://api.example.test/snowman-\N{SNOWMAN}"),
    ],
)
def test_only_safe_ascii_https_get_and_head_requests_are_accepted(method: str, url: str) -> None:
    mediator = _mediator(ScriptedResolver({}), FakeConnector())

    with pytest.raises(EgressProtocolError):
        mediator.request(method=method, url=url)

    assert mediator.observations[-1].decision == "blocked"


@pytest.mark.parametrize(
    "dimension",
    ("provider", "service", "account", "tenant", "cluster", "namespace", "resource"),
)
def test_every_authenticated_resource_dimension_is_exactly_allowlisted(dimension: str) -> None:
    endpoints = (_endpoint("192.0.2.10"),)
    resolver = ScriptedResolver({"api.example.test": [endpoints, endpoints]})
    actual = replace(IDENTITY, **{dimension: f"other-{dimension}"})
    connection = FakeConnection(certificate=_certificate(_identity_uri(actual)))
    mediator = _mediator(resolver, FakeConnector(connection))

    with pytest.raises(AuthenticatedResourceScopeError, match="exact allowlist"):
        mediator.request(method="GET", url="https://api.example.test/")

    assert connection.requests == []
    assert mediator.observations[-1].decision == "blocked"


@pytest.mark.parametrize(
    "certificate",
    [
        _certificate(),
        _certificate(_identity_uri(), _identity_uri()),
        _certificate(f"spiffe://{TRUST_DOMAIN}/cops/v1/provider/aws/service/eks"),
        _certificate(
            f"spiffe://{TRUST_DOMAIN}/cops/v1/provider/aws/service/eks/account/%FF/tenant/tenant-a/"
            "cluster/cluster-a/namespace/namespace-a/resource/resource-a"
        ),
    ],
    ids=("missing", "duplicate", "malformed", "invalid-utf8"),
)
def test_hostname_certificate_without_one_canonical_resource_binding_is_denied(
    certificate: Mapping[str, object],
) -> None:
    endpoints = (_endpoint("192.0.2.10"),)
    resolver = ScriptedResolver({"api.example.test": [endpoints, endpoints]})
    mediator = _mediator(resolver, FakeConnector(FakeConnection(certificate=certificate)))

    with pytest.raises(AuthenticatedResourceScopeError):
        mediator.request(method="GET", url="https://api.example.test/")

    assert mediator.observations[-1].decision == "blocked"


def test_direct_connector_rejects_insecure_injected_tls_contexts() -> None:
    insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE

    with pytest.raises(ValueError, match="certificate and hostname"):
        DirectTLSConnector(tls_context=insecure)


def test_response_metadata_reader_bounds_the_underlying_allocation() -> None:
    stream = RecordingMetadataStream()
    reader = _MetadataBoundedReader(stream, max_metadata_bytes=8)

    with pytest.raises(EgressMediationError, match="metadata exceeded"):
        reader.readline()

    assert stream.readline_limits == [9]


@pytest.mark.parametrize("failure_point", ("resolver", "connector", "request", "response"))
def test_runtime_failures_are_blocked_without_persisting_url_details(failure_point: str) -> None:
    endpoints = (_endpoint("192.0.2.10"),)
    resolver_results: list[object] = [endpoints, endpoints]
    connections: list[object] = [FakeConnection()]
    if failure_point == "resolver":
        resolver_results = [RuntimeError("resolver saw /private?token=secret")]
    elif failure_point == "connector":
        connections = [RuntimeError("connector saw /private?token=secret")]
    elif failure_point == "request":
        connections = [FakeConnection(request_error=UnicodeEncodeError("ascii", "\N{SNOWMAN}", 0, 1, "bad"))]
    elif failure_point == "response":
        connections = [FakeConnection(response=(200, (("Bad Header", "value"),), b""))]
    mediator = _mediator(
        ScriptedResolver({"api.example.test": resolver_results}),
        FakeConnector(*connections),
    )

    with pytest.raises(EgressMediationError):
        mediator.request(method="GET", url="https://api.example.test/private?token=secret")

    assert mediator.observations[-1].origin == "https://api.example.test"
    assert "private" not in repr(mediator.observations)
    assert "secret" not in repr(mediator.observations)


_BROKER_CHILD = r"""
import os
import socket
import sys

client = socket.socket(fileno=int(os.environ["COPS_EGRESS_BROKER_FD"]))
client.sendall(sys.argv[1].encode("utf-8") + b"\n")
received = b""
while not received.endswith(b"\n"):
    chunk = client.recv(65536)
    if not chunk:
        break
    received += chunk
sys.stdout.buffer.write(received)
"""


@pytest.mark.parametrize("attempt", ("direct-ip", "dns-rebind", "redirect", "proxy"))
def test_subprocess_broker_requests_receive_fail_closed_denials(attempt: str) -> None:
    allowed = (_endpoint("192.0.2.10"),)
    rebound = (_endpoint("192.0.2.11"),)
    document = _request_document()
    domains = ("api.example.test",)
    scripts: dict[str, list[object]] = {"api.example.test": [allowed, allowed]}
    connections: list[object] = [FakeConnection()]
    if attempt == "direct-ip":
        document["url"] = "https://198.51.100.10/"
        denied = (_endpoint("198.51.100.10"),)
        scripts = {"198.51.100.10": [denied]}
    elif attempt == "dns-rebind":
        scripts = {"api.example.test": [allowed, rebound]}
    elif attempt == "redirect":
        connections = [FakeConnection(response=(302, (("Location", "https://pivot.example.test/"),), b""))]
    elif attempt == "proxy":
        document["headers"] = {"Proxy-Authorization": "secret"}
    mediator = _mediator(ScriptedResolver(scripts), FakeConnector(*connections), domains=domains)
    broker = ExecutionEgressBroker(mediator)

    with broker.open_channel() as channel:
        completed = subprocess.run(
            [sys.executable, "-c", _BROKER_CHILD, json.dumps(document)],
            check=True,
            capture_output=True,
            env={**os.environ, **channel.environment},
            pass_fds=channel.pass_fds,
        )

    assert json.loads(completed.stdout) == {"error": "egress_denied", "ok": False}
    assert mediator.observations[-1].decision == "blocked"


def test_v1_broker_rejects_direct_provider_post_before_resolution() -> None:
    resolver = ScriptedResolver({})
    connector = FakeConnector()
    mediator = _mediator(
        resolver,
        connector,
        domains=("api.openai.com",),
        approved_origin=("api.openai.com", 443),
    )
    broker = ExecutionEgressBroker(mediator)
    document = {
        "version": BROKER_PROTOCOL,
        "method": "POST",
        "url": "https://api.openai.com/v1/responses",
        "headers": {},
        "body": "{}",
    }

    with broker.open_channel() as channel:
        completed = subprocess.run(
            [sys.executable, "-c", _BROKER_CHILD, json.dumps(document)],
            check=True,
            capture_output=True,
            env={**os.environ, **channel.environment},
            pass_fds=channel.pass_fds,
        )

    assert json.loads(completed.stdout) == {"error": "egress_denied", "ok": False}
    assert resolver.calls == []
    assert connector.opened == []


def _gateway_broker(
    *,
    tmp_path: object,
    trust: GatewayDispatchTrustStore,
    resolver: ScriptedResolver,
    connector: FakeConnector,
    action_plan_id: str = "plan-1",
    gateway_spiffe_id: str | None = None,
) -> ExecutionEgressBroker:
    mediator = _mediator(
        resolver,
        connector,
        request_targets=frozenset({"/v2/dispatch"}),
        approved_origin=("api.example.test", 443),
    )
    config = GatewayBrokerConfig(
        gateway_url="https://api.example.test/v2/dispatch",
        gateway_spiffe_id=gateway_spiffe_id or _identity_uri(),
        expected_identity=IDENTITY,
        action_plan_id=action_plan_id,
        plan_digest="a" * 64,
        worker_spiffe_id="spiffe://identity.example.test/worker/approved",
        max_body_bytes=4096,
        authorizer=_dispatch_authorizer(trust),
        replay_store=GatewayDispatchReplayStore(tmp_path / "broker-replay.sqlite"),
    )
    return ExecutionEgressBroker(mediator, gateway_config=config)


def _gateway_broker_document(grant: GatewayDispatchGrant, body: bytes) -> bytes:
    return json.dumps(
        {
            "version": GATEWAY_POST_BROKER_PROTOCOL,
            "grant": grant.to_dict(),
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
    ).encode("ascii")


def test_gateway_broker_binds_signed_grant_and_consumes_it_once(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,)] * 4})
    first = FakeConnection()
    second = FakeConnection()
    broker = _gateway_broker(
        tmp_path=tmp_path,
        trust=trust,
        resolver=resolver,
        connector=FakeConnector(first, second),
    )
    request = _gateway_broker_document(grant, body)

    response = broker._dispatch(request, deadline=time.monotonic() + 5)

    assert response.status == 200
    assert first.requests[0][0:2] == ("POST", "/v2/dispatch")
    sent_grant, sent_body = decode_gateway_dispatch_envelope(first.request_bodies[0])
    assert sent_grant == grant
    assert sent_grant.request_target == "https://api.openai.com/v1/responses"
    assert sent_body == body

    with pytest.raises(EgressMediationError, match="authorization callback"):
        broker._dispatch(request, deadline=time.monotonic() + 5)

    assert second.requests == []
    assert broker._mediator.observations[-1].decision == "blocked"
    assert "approved" not in repr(broker._mediator.observations)


def test_gateway_broker_rechecks_expiry_after_connection_preflight(tmp_path, monkeypatch) -> None:
    grant, trust, body = _dispatch_grant()
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    connection = FakeConnection()
    broker = _gateway_broker(
        tmp_path=tmp_path,
        trust=trust,
        resolver=resolver,
        connector=FakeConnector(connection),
    )
    clock = iter(
        (
            grant.issued_at,
            (datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")) + timedelta(seconds=1)).isoformat(),
        )
    )
    monkeypatch.setattr("cops.execution.gateway_dispatch.utc_now", lambda: next(clock))

    with pytest.raises(EgressMediationError, match="authorization callback"):
        broker._dispatch(_gateway_broker_document(grant, body), deadline=time.monotonic() + 5)

    assert connection.requests == []


def test_gateway_broker_denies_wrong_certificate_spiffe_id_before_send(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    connection = FakeConnection(certificate=_certificate(_identity_uri(), _identity_uri()))
    broker = _gateway_broker(
        tmp_path=tmp_path,
        trust=trust,
        resolver=resolver,
        connector=FakeConnector(connection),
    )

    with pytest.raises(AuthenticatedResourceScopeError):
        broker._dispatch(_gateway_broker_document(grant, body), deadline=time.monotonic() + 5)

    assert connection.requests == []


@pytest.mark.parametrize("alteration", ("scope", "identity", "body", "direct-url"))
def test_gateway_broker_rejects_unapproved_dispatch_before_network(tmp_path, alteration: str) -> None:
    grant, trust, body = _dispatch_grant()
    endpoint = _endpoint("192.0.2.10")
    resolver = ScriptedResolver({"api.example.test": [(endpoint,), (endpoint,)]})
    connection = FakeConnection()
    broker = _gateway_broker(
        tmp_path=tmp_path,
        trust=trust,
        resolver=resolver,
        connector=FakeConnector(connection),
        action_plan_id="another-plan" if alteration == "scope" else "plan-1",
        gateway_spiffe_id="spiffe://identity.example.test/other" if alteration == "identity" else None,
    )
    if alteration == "body":
        body = b'{"model":"altered"}'
    document = json.loads(_gateway_broker_document(grant, body))
    if alteration == "direct-url":
        document["url"] = "https://api.openai.com/v1/responses"

    with pytest.raises((EgressProtocolError, GatewayDispatchValidationError)):
        broker._dispatch(json.dumps(document).encode("ascii"), deadline=time.monotonic() + 5)

    assert resolver.calls == []
    assert connection.requests == []


def test_gateway_emulator_uses_independent_plan_and_worker_scope_and_replay_store(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()
    invocations: list[object] = []
    gateway = GatewayDispatchEmulator(
        authorizer=_dispatch_authorizer(trust),
        replay_store=GatewayDispatchReplayStore(tmp_path / "gateway-replay.sqlite"),
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id="spiffe://identity.example.test/worker/approved",
        handler=invocations.append,
    )

    with pytest.raises(GatewayDispatchValidationError):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id="spiffe://identity.example.test/worker/other",
            request_target=grant.request_target,
            body=body,
        )
    assert invocations == []

    receipt = gateway.dispatch(
        grant=grant,
        presented_worker_spiffe_id=grant.worker_spiffe_id,
        request_target=grant.request_target,
        body=body,
    )
    assert receipt.decision == "accepted"
    assert len(invocations) == 1
    assert "approved" not in repr(invocations)

    with pytest.raises(GatewayDispatchReplayError):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
        )
    assert len(invocations) == 1


def test_gateway_replay_store_consumes_authorization_id_once_across_dispatch_ids(tmp_path) -> None:
    first, _, _ = _dispatch_grant()
    second, _, _ = _dispatch_grant(dispatch_id="dispatch-2")
    store = GatewayDispatchReplayStore(tmp_path / "replay.sqlite")

    store.consume(first)
    with pytest.raises(GatewayDispatchReplayError):
        store.consume(second)


def test_gateway_replay_store_fails_closed_on_legacy_schema(tmp_path) -> None:
    first, _, _ = _dispatch_grant()
    database_path = tmp_path / "legacy-replay.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE consumed_dispatches (dispatch_id TEXT PRIMARY KEY, descriptor_digest TEXT NOT NULL, consumed_at TEXT NOT NULL)"
        )
    database_path.chmod(0o600)

    with pytest.raises(GatewayDispatchStoreError):
        GatewayDispatchReplayStore(database_path).consume(first)


def test_gateway_emulator_returns_bounded_response_after_consumption(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()
    store = GatewayDispatchReplayStore(tmp_path / "gateway-response-replay.sqlite")
    invocations = []

    def handler(invocation):
        invocations.append(invocation)
        with pytest.raises(GatewayDispatchReplayError):
            store.consume(grant)
        return GatewayDispatchResponse(200, "application/json", b'{"secret":"never-log"}')

    gateway = GatewayDispatchEmulator(
        authorizer=_dispatch_authorizer(trust),
        replay_store=store,
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id="spiffe://identity.example.test/worker/approved",
        handler=handler,
    )

    receipt = gateway.dispatch(
        grant=grant,
        presented_worker_spiffe_id=grant.worker_spiffe_id,
        request_target=grant.request_target,
        body=body,
    )

    assert invocations[0].body == body
    assert receipt.response is not None
    assert receipt.response.body == b'{"secret":"never-log"}'
    assert "never-log" not in repr(receipt)
    assert body.decode("ascii") not in repr(invocations[0])


def test_gateway_emulator_does_not_replay_after_oversized_response(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()

    def oversized_response(_invocation):
        return GatewayDispatchResponse(200, "application/json", b"x" * 1_048_577)

    gateway = GatewayDispatchEmulator(
        authorizer=_dispatch_authorizer(trust),
        replay_store=GatewayDispatchReplayStore(tmp_path / "gateway-oversize-replay.sqlite"),
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id="spiffe://identity.example.test/worker/approved",
        handler=oversized_response,
    )

    with pytest.raises(GatewayDispatchError, match="failed after authorization consumption"):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
        )
    with pytest.raises(GatewayDispatchReplayError):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
        )


@pytest.mark.parametrize(
    ("provider", "request_target"),
    [
        ("openai", "https://api.openai.com/v1/responses"),
        ("azure_openai", "https://approved.openai.azure.com/openai/v1/responses"),
        ("bedrock", "https://bedrock-runtime.us-east-1.amazonaws.com/model/model-1/converse"),
        (
            "vertex",
            "https://us-east1-aiplatform.googleapis.com/v1/projects/project-1/locations/us-east1/publishers/google/models/model-1:generateContent",
        ),
    ],
)
def test_gateway_credential_scope_dispatches_once_after_grant_consumption(
    tmp_path,
    provider: str,
    request_target: str,
) -> None:
    grant, trust, body = _dispatch_grant(provider=provider, request_target=request_target)
    endpoint = _dispatch_endpoint(provider=provider, request_target=request_target)
    events: list[tuple[object, ...]] = []
    secret = "provider-secret-never-in-evidence"

    def resolve(credential_ref: str) -> str:
        events.append(("resolve", credential_ref))
        return secret

    def transport(
        actual_endpoint: GatewayDispatchEndpoint, actual_body: bytes, credential: str | bytes
    ) -> GatewayDispatchResponse:
        events.append(("transport", actual_endpoint, actual_body, credential))
        return GatewayDispatchResponse(200, "application/json", b'{"usage":{"total_tokens":1}}')

    handler = GatewayScopedProviderHandler(
        bindings={endpoint.gateway_endpoint_id: GatewayCredentialBinding(endpoint, "vault://approved")},
        credential_resolver=resolve,
        transports={provider: transport},
    )
    gateway = GatewayDispatchEmulator(
        authorizer=GatewayDispatchTransportAuthorizer(
            trust_store=trust,
            endpoints={endpoint.gateway_endpoint_id: endpoint},
        ),
        replay_store=GatewayDispatchReplayStore(tmp_path / "credential-replay.sqlite"),
        action_plan_id=grant.action_plan_id,
        plan_digest=grant.plan_digest,
        worker_spiffe_id=grant.worker_spiffe_id,
        handler=handler,
    )

    receipt = gateway.dispatch(
        grant=grant,
        presented_worker_spiffe_id=grant.worker_spiffe_id,
        request_target=request_target,
        body=body,
    )
    assert receipt.decision == "accepted"
    assert events == [
        ("resolve", "vault://approved"),
        ("transport", endpoint, body, secret),
    ]
    assert secret not in repr(receipt)
    assert secret not in repr(handler)
    assert secret not in repr(GatewayCredentialBinding(endpoint, "vault://approved"))
    with pytest.raises(GatewayDispatchReplayError):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=request_target,
            body=body,
        )
    assert len(events) == 2


def test_gateway_credential_scope_mismatch_consumes_grant_without_resolving(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()
    endpoint = _dispatch_endpoint()
    resolved: list[str] = []
    handler = GatewayScopedProviderHandler(
        bindings={
            endpoint.gateway_endpoint_id: GatewayCredentialBinding(
                replace(endpoint, model="other-model"), "vault://wrong"
            )
        },
        credential_resolver=lambda ref: resolved.append(ref) or "secret",
        transports={
            "openai": lambda _endpoint, _body, _credential: GatewayDispatchResponse(200, "application/json", b"{}")
        },
    )
    gateway = GatewayDispatchEmulator(
        authorizer=GatewayDispatchTransportAuthorizer(
            trust_store=trust, endpoints={endpoint.gateway_endpoint_id: endpoint}
        ),
        replay_store=GatewayDispatchReplayStore(tmp_path / "mismatch-replay.sqlite"),
        action_plan_id=grant.action_plan_id,
        plan_digest=grant.plan_digest,
        worker_spiffe_id=grant.worker_spiffe_id,
        handler=handler,
    )

    with pytest.raises(GatewayDispatchError, match="failed after authorization consumption"):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
        )
    assert resolved == []
    with pytest.raises(GatewayDispatchReplayError):
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
        )


def test_gateway_credential_failure_has_no_secret_exception_chain(tmp_path) -> None:
    grant, trust, body = _dispatch_grant()
    endpoint = _dispatch_endpoint()
    secret = "provider-secret-never-in-traceback"

    def fail_resolve(_ref: str) -> str:
        raise RuntimeError(secret)

    handler = GatewayScopedProviderHandler(
        bindings={endpoint.gateway_endpoint_id: GatewayCredentialBinding(endpoint, "vault://approved")},
        credential_resolver=fail_resolve,
        transports={
            "openai": lambda _endpoint, _body, _credential: GatewayDispatchResponse(200, "application/json", b"{}")
        },
    )
    gateway = GatewayDispatchEmulator(
        authorizer=GatewayDispatchTransportAuthorizer(
            trust_store=trust, endpoints={endpoint.gateway_endpoint_id: endpoint}
        ),
        replay_store=GatewayDispatchReplayStore(tmp_path / "failure-replay.sqlite"),
        action_plan_id=grant.action_plan_id,
        plan_digest=grant.plan_digest,
        worker_spiffe_id=grant.worker_spiffe_id,
        handler=handler,
    )

    with pytest.raises(GatewayDispatchError, match="failed after authorization consumption") as error:
        gateway.dispatch(
            grant=grant,
            presented_worker_spiffe_id=grant.worker_spiffe_id,
            request_target=grant.request_target,
            body=body,
        )
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert secret not in repr(error.value)


def _receive_line(client: socket.socket) -> dict[str, object]:
    received = b""
    while not received.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            raise AssertionError("broker closed without returning a complete response")
        received += chunk
    return json.loads(received)


def _hanging_mediator(phase: str) -> HTTPSExecutionMediator:
    allowed = (_endpoint("192.0.2.10"),)
    resolver = ScriptedResolver(
        {"api.example.test": [allowed, allowed]},
        delay_seconds=60 if phase == "resolver" else 0,
    )
    connection = FakeConnection(
        request_delay_seconds=60 if phase == "response" else 0,
        close_delay_seconds=60 if phase == "close" else 0,
    )
    connector = FakeConnector(connection, delay_seconds=60 if phase == "connector" else 0)
    identity_verifier = HangingIdentityVerifier() if phase == "identity" else None
    return _mediator(resolver, connector, identity_verifier=identity_verifier)


@pytest.mark.parametrize("phase", ("resolver", "connector", "identity", "response", "close"))
def test_broker_hard_deadline_kills_and_reaps_every_blocking_phase(phase: str) -> None:
    mediator = _hanging_mediator(phase)
    broker = ExecutionEgressBroker(mediator, protocol_timeout_seconds=0.15)

    started = time.monotonic()
    with broker.open_channel() as channel:
        process = channel._supervisor._process
        channel._client_socket.settimeout(2)
        request = _request_document("https://api.example.test/private?token=secret")
        channel._client_socket.sendall(json.dumps(request).encode("utf-8") + b"\n")
        assert _receive_line(channel._client_socket) == {"error": "egress_denied", "ok": False}

    assert time.monotonic() - started < 2
    assert not process.is_alive()
    assert process.exitcode is not None and process.exitcode < 0
    assert mediator.observations[-1].origin == "https://api.example.test"
    assert mediator.observations[-1].decision == "blocked"
    assert mediator.observations[-1].reason == "broker_deadline_exceeded"
    assert sum(observation.reason == "broker_deadline_exceeded" for observation in mediator.observations) == 1
    assert "secret" not in repr(mediator.observations)


def test_broker_clamps_protocol_to_worker_operation_deadline() -> None:
    broker = ExecutionEgressBroker(_hanging_mediator("response"), protocol_timeout_seconds=10)

    started = time.monotonic()
    with broker.open_channel(deadline=started + 0.15) as channel:
        process = channel._supervisor._process
        channel._client_socket.settimeout(2)
        channel._client_socket.sendall(json.dumps(_request_document()).encode("utf-8") + b"\n")
        assert _receive_line(channel._client_socket) == {"error": "egress_denied", "ok": False}

    assert time.monotonic() - started < 2
    assert not process.is_alive()
    assert process.exitcode is not None


def test_broker_rejects_expired_worker_operation_deadline() -> None:
    broker = ExecutionEgressBroker(_hanging_mediator("response"), protocol_timeout_seconds=10)

    with pytest.raises(EgressMediationError, match="deadline has expired"):
        with broker.open_channel(deadline=time.monotonic() - 1):
            pytest.fail("expired deadline must not open an egress channel")


def test_broker_client_disconnect_kills_and_reaps_blocked_mediation() -> None:
    broker = ExecutionEgressBroker(_hanging_mediator("response"), protocol_timeout_seconds=10)

    started = time.monotonic()
    with broker.open_channel() as channel:
        process = channel._supervisor._process
        channel._client_socket.sendall(json.dumps(_request_document()).encode("utf-8") + b"\n")
        time.sleep(0.05)
        assert process.is_alive()

    assert time.monotonic() - started < 2
    assert not process.is_alive()
    assert process.exitcode is not None


def test_broker_bounds_total_requests_and_total_request_bytes_per_operation() -> None:
    allowed = (_endpoint("192.0.2.10"),)
    request_line = json.dumps(_request_document()).encode("utf-8") + b"\n"

    count_mediator = _mediator(
        ScriptedResolver({"api.example.test": [allowed, allowed]}),
        FakeConnector(FakeConnection()),
    )
    with ExecutionEgressBroker(count_mediator, max_requests=1).open_channel() as channel:
        channel._client_socket.sendall(request_line)
        assert _receive_line(channel._client_socket)["ok"] is True
        channel._client_socket.sendall(request_line)
        assert _receive_line(channel._client_socket) == {"error": "operation_limit_exceeded", "ok": False}
    assert count_mediator.observations[-1].origin == "https://api.example.test"
    assert count_mediator.observations[-1].reason == "broker_request_count_limit"

    padded = _request_document()
    padded["headers"] = {"X-Padding": "a" * 300}
    padded_line = json.dumps(padded).encode("utf-8") + b"\n"
    assert len(padded_line) < 512 < len(padded_line) * 2
    byte_mediator = _mediator(
        ScriptedResolver({"api.example.test": [allowed, allowed]}),
        FakeConnector(FakeConnection()),
    )
    with ExecutionEgressBroker(
        byte_mediator,
        max_request_bytes=512,
        max_total_request_bytes=512,
    ).open_channel() as channel:
        channel._client_socket.sendall(padded_line)
        assert _receive_line(channel._client_socket)["ok"] is True
        channel._client_socket.sendall(padded_line)
        assert _receive_line(channel._client_socket) == {"error": "operation_limit_exceeded", "ok": False}
    assert byte_mediator.observations[-1].origin == "https://api.example.test"
    assert byte_mediator.observations[-1].reason == "broker_total_request_bytes_limit"


def test_broker_records_redacted_per_request_byte_limit_observation() -> None:
    allowed = (_endpoint("192.0.2.10"),)
    mediator = _mediator(
        ScriptedResolver({"api.example.test": [allowed, allowed]}),
        FakeConnector(FakeConnection()),
    )
    request_line = (
        json.dumps(_request_document("https://api.example.test/private?token=secret")).encode("utf-8") + b"\n"
    )

    with ExecutionEgressBroker(
        mediator,
        max_request_bytes=len(request_line) - 1,
        max_total_request_bytes=len(request_line),
    ).open_channel() as channel:
        process = channel._supervisor._process
        channel._client_socket.sendall(request_line)
        assert _receive_line(channel._client_socket) == {"error": "request_too_large", "ok": False}

    assert process.exitcode == 0
    assert mediator.observations[-1].origin == "https://api.example.test"
    assert mediator.observations[-1].decision == "blocked"
    assert mediator.observations[-1].reason == "broker_request_bytes_limit"
    assert "secret" not in repr(mediator.observations)


def test_broker_bounds_total_response_bytes_per_operation() -> None:
    allowed = (_endpoint("192.0.2.10"),)
    mediator = _mediator(
        ScriptedResolver({"api.example.test": [allowed, allowed]}),
        FakeConnector(FakeConnection(response=(200, (), b"x" * 256))),
    )

    with ExecutionEgressBroker(mediator, max_total_response_bytes=128).open_channel() as channel:
        channel._client_socket.sendall(json.dumps(_request_document()).encode("utf-8") + b"\n")
        assert _receive_line(channel._client_socket) == {"error": "operation_limit_exceeded", "ok": False}
    assert mediator.observations[-1].origin == "https://api.example.test"
    assert mediator.observations[-1].reason == "broker_total_response_bytes_limit"
