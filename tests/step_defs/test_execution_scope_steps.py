"""Step definitions for execution scope enforcement BDD scenarios."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution import ScopeDefinition, ScopeGuard, ScopeViolationError
from cops.execution.egress import (
    GATEWAY_POST_BROKER_PROTOCOL,
    AuthenticatedResourceScopeError,
    AuthenticatedServiceAllowlist,
    AuthenticatedServiceIdentity,
    CertificateURIIdentityVerifier,
    EgressMediationError,
    ExecutionEgressBroker,
    GatewayBrokerConfig,
    HTTPSExecutionMediator,
    ResolvedEndpoint,
)
from cops.execution.gateway_dispatch import (
    GATEWAY_DISPATCH_ALGORITHM,
    GATEWAY_DISPATCH_SCHEMA,
    GatewayDispatchEmulator,
    GatewayDispatchEndpoint,
    GatewayDispatchGrant,
    GatewayDispatchReplayError,
    GatewayDispatchReplayStore,
    GatewayDispatchResponse,
    GatewayDispatchTransportAuthorizer,
    GatewayDispatchTrustStore,
    decode_gateway_dispatch_envelope,
    sign_gateway_dispatch,
)
from cops.execution.sandbox import LinuxBubblewrapSandbox, SandboxReadinessError

scenarios("../../specs/features/execution_scope_enforcement.feature")


@pytest.fixture
def scope_context():
    return {}


@given(parsers.parse('an engagement scope containing included subnet "{subnet}" and domain "{domain}"'))
def init_scope_subnet_domain(scope_context, subnet, domain):
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network(subnet)],
        included_domains={domain},
    )
    scope_context["guard"] = ScopeGuard(
        scope_context["scope_def"],
        resolver=lambda d: ["10.0.0.50"] if d == domain else [],
    )


@when(parsers.parse('the ScopeGuard verifies destination "{dest}"'))
def verify_dest(scope_context, dest):
    try:
        scope_context["guard"].check_destination(dest)
        scope_context["last_error"] = None
    except ScopeViolationError as err:
        scope_context["last_error"] = err


@then("the destination is permitted")
def assert_permitted(scope_context):
    assert scope_context["last_error"] is None


@given(parsers.parse('an engagement scope containing included subnet "{subnet}" with excluded IP "{excluded_ip}"'))
def init_scope_with_exclusion(scope_context, subnet, excluded_ip):
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network(subnet)],
        excluded_ips={ipaddress.ip_address(excluded_ip)},
    )
    scope_context["guard"] = ScopeGuard(scope_context["scope_def"])


@then("the destination is rejected as an excluded target")
def assert_excluded(scope_context):
    assert isinstance(scope_context["last_error"], ScopeViolationError)
    assert "excluded" in str(scope_context["last_error"])


@given("an engagement scope")
def init_default_scope(scope_context):
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network("10.0.0.0/24")],
        block_cloud_metadata=True,
    )
    scope_context["guard"] = ScopeGuard(scope_context["scope_def"])


@then("the destination is rejected as a blocked cloud metadata address")
def assert_metadata_blocked(scope_context):
    assert isinstance(scope_context["last_error"], ScopeViolationError)
    assert "cloud metadata" in str(scope_context["last_error"])


@given(parsers.parse('a hostname "{hostname}" resolving to cloud metadata IP "{metadata_ip}"'))
def init_rebind_host(scope_context, hostname, metadata_ip):
    scope_context["rebind_hostname"] = hostname
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network("10.0.0.0/24")],
        included_domains={hostname},
        block_cloud_metadata=True,
    )
    scope_context["guard"] = ScopeGuard(
        scope_context["scope_def"],
        resolver=lambda h: [metadata_ip] if h == hostname else [],
    )


@when("the ScopeGuard verifies the hostname destination")
def verify_rebind(scope_context):
    try:
        scope_context["guard"].check_destination(scope_context["rebind_hostname"])
        scope_context["last_error"] = None
    except ScopeViolationError as err:
        scope_context["last_error"] = err


_IDENTITY = AuthenticatedServiceIdentity(
    provider="aws",
    service="eks",
    account="account-a",
    tenant="tenant-a",
    cluster="cluster-a",
    namespace="namespace-a",
    resource="resource-a",
)
_TRUST_DOMAIN = "identity.example.test"
_IDENTITY_URI = (
    f"spiffe://{_TRUST_DOMAIN}/cops/v1/provider/aws/service/eks/account/account-a/"
    "tenant/tenant-a/cluster/cluster-a/namespace/namespace-a/resource/resource-a"
)
_ENDPOINT = ResolvedEndpoint(socket.AF_INET, socket.SOCK_STREAM, 0, ("192.0.2.10", 443), "192.0.2.10")


class _BDDConnection:
    def __init__(self, *, peer_ip="192.0.2.10", identity_uri=_IDENTITY_URI, response=None, request_error=None):
        self.peer_ip = peer_ip
        self.peer_certificate_der = b"authenticated-peer"
        self.peer_certificate = {"subjectAltName": (("DNS", "api.example.test"), ("URI", identity_uri))}
        self.requests = []
        self.request_bodies = []
        self.response = response or (200, (("Content-Type", "application/json"),), b"{}")
        self.request_error = request_error

    def request(self, *, method, target, headers, body=b"", **_limits):
        self.requests.append((method, target, dict(headers)))
        self.request_bodies.append(body)
        if self.request_error is not None:
            raise self.request_error
        return self.response

    def close(self):
        pass


class _BDDConnector:
    def __init__(self, connection):
        self.connection = connection
        self.open_count = 0

    def open(self, _endpoint, *, hostname, port, timeout_seconds):
        assert (hostname, port) == ("api.example.test", 443)
        assert timeout_seconds > 0
        self.open_count += 1
        return self.connection


def _mediator_for_bdd(connection, *, allow_target="/v1/status", approved_origin=None):
    connector = _BDDConnector(connection)
    mediator = HTTPSExecutionMediator(
        scope_guard=ScopeGuard(
            ScopeDefinition(
                included_networks=[ipaddress.ip_network("192.0.2.0/24")],
                included_domains={"api.example.test"},
                egress_allowed=True,
            )
        ),
        identity_verifier=CertificateURIIdentityVerifier(trust_domain=_TRUST_DOMAIN),
        identity_allowlist=AuthenticatedServiceAllowlist({_IDENTITY: frozenset({allow_target})}),
        approved_origin=approved_origin,
        resolver=lambda _hostname, _port: (_ENDPOINT,),
        connector=connector,
    )
    return mediator, connector


@given("an approved authenticated service identity and exact HTTPS request target")
def init_authenticated_service(scope_context):
    scope_context["authenticated_url"] = "https://api.example.test/v1/status"


@when("the mediator verifies the live destination, TLS identity, and request target")
def verify_authenticated_service(scope_context):
    approved = _BDDConnection()
    mediator, connector = _mediator_for_bdd(approved)
    response = mediator.request(method="GET", url=scope_context["authenticated_url"])
    scope_context["approved"] = (response, approved, connector)

    denials = []
    for connection, url, expected_error in (
        (_BDDConnection(peer_ip="192.0.2.11"), scope_context["authenticated_url"], EgressMediationError),
        (
            _BDDConnection(identity_uri=_IDENTITY_URI.replace("account/account-a", "account/account-b")),
            scope_context["authenticated_url"],
            AuthenticatedResourceScopeError,
        ),
        (_BDDConnection(), "https://api.example.test/v1/other", AuthenticatedResourceScopeError),
    ):
        denied_mediator, denied_connector = _mediator_for_bdd(connection)
        with pytest.raises(expected_error):
            denied_mediator.request(method="GET", url=url)
        denials.append((connection, denied_connector))
    scope_context["denials"] = denials


@then("the request is dispatched only when every binding matches exactly")
def assert_authenticated_service_bound(scope_context):
    response, connection, connector = scope_context["approved"]
    assert response.status == 200
    assert response.identity == _IDENTITY
    assert connection.requests == [("GET", "/v1/status", {"Host": "api.example.test"})]
    assert connector.open_count == 1
    assert all(not connection.requests for connection, _connector in scope_context["denials"])


@given("an adapter receives an egress broker capability")
def init_broker_capability(scope_context):
    scope_context["broker"] = ExecutionEgressBroker(_mediator_for_bdd(_BDDConnection())[0])


@when("the adapter executes in the worker network sandbox")
def run_contained_adapter(scope_context, tmp_path):
    if not sys.platform.startswith("linux"):
        pytest.skip("production bubblewrap containment is Linux-only")
    bubblewrap_path = Path("/usr/bin/bwrap")
    if not bubblewrap_path.is_file():
        pytest.fail("required Linux bubblewrap isolation gate cannot find /usr/bin/bwrap")

    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    workspace.chmod(0o700)
    sandbox = LinuxBubblewrapSandbox(bubblewrap_path=bubblewrap_path)
    try:
        sandbox.assert_ready("bdd-execution-scope", cwd=workspace)
    except SandboxReadinessError as err:
        pytest.fail(f"required Linux isolation readiness failed: {err}")

    listeners = []
    targets = []
    for label, family, bind_address in (
        ("ipv4", socket.AF_INET, ("127.0.0.1", 0)),
        ("ipv6", socket.AF_INET6, ("::1", 0, 0, 0)),
    ):
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.settimeout(1)
            listener.bind(bind_address)
            listener.listen(1)
            address = listener.getsockname()
            with socket.socket(family, socket.SOCK_STREAM) as control:
                control.settimeout(1)
                control.connect(address)
            accepted, _peer = listener.accept()
            accepted.close()
        except OSError:
            listener.close()
            if family == socket.AF_INET6:
                continue
            raise
        listeners.append(listener)
        targets.append((label, family, address))

    executable_fd = os.open(Path("/usr/bin/python3").resolve(strict=True), os.O_RDONLY)
    script = """
import json
import os
import socket
import sys

direct = {}
for label, family, address in json.loads(sys.argv[1]):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as channel:
            channel.settimeout(0.5)
            channel.connect(tuple(address))
    except OSError as err:
        direct[label] = err.errno
    else:
        direct[label] = None

broker = socket.socket(fileno=int(os.environ["COPS_EGRESS_BROKER_FD"]))
request = {"version": "cops.execution-egress/v1", "method": "GET", "url": "https://api.example.test/v1/status", "headers": {}}
broker.sendall(json.dumps(request).encode("ascii") + b"\\n")
reply = b""
while not reply.endswith(b"\\n"):
    chunk = broker.recv(4096)
    if not chunk:
        raise RuntimeError("broker closed before returning a complete response")
    reply += chunk
print(json.dumps({"direct": direct, "broker": json.loads(reply), "net_namespace": os.readlink("/proc/self/ns/net")}))
"""
    try:
        with scope_context["broker"].open_channel() as channel:
            result = sandbox.run(
                [f"/proc/self/fd/{executable_fd}", "-c", script, json.dumps(targets)],
                cwd=workspace,
                env={},
                operation_env=channel.environment,
                timeout_seconds=10.0,
                max_output_bytes=4096,
                pass_fds=(executable_fd,),
                capability_fds=channel.pass_fds,
            )
    finally:
        os.close(executable_fd)
        for listener in listeners:
            listener.close()
    assert not result.timed_out
    assert not result.output_limit_exceeded
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    scope_context["contained_adapter"] = json.loads(result.stdout)
    scope_context["host_net_namespace"] = os.readlink("/proc/self/ns/net")
    scope_context["direct_target_labels"] = [target[0] for target in targets]


@then("direct IPv4 and IPv6 connections are denied and mediated broker requests remain available")
def assert_mandatory_mediation(scope_context):
    observed = scope_context["contained_adapter"]
    assert observed["net_namespace"] != scope_context["host_net_namespace"]
    assert "ipv4" in scope_context["direct_target_labels"]
    assert set(observed["direct"]) == set(scope_context["direct_target_labels"])
    assert all(isinstance(error, int) and error > 0 for error in observed["direct"].values())
    assert observed["broker"]["ok"] is True
    assert observed["broker"]["status"] == 200
    assert observed["broker"]["identity"] == _IDENTITY.as_dict()


_GATEWAY_URL = "https://api.example.test/v2/dispatch"
_PROVIDER_TARGET = "https://api.openai.com/v1/responses"
_WORKER_SPIFFE_ID = "spiffe://identity.example.test/worker/approved"


def _gateway_fixture(tmp_path, *, authorization_id="auth-1", dispatch_id="dispatch-1", body=None, connection=None):
    request_body = body if body is not None else b'{"model":"approved"}'
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    grant = sign_gateway_dispatch(
        GatewayDispatchGrant(
            schema_version=GATEWAY_DISPATCH_SCHEMA,
            dispatch_id=dispatch_id,
            authorization_id=authorization_id,
            action_plan_id="plan-1",
            plan_digest="a" * 64,
            worker_spiffe_id=_WORKER_SPIFFE_ID,
            provider="openai",
            account_or_project_kind="project",
            account_or_project="project-1",
            region="us-east-1",
            model="model-1",
            gateway_endpoint_id="endpoint-1",
            request_target=_PROVIDER_TARGET,
            body_sha256=hashlib.sha256(request_body).hexdigest(),
            body_bytes=len(request_body),
            issued_at=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            expires_at=(now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            key_id="bdd-key",
            algorithm=GATEWAY_DISPATCH_ALGORITHM,
        ),
        key,
    )
    trust = GatewayDispatchTrustStore(
        {"bdd-key": key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)}
    )
    endpoint = GatewayDispatchEndpoint(
        gateway_endpoint_id="endpoint-1",
        gateway_identity=_IDENTITY_URI,
        provider="openai",
        account_or_project_kind="project",
        account_or_project="project-1",
        region="us-east-1",
        model="model-1",
        request_target=_PROVIDER_TARGET,
    )
    authorizer = GatewayDispatchTransportAuthorizer(trust_store=trust, endpoints={"endpoint-1": endpoint})
    replay_store = GatewayDispatchReplayStore(tmp_path / "replay.sqlite")
    peer = connection or _BDDConnection()
    mediator, connector = _mediator_for_bdd(
        peer, allow_target="/v2/dispatch", approved_origin=("api.example.test", 443)
    )
    config = GatewayBrokerConfig(
        gateway_url=_GATEWAY_URL,
        gateway_spiffe_id=_IDENTITY_URI,
        expected_identity=_IDENTITY,
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id=_WORKER_SPIFFE_ID,
        max_body_bytes=4096,
        authorizer=authorizer,
        replay_store=replay_store,
    )
    return {
        "grant": grant,
        "body": request_body,
        "peer": peer,
        "mediator": mediator,
        "connector": connector,
        "config": config,
        "authorizer": authorizer,
        "replay_store": replay_store,
    }


def _gateway_document(grant, body):
    return json.dumps(
        {
            "version": GATEWAY_POST_BROKER_PROTOCOL,
            "grant": grant.to_dict(),
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
    ).encode("ascii")


def _dispatch_bdd(fixture, *, config=None, body=None):
    broker = ExecutionEgressBroker(fixture["mediator"], gateway_config=config or fixture["config"])
    return broker._dispatch(
        _gateway_document(fixture["grant"], fixture["body"] if body is None else body),
        deadline=time.monotonic() + 5,
    )


@given(
    parsers.parse('a signed dispatch descriptor for authorization "{authorization_id}" and dispatch "{dispatch_id}"')
)
def signed_gateway_descriptor(scope_context, tmp_path, authorization_id, dispatch_id):
    scope_context["gateway"] = _gateway_fixture(tmp_path, authorization_id=authorization_id, dispatch_id=dispatch_id)


@given(
    "the descriptor binds one gateway origin, request target, SPIFFE identity, account, project, region, model, endpoint, body digest, and body length"
)
def bound_gateway_descriptor(scope_context):
    fixture = scope_context["gateway"]
    grant = fixture["grant"]
    assert fixture["config"].gateway_url == _GATEWAY_URL
    assert fixture["config"].gateway_spiffe_id == _IDENTITY_URI
    assert grant.request_target == _PROVIDER_TARGET
    assert (grant.account_or_project_kind, grant.account_or_project) == ("project", "project-1")
    assert (grant.region, grant.model, grant.gateway_endpoint_id) == ("us-east-1", "model-1", "endpoint-1")
    assert (grant.body_sha256, grant.body_bytes) == (hashlib.sha256(fixture["body"]).hexdigest(), len(fixture["body"]))


@given("the worker has a matching bounded request body")
def matching_gateway_body(scope_context):
    fixture = scope_context["gateway"]
    assert len(fixture["body"]) <= fixture["config"].max_body_bytes


@when("the worker completes gateway transport preflight")
def complete_gateway_preflight(scope_context):
    fixture = scope_context["gateway"]
    scope_context["gateway_response"] = _dispatch_bdd(fixture)


@then("it sends exactly one HTTPS POST to the bound gateway origin and request target")
def assert_exact_gateway_post(scope_context):
    fixture = scope_context["gateway"]
    peer = fixture["peer"]
    assert fixture["connector"].open_count == 1
    assert len(peer.requests) == len(peer.request_bodies) == 1
    method, target, headers = peer.requests[0]
    assert (method, target, headers["Host"]) == ("POST", "/v2/dispatch", "api.example.test")
    grant, body = decode_gateway_dispatch_envelope(peer.request_bodies[0])
    assert grant == fixture["grant"]
    assert body == fixture["body"]
    assert scope_context["gateway_response"].status == 200


@then("it exposes no provider origin or provider credential to the worker")
def assert_gateway_worker_scope(scope_context):
    fixture = scope_context["gateway"]
    _, _, headers = fixture["peer"].requests[0]
    assert fixture["config"].gateway_url == _GATEWAY_URL
    assert "Authorization" not in headers
    assert "Proxy-Authorization" not in headers
    assert _PROVIDER_TARGET not in repr(fixture["mediator"].observations)


@given("a pending one-use authorization and a signed dispatch descriptor")
def pending_gateway_authorization(scope_context, tmp_path):
    scope_context["gateway_root"] = tmp_path


@when("the gateway origin, request target, SPIFFE identity, body digest, or body length fails validation")
def invalidate_gateway_binding(scope_context):
    denials = []
    for kind in ("origin", "target", "identity", "digest", "length"):
        fixture = _gateway_fixture(scope_context["gateway_root"] / kind)
        config = fixture["config"]
        body = fixture["body"]
        if kind == "origin":
            config = replace(config, gateway_url=_PROVIDER_TARGET)
        elif kind == "target":
            config = replace(config, gateway_url="https://api.example.test/v2/other")
        elif kind == "identity":
            config = replace(config, gateway_spiffe_id="spiffe://identity.example.test/other")
        elif kind == "digest":
            body = b"{" + body[1:]
            body = body[:-1] + b"!"
        else:
            body += b"!"
        with pytest.raises((EgressMediationError, RuntimeError)):
            _dispatch_bdd(fixture, config=config, body=body)
        denials.append(fixture)
    scope_context["gateway_denials"] = denials


@then("the worker sends no request")
def assert_gateway_denials_send_nothing(scope_context):
    assert all(not case["peer"].requests for case in scope_context["gateway_denials"])


@then("the authorization remains unconsumed")
def assert_gateway_authorizations_unconsumed(scope_context):
    for case in scope_context["gateway_denials"]:
        case["replay_store"].consume(case["grant"])
        with pytest.raises(GatewayDispatchReplayError):
            case["replay_store"].consume(case["grant"])


@given("an approved gateway POST dispatch has been transmitted once")
def approved_gateway_once(scope_context, tmp_path):
    scope_context["gateway_root"] = tmp_path


@when("the gateway returns a redirect or the connection result is unknown")
def gateway_redirect_or_unknown(scope_context):
    outcomes = []
    for kind, peer in (
        ("redirect", _BDDConnection(response=(302, (("Location", _PROVIDER_TARGET),), b""))),
        ("unknown", _BDDConnection(request_error=ConnectionResetError("connection lost"))),
    ):
        fixture = _gateway_fixture(scope_context["gateway_root"] / kind, connection=peer)
        with pytest.raises(EgressMediationError):
            _dispatch_bdd(fixture)
        with pytest.raises((EgressMediationError, RuntimeError)):
            _dispatch_bdd(fixture)
        outcomes.append(fixture)
    scope_context["gateway_uncertain"] = outcomes


@then("the dispatch is recorded with a redacted rejected or unknown outcome")
def assert_gateway_uncertain_evidence(scope_context):
    for case in scope_context["gateway_uncertain"]:
        observations = case["mediator"].observations
        assert observations and all(item.decision == "blocked" for item in observations)
        assert all(item.origin == "https://api.example.test" for item in observations)
        assert _PROVIDER_TARGET not in repr(observations)
        assert "connection lost" not in repr(observations)


@then("the worker does not follow a redirect or send another request")
def assert_gateway_no_retry(scope_context):
    for case in scope_context["gateway_uncertain"]:
        assert len(case["peer"].requests) == 1
        # A caller-initiated replay may establish TLS before the one-use
        # authorization is rejected by the pre-send callback.
        assert case["connector"].open_count == 2


def _gateway_emulator(case, handler):
    return GatewayDispatchEmulator(
        authorizer=case["authorizer"],
        replay_store=case["replay_store"],
        action_plan_id="plan-1",
        plan_digest="a" * 64,
        worker_spiffe_id=_WORKER_SPIFFE_ID,
        handler=handler,
    )


@given(parsers.parse('a gateway has durably claimed dispatch "{dispatch_id}"'))
def gateway_claimed_dispatch(scope_context, tmp_path, dispatch_id):
    case = _gateway_fixture(tmp_path, dispatch_id=dispatch_id)
    attempts = []
    emulator = _gateway_emulator(case, lambda invocation: attempts.append(invocation) or None)
    emulator.dispatch(
        grant=case["grant"],
        presented_worker_spiffe_id=_WORKER_SPIFFE_ID,
        request_target=_PROVIDER_TARGET,
        body=case["body"],
    )
    scope_context["claimed_gateway"] = (case, emulator, attempts)


@when(parsers.parse('it receives another request for dispatch "{dispatch_id}"'))
def replay_gateway_dispatch(scope_context, dispatch_id):
    case, emulator, _attempts = scope_context["claimed_gateway"]
    assert case["grant"].dispatch_id == dispatch_id
    with pytest.raises(GatewayDispatchReplayError) as error:
        emulator.dispatch(
            grant=case["grant"],
            presented_worker_spiffe_id=_WORKER_SPIFFE_ID,
            request_target=_PROVIDER_TARGET,
            body=case["body"],
        )
    scope_context["gateway_replay_error"] = error.value


@then("it rejects the request before an upstream provider attempt")
def assert_gateway_replay_prevents_attempt(scope_context):
    assert len(scope_context["claimed_gateway"][2]) == 1


@then("it emits only redacted replay evidence")
def assert_gateway_replay_redacted(scope_context):
    message = str(scope_context["gateway_replay_error"])
    assert message == "gateway dispatch authorization denied"
    assert _PROVIDER_TARGET not in message


@given("the loopback-only gateway emulator receives a valid dispatch")
def valid_synthetic_gateway_dispatch(scope_context, tmp_path):
    scope_context["synthetic_gateway"] = _gateway_fixture(tmp_path, body=b'{"prompt":"sensitive-payload"}')


@when("it validates the descriptor and returns a synthetic outcome")
def return_synthetic_gateway_outcome(scope_context):
    case = scope_context["synthetic_gateway"]
    invocations = []

    def handler(invocation):
        invocations.append(invocation)
        return GatewayDispatchResponse(
            status_code=200, media_type="application/json", body=b'{"text":"sensitive-output"}'
        )

    emulator = _gateway_emulator(case, handler)
    receipt = emulator.dispatch(
        grant=case["grant"],
        presented_worker_spiffe_id=_WORKER_SPIFFE_ID,
        request_target=_PROVIDER_TARGET,
        body=case["body"],
    )
    scope_context["synthetic_receipt"] = receipt
    scope_context["synthetic_invocations"] = invocations


@then("its evidence contains only identifiers, hashes, byte counts, decision codes, and bounded status metadata")
def assert_synthetic_gateway_metadata(scope_context):
    receipt = scope_context["synthetic_receipt"]
    assert receipt.decision == "accepted"
    assert receipt.response is not None
    assert (receipt.response.status_code, receipt.response.media_type) == (200, "application/json")
    assert receipt.body_bytes == len(scope_context["synthetic_gateway"]["body"])
    assert receipt.body_sha256 == hashlib.sha256(scope_context["synthetic_gateway"]["body"]).hexdigest()
    assert len(scope_context["synthetic_invocations"]) == 1


@then(
    "it contains no provider credential, raw request body, authorization header, raw provider response, or provider network destination"
)
def assert_synthetic_gateway_redaction(scope_context):
    receipt = scope_context["synthetic_receipt"]
    invocation = scope_context["synthetic_invocations"][0]
    evidence = repr(receipt) + repr(invocation) + repr(receipt.response)
    for secret in (
        "provider-secret-credential",
        "sensitive-payload",
        "sensitive-output",
        "Authorization",
        _PROVIDER_TARGET,
    ):
        assert secret not in evidence
