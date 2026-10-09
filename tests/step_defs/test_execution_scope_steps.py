"""Step definitions for execution scope enforcement BDD scenarios."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution import ScopeDefinition, ScopeGuard, ScopeViolationError
from cops.execution.egress import (
    AuthenticatedResourceScopeError,
    AuthenticatedServiceAllowlist,
    AuthenticatedServiceIdentity,
    CertificateURIIdentityVerifier,
    EgressMediationError,
    ExecutionEgressBroker,
    HTTPSExecutionMediator,
    ResolvedEndpoint,
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
    def __init__(self, *, peer_ip="192.0.2.10", identity_uri=_IDENTITY_URI):
        self.peer_ip = peer_ip
        self.peer_certificate_der = b"authenticated-peer"
        self.peer_certificate = {"subjectAltName": (("DNS", "api.example.test"), ("URI", identity_uri))}
        self.requests = []

    def request(self, *, method, target, headers, **_limits):
        self.requests.append((method, target, dict(headers)))
        return 200, (("Content-Type", "application/json"),), b"{}"

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


def _mediator_for_bdd(connection, *, allow_target="/v1/status"):
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

    executable_fd = os.open(Path("/usr/bin/python3").resolve(strict=True), os.O_RDONLY)
    script = """
import json
import os
import socket

direct = {}
for label, family, address in (
    ("ipv4", socket.AF_INET, ("192.0.2.10", 443)),
    ("ipv6", socket.AF_INET6, ("2001:db8::10", 443, 0, 0)),
):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as channel:
            channel.settimeout(0.5)
            channel.connect(address)
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
                [f"/proc/self/fd/{executable_fd}", "-c", script],
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
    assert not result.timed_out
    assert not result.output_limit_exceeded
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    scope_context["contained_adapter"] = json.loads(result.stdout)
    scope_context["host_net_namespace"] = os.readlink("/proc/self/ns/net")


@then("direct IPv4 and IPv6 connections are denied and mediated broker requests remain available")
def assert_mandatory_mediation(scope_context):
    import errno

    observed = scope_context["contained_adapter"]
    assert observed["net_namespace"] != scope_context["host_net_namespace"]
    assert observed["direct"]["ipv4"] in {errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH}
    assert observed["direct"]["ipv6"] in {
        errno.EPERM,
        errno.EACCES,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.EAFNOSUPPORT,
    }
    assert observed["broker"]["ok"] is True
    assert observed["broker"]["status"] == 200
    assert observed["broker"]["identity"] == _IDENTITY.as_dict()
