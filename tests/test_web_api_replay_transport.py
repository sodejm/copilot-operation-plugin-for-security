"""Transport and approval regressions using real loopback HTTP exchanges."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cops.execution.scope_guard import ScopeDefinition, ScopeGuard, ScopeViolationError
from cops.execution.store import ApprovalStore
from cops.laboratory.service_tls import _certificate_material
from cops.web_api.models import AuthenticationMechanism, ReplayBudget, ReplayRequest, SessionContext
from cops.web_api.replay import (
    DestinationGuard,
    DestinationViolationError,
    ReplayAuthorizationError,
    ReplayBudgetExceededError,
    StandardHttpReplayer,
    build_replay_action_plan,
    execute_authorized_replay_session,
    preview_replay_session,
)
from tests.auth_testkit import TestApprovalControl, authorize_test_plan


@pytest.fixture
def http_lab():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _handle(self):
            body_length = int(self.headers.get("Content-Length", "0"))
            if body_length:
                self.rfile.read(body_length)
            seen.append((self.path, dict(self.headers)))
            if self.path == "/drop":
                self.close_connection = True
                return
            if self.path.startswith("/redirect"):
                self.send_response(self.server.redirect_status)
                self.send_header("Location", self.server.redirect_target)
                self.end_headers()
                return
            status = int(self.path[1:]) if self.path[1:].isdigit() else 200
            self.send_response(status)
            self.send_header("Retry-After", "1")
            self.send_header("Content-Length", "2")
            self.end_headers()
            if self.path == "/slow":
                time.sleep(0.3)
            try:
                self.wfile.write(b"ok")
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.redirect_target = "/200"
    server.redirect_status = 302
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


@pytest.fixture
def https_lab(tmp_path):
    material_dir = tmp_path / "tls"
    material_dir.mkdir()
    material = _certificate_material(material_dir)
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            seen.append((self.path, dict(self.headers)))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(material["server_cert"], material["server_key"])
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}", seen, material
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def _scope(resolver=None):
    scope = ScopeDefinition(included_ips=[ipaddress.ip_address("127.0.0.1")], included_domains=["replay.test"])
    return ScopeGuard(scope, resolver=resolver) if resolver else ScopeGuard(scope)


def _request(url, method="GET", **kwargs):
    return ReplayRequest(request_id="request-one", endpoint_id="endpoint-one", method=method, url=url, **kwargs)


def _plan(requests, destinations, budget, sessions=None):
    return build_replay_action_plan(
        plan_id="plan-api-transport",
        engagement_id="eng-api-transport",
        scenario_id="scen-api-transport",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        allowed_destinations=destinations,
        budget=budget,
        sessions=sessions,
        created_at="2026-10-18T00:00:00Z",
    )


def _authority(tmp_path, plan):
    auth, trust, engagement = authorize_test_plan(plan, worker_identity="worker-api-transport")
    store = ApprovalStore(tmp_path / "authority" / "approvals.sqlite3")
    store.store_authorization(auth)
    return auth.authorization_id, TestApprovalControl(store, trust, engagement)


def _execute(plan, auth_id, approval, requests, destinations, budget, sessions=None, scope=None):
    return execute_authorized_replay_session(
        requests=requests,
        sessions=sessions or [],
        allowed_destinations=destinations,
        scope_guard=scope or _scope(),
        budget=budget,
        action_plan=plan,
        authorization_id=auth_id,
        approval_control=approval,
        worker_identity="worker-api-transport",
    )


@pytest.mark.parametrize("status", [200, 401, 403, 404, 429, 500])
def test_completed_http_responses_are_evidence(http_lab, status):
    base, seen, _ = http_lab
    response = StandardHttpReplayer(DestinationGuard([base.removeprefix("http://")]), _scope()).send(
        _request(f"{base}/{status}"), ReplayBudget(timeout_seconds=1)
    )
    assert response.status_code == status
    assert response.replay_success and response.error_message is None
    assert response.body_excerpt == "ok" and len(seen) == 1


def test_checked_numeric_address_is_used_without_second_dns_or_proxy(http_lab, monkeypatch):
    base, seen, _ = http_lab
    port = base.rsplit(":", 1)[1]
    resolved = []

    def resolve(host):
        resolved.append(host)
        return ["127.0.0.1"]

    def forbidden_dns(*_args, **_kwargs):
        raise AssertionError("transport performed a second DNS resolution")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_dns)
    monkeypatch.setenv("http_proxy", "http://unapproved-proxy.test:9999")
    monkeypatch.setenv("HTTP_PROXY", "http://unapproved-proxy.test:9999")
    monkeypatch.setenv("no_proxy", "")
    response = StandardHttpReplayer(DestinationGuard([f"replay.test:{port}"]), _scope(resolve)).send(
        _request(f"http://replay.test:{port}/200"), ReplayBudget(timeout_seconds=1)
    )
    assert response.replay_success
    assert resolved == ["replay.test"]
    assert seen[0][1]["Host"] == f"replay.test:{port}"


def test_redirect_revalidates_changed_dns_before_dispatch(http_lab):
    base, seen, _ = http_lab
    port = base.rsplit(":", 1)[1]
    answers = iter([["127.0.0.1"], ["192.0.2.1"]])
    replayer = StandardHttpReplayer(DestinationGuard([f"replay.test:{port}"]), _scope(lambda _: next(answers)))
    with pytest.raises(ScopeViolationError):
        replayer.send(_request(f"http://replay.test:{port}/redirect"), ReplayBudget(timeout_seconds=1))
    assert len(seen) == 1


@pytest.mark.parametrize("target", ["http://192.0.2.1/200", "http://user:password@127.0.0.1/200"])
def test_redirect_rejects_disallowed_or_userinfo_destination(http_lab, target):
    base, seen, server = http_lab
    server.redirect_target = target
    replayer = StandardHttpReplayer(DestinationGuard([base.removeprefix("http://")]), _scope())
    with pytest.raises(DestinationViolationError):
        replayer.send(_request(f"{base}/redirect"), ReplayBudget(timeout_seconds=1))
    assert len(seen) == 1


def test_redirect_credentials_cannot_cross_origins(http_lab):
    base, seen, server = http_lab
    port = server.server_port
    server.redirect_target = f"http://replay.test:{port}/200"
    replayer = StandardHttpReplayer(
        DestinationGuard([base.removeprefix("http://"), f"replay.test:{port}"]), _scope(lambda _: ["127.0.0.1"])
    )
    with pytest.raises(DestinationViolationError, match="cross-origin"):
        replayer.send(_request(f"{base}/redirect", headers={"Authorization": "Bearer synthetic"}), ReplayBudget())
    assert len(seen) == 1


def test_custom_session_credential_header_cannot_cross_origins(http_lab, tmp_path):
    base, seen, server = http_lab
    port = server.server_port
    server.redirect_target = f"http://replay.test:{port}/200"
    requests = [_request(f"{base}/redirect", session_id="owner", role_id="owner")]
    sessions = [
        SessionContext(
            session_id="owner",
            role_id="owner",
            auth_mechanism=AuthenticationMechanism(
                auth_type="custom",
                token_name="X-Identity-Proof",
                location="header",
            ),
            headers={"X-Identity-Proof": "synthetic-proof"},
        )
    ]
    destinations = [base.removeprefix("http://"), f"replay.test:{port}"]
    budget = ReplayBudget(max_requests=1, timeout_seconds=1, rate_limit_rps=0)
    plan = _plan(requests, destinations, budget, sessions)
    auth_id, approval = _authority(tmp_path, plan)

    with pytest.raises(DestinationViolationError, match="cross-origin"):
        _execute(
            plan,
            auth_id,
            approval,
            requests,
            destinations,
            budget,
            sessions,
            _scope(lambda _: ["127.0.0.1"]),
        )

    assert len(seen) == 1
    assert seen[0][0] == "/redirect"
    assert seen[0][1]["X-Identity-Proof"] == "synthetic-proof"


def test_cross_origin_redirect_cannot_retain_request_body(http_lab):
    base, seen, server = http_lab
    port = server.server_port
    server.redirect_status = 307
    server.redirect_target = f"http://replay.test:{port}/200"
    replayer = StandardHttpReplayer(
        DestinationGuard([base.removeprefix("http://"), f"replay.test:{port}"]), _scope(lambda _: ["127.0.0.1"])
    )
    request = _request(
        f"{base}/redirect",
        method="POST",
        headers={"Content-Type": "application/json"},
        body='{"password":"synthetic"}',
    )
    with pytest.raises(DestinationViolationError, match="cross-origin"):
        replayer.send(request, ReplayBudget())
    assert len(seen) == 1


def test_cross_origin_redirect_allows_body_dropping_method_rewrite(http_lab):
    base, seen, server = http_lab
    port = server.server_port
    server.redirect_status = 303
    server.redirect_target = f"http://replay.test:{port}/200"
    replayer = StandardHttpReplayer(
        DestinationGuard([base.removeprefix("http://"), f"replay.test:{port}"]), _scope(lambda _: ["127.0.0.1"])
    )
    response = replayer.send(
        _request(
            f"{base}/redirect",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Signature": "synthetic-signature",
            },
            body='{"value":"synthetic"}',
        ),
        ReplayBudget(),
    )
    assert response.replay_success
    assert [path for path, _headers in seen] == ["/redirect", "/200"]
    assert "Content-Type" not in seen[1][1]
    assert "Signature" not in seen[1][1]


def test_tls_verifies_trusted_certificate_for_original_host(https_lab):
    base, seen, material = https_lab
    client_context = ssl.create_default_context(cafile=material["ca"])
    response = StandardHttpReplayer(
        DestinationGuard([base.removeprefix("https://")]), _scope(), tls_context=client_context
    ).send(_request(f"{base}/200"), ReplayBudget(timeout_seconds=1))
    assert response.replay_success and response.status_code == 200
    assert len(seen) == 1


@pytest.mark.parametrize("failure", ["hostname", "trust"])
def test_tls_rejects_hostname_mismatch_and_untrusted_certificate(https_lab, failure):
    base, seen, material = https_lab
    port = base.rsplit(":", 1)[1]
    if failure == "hostname":
        url = f"https://replay.test:{port}/200"
        client_context = ssl.create_default_context(cafile=material["ca"])
    else:
        url = f"{base}/200"
        client_context = ssl.create_default_context(cafile=material["untrusted_ca"])
    response = StandardHttpReplayer(
        DestinationGuard([url.removeprefix("https://").split("/", 1)[0]]),
        _scope(lambda _: ["127.0.0.1"]),
        tls_context=client_context,
    ).send(_request(url), ReplayBudget(timeout_seconds=1))
    assert not response.replay_success and response.status_code == 0
    assert response.error_message == "SSLCertVerificationError"
    assert seen == []


def test_tls_context_cannot_disable_certificate_verification():
    insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_context.check_hostname = False
    insecure_context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ReplayAuthorizationError, match="certificate and hostname verification"):
        StandardHttpReplayer(DestinationGuard(["replay.test"]), _scope(), tls_context=insecure_context)


def test_body_deadline_is_aggregate_and_returns_no_false_success(http_lab):
    base, seen, _ = http_lab
    started = time.monotonic()
    response = StandardHttpReplayer(DestinationGuard([base.removeprefix("http://")]), _scope()).send(
        _request(f"{base}/slow"), ReplayBudget(timeout_seconds=0.05)
    )
    assert time.monotonic() - started < 0.25
    assert not response.replay_success and response.status_code == 0
    assert response.error_message == "TimeoutError" and len(seen) == 1


def test_resolver_deadline_cannot_dispatch_late_credentials(http_lab):
    base, seen, _ = http_lab
    port = base.rsplit(":", 1)[1]
    finished = threading.Event()

    def resolve(_):
        time.sleep(0.2)
        finished.set()
        return ["127.0.0.1"]

    started = time.monotonic()
    response = StandardHttpReplayer(DestinationGuard([f"replay.test:{port}"]), _scope(resolve)).send(
        _request(f"http://replay.test:{port}/200", headers={"Authorization": "Bearer synthetic"}),
        ReplayBudget(timeout_seconds=0.04),
    )
    assert time.monotonic() - started < 0.15
    assert not response.replay_success and response.error_message == "TimeoutError"
    assert finished.wait(1)
    time.sleep(0.02)
    assert seen == []


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "other.test"},
        {"Transfer-Encoding": "chunked"},
        {"Content-Length": "8"},
        {"X-One": "a", "x-one": "b"},
        {"X-Test": "bad\r\nInjected: value"},
    ],
)
def test_unsafe_headers_rejected_before_dispatch(http_lab, headers):
    base, seen, _ = http_lab
    with pytest.raises(ReplayAuthorizationError):
        StandardHttpReplayer(DestinationGuard([base.removeprefix("http://")]), _scope()).send(
            _request(f"{base}/200", headers=headers), ReplayBudget(timeout_seconds=1)
        )
    assert seen == []


@pytest.mark.parametrize(
    "url,allowed,expected",
    [
        ("http://[::1]:8123/", ["[::1]:8123"], True),
        ("http://[::1]:8124/", ["[::1]:8123"], False),
        ("http://name.test:bad/", ["name.test"], False),
        ("http://user:password@name.test/", ["name.test"], False),
        ("http://name.test\n/", ["name.test"], False),
        ("http://name.test:0/", ["name.test"], False),
    ],
)
def test_destination_authorities_are_unambiguous(url, allowed, expected):
    assert DestinationGuard(allowed).is_destination_allowed(url) is expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_requests", True),
        ("max_requests", 1.5),
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", float("inf")),
        ("timeout_seconds", True),
        ("rate_limit_rps", float("nan")),
        ("rate_limit_rps", 1e-300),
        ("max_redirect_hops", -1),
        ("max_redirect_hops", 1.2),
        ("max_websocket_frames", True),
    ],
)
def test_invalid_budgets_rejected_before_preview(field, value):
    with pytest.raises(ReplayBudgetExceededError):
        preview_replay_session(
            [_request("http://example.test/")], ["example.test"], replace(ReplayBudget(), **{field: value})
        )


def test_budget_deserialization_does_not_coerce_invalid_types():
    budget = ReplayBudget.from_dict({"max_requests": True})
    with pytest.raises(ReplayBudgetExceededError):
        preview_replay_session([], ["example.test"], budget)


@pytest.mark.parametrize(
    "change",
    [
        "request",
        "credentials",
        "cookies",
        "session_metadata",
        "isolation",
        "destinations",
        "requests",
        "hops",
        "timeout",
        "rate",
        "frames",
    ],
)
def test_approved_wire_session_and_every_budget_are_bound(tmp_path, change):
    requests = [_request("http://replay.test/200", session_id="owner", role_id="owner")]
    sessions = [SessionContext(session_id="owner", role_id="owner", headers={"Authorization": "Bearer synthetic-one"})]
    destinations = ["replay.test", "second.test"]
    budget = ReplayBudget(max_requests=1, timeout_seconds=0.6, rate_limit_rps=100)
    plan = _plan(requests, destinations, budget, sessions)
    auth_id, approval = _authority(tmp_path, plan)
    if change == "request":
        requests = [replace(requests[0], query_parameters={"changed": "true"})]
    elif change == "credentials":
        sessions = [replace(sessions[0], headers={"Authorization": "Bearer synthetic-two"})]
    elif change == "cookies":
        sessions = [replace(sessions[0], cookies={"session": "synthetic-cookie"})]
    elif change == "session_metadata":
        sessions = [
            replace(
                sessions[0],
                auth_mechanism=replace(sessions[0].auth_mechanism, credential_hash="changed"),
            )
        ]
    elif change == "isolation":
        sessions = [replace(sessions[0], is_isolated="false")]
    elif change == "destinations":
        destinations = ["replay.test", "third.test"]
    else:
        field, value = {
            "requests": ("max_requests", 2),
            "hops": ("max_redirect_hops", 4),
            "timeout": ("timeout_seconds", 0.7),
            "rate": ("rate_limit_rps", 101),
            "frames": ("max_websocket_frames", 11),
        }[change]
        budget = replace(budget, **{field: value})
    resolved = []
    with pytest.raises(ReplayAuthorizationError):
        _execute(
            plan,
            auth_id,
            approval,
            requests,
            destinations,
            budget,
            sessions,
            _scope(lambda h: resolved.append(h) or ["127.0.0.1"]),
        )
    assert resolved == [] and approval.consume_calls == []


def test_caller_mutation_during_approval_consumption_cannot_change_wire_behavior(http_lab, tmp_path):
    base, seen, _ = http_lab
    request = _request(
        f"{base}/200",
        session_id="owner",
        role_id="owner",
        headers={"X-Snapshot": "before"},
        query_parameters={"ordinary": "before"},
    )
    session = SessionContext(
        session_id="owner",
        role_id="owner",
        headers={"Authorization": "Bearer synthetic-before"},
    )
    requests = [request]
    sessions = [session]
    destinations = [base.removeprefix("http://")]
    budget = ReplayBudget(max_requests=1, timeout_seconds=1, rate_limit_rps=0)
    plan = _plan(requests, destinations, budget, sessions)
    auth_id, approval = _authority(tmp_path, plan)
    consume_authorization = approval.consume_authorization

    def mutate_then_consume(authorization_id, action_plan, worker_identity):
        request.headers["X-Snapshot"] = "after"
        request.query_parameters["ordinary"] = "after"
        session.headers["Authorization"] = "Bearer synthetic-after"
        destinations[:] = ["unapproved.test"]
        budget.timeout_seconds = float("nan")
        return consume_authorization(authorization_id, action_plan, worker_identity)

    approval.consume_authorization = mutate_then_consume
    report = _execute(plan, auth_id, approval, requests, destinations, budget, sessions)
    assert report.responses[0].replay_success
    assert report.allowed_destinations == [base.removeprefix("http://")]
    assert report.budget.timeout_seconds == 1
    assert seen[0][0] == "/200?ordinary=before"
    assert seen[0][1]["X-Snapshot"] == "before"
    assert seen[0][1]["Authorization"] == "Bearer synthetic-before"


def test_signed_approval_consumed_once_and_fail_fast_releases_receipt(http_lab, tmp_path):
    base, seen, _ = http_lab
    requests = [_request(f"{base}/drop"), replace(_request(f"{base}/200"), request_id="request-two")]
    destinations = [base.removeprefix("http://")]
    budget = ReplayBudget(max_requests=2, timeout_seconds=1, rate_limit_rps=0)
    plan = _plan(requests, destinations, budget)
    auth_id, approval = _authority(tmp_path, plan)
    report = _execute(plan, auth_id, approval, requests, destinations, budget)
    assert len(seen) == 1 and report.total_dispatched == 1 and report.total_failed == 1
    assert not approval._issued_receipts
    with pytest.raises(Exception, match="consum"):
        _execute(plan, auth_id, approval, requests, destinations, budget)
    assert len(seen) == 1
