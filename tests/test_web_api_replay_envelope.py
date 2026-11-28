"""Closed worker replay envelopes and exact approved dispatch boundaries."""

import ipaddress
import json
import ssl
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import MappingProxyType
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from cops.evidence.canonical import digest
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.laboratory.service_tls import _certificate_material
from cops.web_api.replay import StandardHttpReplayer
from cops.web_api.worker_replay import (
    WEB_API_REPLAY_TOOL,
    WebApiReplayEnvelope,
    WebApiReplayError,
    WebApiReplayMediator,
    validate_web_api_operation,
)
from tests.websocket_testkit import WebSocketTestServer


def envelope_value(*, protocol="http", method="GET", url="https://api.example.test:443/items"):
    request = {
        "request_id": "request-one",
        "protocol": protocol,
        "method": method,
        "url": url,
        "headers": {},
        "body": None,
        "graphql_query": None,
        "graphql_variables": {},
        "websocket_messages": [],
    }
    value = {
        "schema_version": "1",
        "session_id": "session-one",
        "role_id": "reader",
        "request": request,
        "credential_references": [],
        "destination_policy": {
            "transport": "production",
            "request_urls": ["https://api.example.test:443/items"],
        },
        "budgets": {
            "timeout_seconds": 5,
            "rate_limit_rps": 10,
            "max_request_header_bytes": 8192,
            "max_request_body_bytes": 4096,
            "max_response_header_bytes": 8192,
            "max_output_bytes": 16384,
            "max_response_body_bytes": 4096,
            "max_redirect_hops": 0,
            "max_websocket_frames": 10,
            "max_websocket_message_bytes": 1024,
            "max_websocket_bytes": 8192,
        },
    }
    return seal(value)


def seal(value):
    value["request_digest"] = digest(
        {key: value[key] for key in ("session_id", "role_id", "request", "credential_references")}
    )
    return value


def operation(value):
    return {
        "tool": WEB_API_REPLAY_TOOL,
        "tool_version": "1",
        "action": "replay",
        "idempotent": False,
        "arguments": {"envelope": value},
        "egress_policy": {"web_api_replay": value["destination_policy"]},
    }


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
def test_exact_supported_http_methods(method):
    assert WebApiReplayEnvelope.from_dict(envelope_value(method=method)).request["method"] == method


@pytest.mark.parametrize("rate", [True, -1, 1 / 86401, 1000001, float("inf"), float("nan"), "10"])
def test_replay_pacing_budget_rejects_unbound_or_invalid_rate(rate):
    value = envelope_value()
    value["budgets"]["rate_limit_rps"] = rate
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(value)


def test_replay_pacing_budget_is_mandatory():
    value = envelope_value()
    value["budgets"].pop("rate_limit_rps")
    with pytest.raises(WebApiReplayError, match="budget fields"):
        WebApiReplayEnvelope.from_dict(value)


@pytest.mark.parametrize("method", ["CONNECT", "TRACE", "get", "PRI"])
def test_unsupported_methods_fail_closed(method):
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(envelope_value(method=method))


@pytest.mark.parametrize("section", [None, "request", "budgets", "destination_policy"])
def test_unknown_fields_fail_closed(section):
    value = envelope_value()
    (value if section is None else value[section])["unknown"] = True
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(seal(value))


def test_digest_and_original_input_mutation_cannot_change_approved_snapshot():
    value = envelope_value()
    envelope = WebApiReplayEnvelope.from_dict(value)
    value["request"]["method"] = "DELETE"
    assert envelope.request["method"] == "GET"
    copy = envelope.to_dict()
    copy["request"]["url"] = "https://attacker.test/"
    assert envelope.to_dict()["request"]["url"] == "https://api.example.test:443/items"
    with pytest.raises(WebApiReplayError, match="digest"):
        WebApiReplayEnvelope.from_dict(value)


@pytest.mark.parametrize(
    "url", ["http://api.example.test/items", "https://attacker.test/items", "https://api.example.test/other"]
)
def test_exact_origin_target_and_production_tls(url):
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(envelope_value(url=url))


@pytest.mark.parametrize("userinfo", ["@", ":@", "user@", "user:password@"])
def test_url_credentials_including_empty_userinfo_are_rejected(userinfo):
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(envelope_value(url=f"https://{userinfo}api.example.test/items"))


def test_laboratory_plaintext_requires_explicit_loopback_policy():
    value = envelope_value(url="http://127.0.0.1:8123/items")
    value["destination_policy"].update(transport="laboratory", request_urls=[value["request"]["url"]])
    WebApiReplayEnvelope.from_dict(seal(value))
    value["request"]["url"] = "http://api.example.test:80/items"
    value["destination_policy"]["request_urls"] = [value["request"]["url"]]
    with pytest.raises(WebApiReplayError, match="loopback"):
        WebApiReplayEnvelope.from_dict(seal(value))


@pytest.mark.parametrize(
    "urls",
    [
        [],
        ["https://api.example.test:443/items", "https://api.example.test:443/items"],
        ["https://api.example.test:443/final", "https://api.example.test:443/items"],
        ["https://api.example.test:443/items", "https://API.EXAMPLE.TEST:443/final"],
        ["https://api.example.test:443/items", "/final"],
    ],
)
def test_request_urls_require_an_ordered_unique_canonical_initial_wire_url(urls):
    value = envelope_value()
    value["destination_policy"]["request_urls"] = urls
    value["budgets"]["max_redirect_hops"] = 1
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(value)


def test_destination_policy_has_only_transport_and_full_wire_urls():
    value = envelope_value()
    assert set(WebApiReplayEnvelope.from_dict(value).to_dict()["destination_policy"]) == {"transport", "request_urls"}
    for old_field, old_value in (("origin", "https://api.example.test:443"), ("request_targets", ["/items"])):
        broken = deepcopy(value)
        broken["destination_policy"][old_field] = old_value
        with pytest.raises(WebApiReplayError):
            WebApiReplayEnvelope.from_dict(broken)


@pytest.mark.parametrize("header", ["Authorization", "Cookie", "Upgrade", "Connection", "Sec-WebSocket-Extensions"])
def test_direct_credentials_and_transport_headers_rejected(header):
    value = envelope_value()
    value["request"]["headers"][header] = "value"
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(seal(value))


@pytest.mark.parametrize("protocol", ["http", "graphql", "websocket"])
def test_body_budget_covers_wire_graphql_and_websocket(protocol):
    value = envelope_value(protocol=protocol)
    if protocol == "http":
        value["request"]["body"] = "x" * 4097
    elif protocol == "graphql":
        value["request"].update(method="POST", graphql_query="query { item }", graphql_variables={"v": "x" * 4096})
    else:
        value["request"].update(url="wss://api.example.test:443/items", websocket_messages=["x" * 1025])
        value["destination_policy"]["request_urls"] = [value["request"]["url"]]
    with pytest.raises(WebApiReplayError):
        WebApiReplayEnvelope.from_dict(seal(value))


@pytest.mark.parametrize(
    "query", ["subscription { changed }", "query {x} subscription Other { y }", "# comment\nsubscription X { x }"]
)
def test_graphql_subscriptions_are_unsupported(query):
    value = envelope_value(protocol="graphql", method="POST")
    value["request"]["graphql_query"] = query
    with pytest.raises(WebApiReplayError, match="subscription"):
        WebApiReplayEnvelope.from_dict(seal(value))


def test_operation_requires_new_envelope_and_matching_policy():
    value = envelope_value()
    assert validate_web_api_operation(operation(value)).digest == WebApiReplayEnvelope.from_dict(value).digest
    for broken in (
        {**operation(value), "tool": "cops.web_api.standard-http-replayer"},
        {key: item for key, item in operation(value).items() if key != "egress_policy"},
        {**operation(value), "arguments": {"url": "https://api.example.test/items"}},
        {**operation(value), "egress_policy": {"web_api_replay": {}}},
    ):
        with pytest.raises(WebApiReplayError):
            validate_web_api_operation(broken)


def test_operation_requires_explicit_non_idempotent_execution():
    for idempotent in (None, True, 0, "false"):
        candidate = operation(envelope_value())
        if idempotent is None:
            candidate.pop("idempotent")
        else:
            candidate["idempotent"] = idempotent
        with pytest.raises(WebApiReplayError, match="explicitly non-idempotent"):
            validate_web_api_operation(candidate)


def test_mediator_binds_approval_plan_request_and_one_use_before_transport():
    envelope = WebApiReplayEnvelope.from_dict(envelope_value())
    seen = []
    mediator = WebApiReplayMediator(
        scope_guard=None,
        envelope=envelope,
        plan_digest="a" * 64,
        approval_digest="b" * 64,
    )
    mediator._exchange = lambda request, _deadline, _dispatch_observer: seen.append(request) or {"status": 200}
    with pytest.raises(WebApiReplayError):
        mediator.dispatch(envelope.to_dict(), plan_digest="c" * 64, approval_digest="b" * 64)
    assert seen == []
    changed = deepcopy(envelope.to_dict())
    changed["request"]["method"] = "DELETE"
    with pytest.raises(WebApiReplayError):
        mediator.dispatch(seal(changed), plan_digest="a" * 64, approval_digest="b" * 64)
    assert seen == []
    assert mediator.dispatch(envelope.to_dict(), plan_digest="a" * 64, approval_digest="b" * 64)["status"] == 200
    with pytest.raises(WebApiReplayError, match="consumed"):
        mediator.dispatch(envelope.to_dict(), plan_digest="a" * 64, approval_digest="b" * 64)
    assert len(seen) == 1


@contextmanager
def http_laboratory(*, tls_context=None):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.do_POST()

        def do_PUT(self):
            self.do_POST()

        def do_POST(self):
            self.connection.settimeout(2)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append((self.command, self.path, dict(self.headers), body))
            self.server.reply(self)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    server.reply = lambda peer: reply(peer)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        scheme = "https" if tls_context is not None else "http"
        yield f"{scheme}://127.0.0.1:{server.server_port}", seen, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        assert not thread.is_alive()


@pytest.fixture
def bounded_http_lab():
    with http_laboratory() as lab:
        yield lab


@pytest.fixture
def connection_attempts(monkeypatch):
    attempts = []
    connect = StandardHttpReplayer._connect

    def observe_connect(replayer, parsed, deadline):
        attempts.append((parsed.scheme, parsed.hostname, parsed.port))
        return connect(replayer, parsed, deadline)

    monkeypatch.setattr(StandardHttpReplayer, "_connect", observe_connect)
    return attempts


def reply(peer, content=b"ok", *, status=200, headers=None):
    peer.send_response(status)
    for key, value in (headers or {}).items():
        peer.send_header(key, value)
    peer.send_header("Content-Length", str(len(content)))
    peer.end_headers()
    try:
        peer.wfile.write(content)
    except (BrokenPipeError, ConnectionResetError):
        pass


def laboratory_value(url, **options):
    value = envelope_value(url=url, **options)
    value["destination_policy"].update(transport="laboratory", request_urls=[url])
    return seal(value)


def mediator(value, **options):
    scope = ScopeGuard(ScopeDefinition(included_ips={ipaddress.ip_address("127.0.0.1")}, egress_allowed=True))
    return WebApiReplayMediator(
        scope_guard=scope,
        envelope=WebApiReplayEnvelope.from_dict(value),
        plan_digest="a" * 64,
        approval_digest="b" * 64,
        **options,
    )


def dispatch(value, **options):
    return mediator(value, **options).dispatch(value, plan_digest="a" * 64, approval_digest="b" * 64)


def test_immutable_action_plan_containers_are_supported():
    value = envelope_value()
    value["credential_references"] = tuple(value["credential_references"])
    value["destination_policy"] = MappingProxyType(value["destination_policy"])
    assert WebApiReplayEnvelope.from_dict(MappingProxyType(value)).request["method"] == "GET"


def test_real_http_uses_scoped_refs_and_redacts_response_credentials(bounded_http_lab):
    base, seen, server = bounded_http_lab
    # Include JSON escaping in the canary to test reflected serialized credentials.
    secret = 'Bearer local-credential-"\\-canary'
    server.reply = lambda peer: reply(
        peer,
        json.dumps({"reflected": secret}).encode(),
        headers={
            "Set-Cookie": "server-private-canary",
            "X-Reflection": secret,
        },
    )
    value = laboratory_value(base + "/items", method="POST")
    value["request"]["body"] = "approved body"
    value["credential_references"] = [{"reference": "credential-one", "header": "Authorization"}]
    seal(value)
    resolved = []

    def resolve(reference, session, role):
        resolved.append((reference, session, role))
        return secret

    result = dispatch(value, credential_resolver=resolve)
    assert resolved == [("credential-one", "session-one", "reader")]
    assert seen[0][0:2] == ("POST", "/items")
    assert seen[0][2]["Authorization"] == secret
    assert seen[0][3] == b"approved body"
    assert result["status"] == 200 and "[REDACTED]" in result["body"]
    exported = json.dumps(result)
    assert secret not in exported and "local-credential" not in exported
    assert "Set-Cookie" not in result["headers"] and "server-private-canary" not in exported


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_graphql_query_and_variables_reach_only_the_approved_wire_target(bounded_http_lab, method):
    base, seen, _server = bounded_http_lab
    value = laboratory_value(base + "/items", protocol="graphql", method=method)
    value["request"].update(
        graphql_query="query Item($id: ID!) { item(id: $id) { id } }", graphql_variables={"id": "42"}
    )
    if method == "GET":
        query = urlencode({"query": value["request"]["graphql_query"], "variables": '{"id":"42"}'})
        value["destination_policy"]["request_urls"] = [base + "/items?" + query]
    result = dispatch(seal(value))
    assert result["body"] == "ok" and len(seen) == 1
    payload = parse_qs(urlsplit(seen[0][1]).query) if method == "GET" else json.loads(seen[0][3])
    assert payload["query"] == (
        [value["request"]["graphql_query"]] if method == "GET" else value["request"]["graphql_query"]
    )
    assert (json.loads(payload["variables"][0]) if method == "GET" else payload["variables"]) == {"id": "42"}


def assert_redirect_evidence(
    result,
    *,
    initial_url,
    final_url,
    status,
    method_before,
    method_after,
    cross_origin=False,
    body_removed=False,
    credentials_removed=False,
    headers_removed=(),
    secret="redirect-private-canary",
):
    assert result["final_url"] == final_url
    assert result["redirect_count"] == 1
    decisions = result["redirect_decisions"]
    assert len(decisions) == 1
    decision = decisions[0]
    assert set(decision) == {
        "status_code",
        "from_url_digest",
        "to_url_digest",
        "cross_origin",
        "method_before",
        "method_after",
        "body_removed",
        "credentials_removed",
        "headers_removed",
        "decision",
    }
    assert decision["status_code"] == status
    assert decision["method_before"] == method_before
    assert decision["method_after"] == method_after
    assert decision["cross_origin"] is cross_origin
    assert decision["body_removed"] is body_removed
    assert decision["credentials_removed"] is credentials_removed
    removed = decision["headers_removed"]
    assert isinstance(removed, list) and removed == sorted(set(removed))
    assert all(isinstance(name, str) and name == name.lower() for name in removed)
    assert set(headers_removed) <= set(removed)
    if not headers_removed:
        assert removed == []
    assert decision["decision"] == "followed"
    assert decision["from_url_digest"] == digest(initial_url)
    assert decision["to_url_digest"] == digest(final_url)
    assert decision["from_url_digest"] != decision["to_url_digest"]
    exported = json.dumps(decisions)
    for private in (
        initial_url,
        final_url,
        urlsplit(initial_url).netloc,
        urlsplit(final_url).netloc,
        "private-query-canary",
        secret,
        "caller-header-canary",
        "session-header-canary",
    ):
        assert private not in exported


@pytest.mark.parametrize("status", [307, 308])
def test_same_origin_redirect_preserves_method_body_and_credentials(bounded_http_lab, status):
    base, seen, server = bounded_http_lab
    final_url = base + "/final?private-query-canary=1"
    server.reply = lambda peer: (
        reply(peer, status=status, headers={"Location": final_url}) if peer.path == "/items" else reply(peer)
    )
    value = laboratory_value(base + "/items", method="POST")
    value["request"]["body"] = "exact-body"
    value["request"]["headers"] = {"Content-Type": "application/custom", "X-Caller": "caller-header-canary"}
    value["credential_references"] = [{"reference": "credential-one", "header": "Authorization"}]
    value["budgets"]["max_redirect_hops"] = 1
    value["destination_policy"]["request_urls"].append(final_url)
    result = dispatch(seal(value), credential_resolver=lambda *_args: "redirect-private-canary")
    assert [(method, target, body) for method, target, _headers, body in seen] == [
        ("POST", "/items", b"exact-body"),
        ("POST", "/final?private-query-canary=1", b"exact-body"),
    ]
    assert all(headers["Authorization"] == "redirect-private-canary" for _method, _target, headers, _body in seen)
    assert all(headers["Content-Type"] == "application/custom" for _method, _target, headers, _body in seen)
    assert_redirect_evidence(
        result,
        initial_url=base + "/items",
        final_url=final_url,
        status=status,
        method_before="POST",
        method_after="POST",
    )


@pytest.mark.parametrize("status,method", [(301, "POST"), (302, "POST"), (303, "POST"), (303, "PUT")])
def test_same_origin_body_removing_redirect_strips_content_headers(bounded_http_lab, status, method):
    base, seen, server = bounded_http_lab
    server.reply = lambda peer: (
        reply(peer, status=status, headers={"Location": "/final"}) if peer.path == "/items" else reply(peer)
    )
    value = laboratory_value(base + "/items", method=method)
    value["request"].update(
        body="exact-body",
        headers={
            "Content-Type": "application/custom",
            "Content-Language": "en",
            "X-Caller": "caller-header-canary",
        },
    )
    value["credential_references"] = [{"reference": "credential-one", "header": "Authorization"}]
    value["budgets"]["max_redirect_hops"] = 1
    value["destination_policy"]["request_urls"].append(base + "/final")
    result = dispatch(seal(value), credential_resolver=lambda *_args: "redirect-private-canary")
    assert [(item[0], item[1], item[3]) for item in seen] == [(method, "/items", b"exact-body"), ("GET", "/final", b"")]
    headers = {name.lower(): item for name, item in seen[1][2].items()}
    assert not any(name.startswith("content-") for name in headers)
    assert headers["authorization"] == "redirect-private-canary"
    assert headers["x-caller"] == "caller-header-canary"
    assert_redirect_evidence(
        result,
        initial_url=base + "/items",
        final_url=base + "/final",
        status=status,
        method_before=method,
        method_after="GET",
        body_removed=True,
        headers_removed=("content-type", "content-language"),
    )


@pytest.mark.parametrize("status", [301, 302, 303])
def test_cross_origin_rewrite_uses_fresh_destination_without_any_caller_headers(
    bounded_http_lab, connection_attempts, status
):
    base, seen, server = bounded_http_lab
    with http_laboratory() as (other_base, other_seen, _other_server):
        final_url = other_base + "/final?private-query-canary=1"
        server.reply = lambda peer: reply(peer, status=status, headers={"Location": final_url})
        value = laboratory_value(base + "/items", method="POST")
        value["request"].update(
            body="exact-body",
            headers={
                "Content-Type": "application/custom",
                "X-Caller": "caller-header-canary",
            },
        )
        value["credential_references"] = [
            {"reference": "credential-one", "header": "Authorization"},
            {"reference": "credential-two", "header": "Cookie"},
            {"reference": "credential-three", "header": "X-Session"},
        ]
        value["budgets"]["max_redirect_hops"] = 1
        value["destination_policy"]["request_urls"].append(final_url)
        result = dispatch(
            seal(value),
            credential_resolver=lambda reference, *_args: (
                "session-header-canary" if reference == "credential-three" else "redirect-private-canary"
            ),
        )
        assert len(seen) == len(other_seen) == 1
        assert seen[0][0] == "POST" and seen[0][3] == b"exact-body"
        assert seen[0][2]["Authorization"] == seen[0][2]["Cookie"] == "redirect-private-canary"
        assert seen[0][2]["X-Session"] == "session-header-canary"
        method, target, headers, body = other_seen[0]
        assert (method, target, body) == ("GET", "/final?private-query-canary=1", b"")
        assert headers["Host"] == urlsplit(other_base).netloc
        assert set(name.lower() for name in headers) <= {"host", "connection"}
        assert connection_attempts == [
            ("http", "127.0.0.1", urlsplit(base).port),
            ("http", "127.0.0.1", urlsplit(other_base).port),
        ]
        assert_redirect_evidence(
            result,
            initial_url=base + "/items",
            final_url=final_url,
            status=status,
            method_before="POST",
            method_after="GET",
            cross_origin=True,
            body_removed=True,
            credentials_removed=True,
            headers_removed=("authorization", "cookie", "content-type", "x-caller", "x-session"),
        )


def test_cross_origin_benign_header_removal_is_not_credential_removal(
    bounded_http_lab,
    connection_attempts,
):
    base, seen, server = bounded_http_lab
    with http_laboratory() as (other_base, other_seen, _other_server):
        final_url = other_base + "/final"
        server.reply = lambda peer: reply(peer, status=302, headers={"Location": final_url})
        value = laboratory_value(base + "/items")
        value["request"]["headers"] = {"X-Caller": "caller-header-canary"}
        value["budgets"]["max_redirect_hops"] = 1
        value["destination_policy"]["request_urls"].append(final_url)

        result = dispatch(seal(value))

        assert len(seen) == len(other_seen) == 1
        method, target, headers, body = other_seen[0]
        assert (method, target, body) == ("GET", "/final", b"")
        assert set(name.lower() for name in headers) <= {"host", "connection"}
        assert connection_attempts == [
            ("http", "127.0.0.1", urlsplit(base).port),
            ("http", "127.0.0.1", urlsplit(other_base).port),
        ]
        assert_redirect_evidence(
            result,
            initial_url=base + "/items",
            final_url=final_url,
            status=302,
            method_before="GET",
            method_after="GET",
            cross_origin=True,
            credentials_removed=False,
            headers_removed=("x-caller",),
        )


@pytest.mark.parametrize("status", [307, 308])
def test_cross_origin_body_preserving_redirect_is_rejected_before_second_connection(
    bounded_http_lab, connection_attempts, status
):
    base, seen, server = bounded_http_lab
    with http_laboratory() as (other_base, other_seen, _other_server):
        server.reply = lambda peer: reply(peer, status=status, headers={"Location": other_base + "/final"})
        value = laboratory_value(base + "/items", method="POST")
        value["request"]["body"] = "exact-body"
        value["budgets"]["max_redirect_hops"] = 1
        value["destination_policy"]["request_urls"].append(other_base + "/final")
        with pytest.raises(WebApiReplayError):
            dispatch(seal(value))
        assert len(seen) == 1 and other_seen == []
        assert connection_attempts == [("http", "127.0.0.1", urlsplit(base).port)]


@pytest.mark.parametrize("target", ["/unapproved", "http://attacker.test:80/items", "/third"])
def test_unapproved_or_reordered_redirect_never_connects_again(bounded_http_lab, connection_attempts, target):
    base, seen, server = bounded_http_lab
    server.reply = lambda peer: reply(peer, status=307, headers={"Location": target})
    value = laboratory_value(base + "/items")
    value["budgets"]["max_redirect_hops"] = 2
    value["destination_policy"]["request_urls"].extend([base + "/final", base + "/third"])
    with pytest.raises(WebApiReplayError):
        dispatch(seal(value))
    assert len(seen) == 1
    assert connection_attempts == [("http", "127.0.0.1", urlsplit(base).port)]


def test_tls_redirect_never_downgrades_to_plaintext(tmp_path, connection_attempts):
    material = _certificate_material(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(material["server_cert"], material["server_key"])
    client_context = ssl.create_default_context(cafile=material["ca"])
    with (
        http_laboratory(tls_context=server_context) as (base, seen, server),
        http_laboratory() as (other_base, other_seen, _other_server),
    ):
        server.reply = lambda peer: reply(peer, status=303, headers={"Location": other_base + "/final"})
        value = laboratory_value(base + "/items", method="POST")
        value["request"]["body"] = "exact-body"
        value["budgets"]["max_redirect_hops"] = 1
        value["destination_policy"]["request_urls"].append(other_base + "/final")
        with pytest.raises(WebApiReplayError):
            dispatch(seal(value), tls_context=client_context)
        assert len(seen) <= 1 and other_seen == []
        assert all(scheme == "https" and port == urlsplit(base).port for scheme, _host, port in connection_attempts)


@pytest.mark.parametrize("overflow", ["body", "headers", "output", "compression", "upgrade"])
def test_peer_response_cannot_expand_approved_contract(bounded_http_lab, overflow):
    base, seen, server = bounded_http_lab
    value = laboratory_value(base + "/items")
    if overflow == "body":
        value["budgets"]["max_response_body_bytes"] = 1
    elif overflow == "headers":
        value["budgets"]["max_response_header_bytes"] = 20
    elif overflow == "output":
        value["budgets"].update(max_response_body_bytes=2, max_output_bytes=2)
    elif overflow == "compression":
        server.reply = lambda peer: reply(peer, headers={"Content-Encoding": "gzip"})
    else:
        server.reply = lambda peer: reply(peer, status=101, headers={"Upgrade": "unrestricted"})
    with pytest.raises(WebApiReplayError):
        dispatch(value)
    assert len(seen) == 1


@pytest.mark.parametrize("source", ["resolver", "peer"])
def test_error_messages_do_not_export_resolver_or_peer_credentials(bounded_http_lab, source):
    base, seen, server = bounded_http_lab
    secret = "private-error-canary"
    value = laboratory_value(base + "/items")
    value["credential_references"] = [{"reference": "credential-one", "header": "Authorization"}]

    def resolver(*_args):
        if source == "resolver":
            raise WebApiReplayError(secret)
        return secret

    server.reply = lambda peer: peer.wfile.write(f"{secret}\r\n\r\n".encode())
    with pytest.raises(WebApiReplayError) as captured:
        dispatch(seal(value), credential_resolver=resolver)
    assert secret not in str(captured.value)
    assert captured.value.__suppress_context__
    assert len(seen) == (0 if source == "resolver" else 1)


@pytest.mark.parametrize("mode", ["binary", "fragment", "rsv", "extension", "subprotocol", "huge-length", "flood"])
def test_real_websocket_rejects_unapproved_features_and_transcript_overflow(mode):
    with WebSocketTestServer(mode=mode) as lab:
        value = laboratory_value(lab.url, protocol="websocket")
        value["request"]["websocket_messages"] = ["hello"]
        with pytest.raises(WebApiReplayError):
            dispatch(seal(value))
        assert lab.closed.wait(1)


def test_real_websocket_text_exchange_is_bounded_and_sanitized():
    with WebSocketTestServer() as lab:
        value = laboratory_value(lab.url, protocol="websocket")
        value["request"]["websocket_messages"] = ["private-text-canary"]
        result = dispatch(seal(value))
        assert result["status_code"] == 101 and result["replay_success"]
        assert lab.messages == [(None, "private-text-canary")]
        assert "private-text-canary" not in json.dumps(result)
        assert lab.closed.wait(1)


def test_dispatch_absolute_timeout_stops_late_credential_resolution_without_connecting(bounded_http_lab):
    base, seen, _server = bounded_http_lab
    value = laboratory_value(base + "/items")
    value["budgets"]["timeout_seconds"] = 0.05
    value["credential_references"] = [{"reference": "credential-one", "header": "Authorization"}]
    finished = threading.Event()

    def slow_resolver(*_args):
        time.sleep(0.15)
        finished.set()
        return "late-private-canary"

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        dispatch(seal(value), credential_resolver=slow_resolver)
    assert time.monotonic() - started < 0.12
    assert finished.wait(1) and seen == []
