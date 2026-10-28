"""Bounded WebSocket replay reuses approval, scope and privacy boundaries."""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import sys
import threading
import time
import traceback
from dataclasses import replace

import pytest

from cops.evidence.canonical import digest
from cops.execution.cleanup import CleanupPersistenceError
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard, ScopeViolationError
from cops.laboratory.service_tls import _certificate_material
from cops.web_api.models import ReplayBudget, ReplayRequest, ReplayResponse, SessionContext
from cops.web_api.replay import (
    DestinationGuard,
    ReplayAuthorizationError,
    ReplayBudgetExceededError,
    StandardHttpReplayer,
    build_replay_action_plan,
    execute_authorized_replay_session,
)
from cops.web_api.worker_replay import WEB_API_REPLAY_TOOL, WEB_API_REPLAY_VERSION, validate_web_api_operation
from tests.web_api_worker_testkit import loopback_worker
from tests.websocket_testkit import WebSocketTestServer


def request(**changes):
    return replace(
        ReplayRequest(
            "ws-one",
            "ws-endpoint",
            "GET",
            "wss://example.test/socket",
            protocol="websocket",
            websocket_messages=["hello"],
        ),
        **changes,
    )


def plan(req=None, budget=None):
    return build_replay_action_plan(
        plan_id="plan-websocket",
        engagement_id="eng-websocket",
        scenario_id="scen-websocket",
        specialist_id="web-api-assessment-workbench",
        requests=[req or request()],
        allowed_destinations=["example.test"],
        budget=budget or ReplayBudget(),
        created_at="2026-10-25T00:00:00Z",
    )


def test_websocket_plan_uses_registered_worker_envelope():
    operation = plan().operations[0]
    assert operation["tool"] == WEB_API_REPLAY_TOOL
    assert operation["tool_version"] == WEB_API_REPLAY_VERSION
    assert operation["action"] == "replay"
    envelope = validate_web_api_operation(operation).to_dict()
    assert envelope["request"]["protocol"] == "websocket"
    assert envelope["request"]["websocket_messages"] == ["hello"]
    assert envelope["destination_policy"] == {
        "transport": "production",
        "request_urls": ["wss://example.test/socket"],
    }
    assert envelope["request_digest"] == digest(
        {
            key: envelope[key]
            for key in (
                "session_id",
                "role_id",
                "request",
                "credential_references",
            )
        }
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "POST"},
        {"url": "https://example.test/socket"},
        {"body": "payload"},
        {"headers": {"Sec-WebSocket-Protocol": "unapproved"}},
        {"headers": {"Sec-WebSocket-Extensions": "permessage-deflate"}},
        {"websocket_messages": [b"binary"]},
        {"websocket_messages": ["\ud800"]},
    ],
)
def test_unsupported_request_fails_before_plan(changes):
    with pytest.raises(ReplayAuthorizationError):
        plan(request(**changes))


def test_known_frame_count_and_message_bytes_reject_without_truncation():
    with pytest.raises(ReplayBudgetExceededError):
        plan(request(websocket_messages=["a", "b"]), ReplayBudget(max_websocket_frames=5))
    with pytest.raises(ReplayBudgetExceededError):
        plan(request(websocket_messages=["x" * 65537]))


def test_explicit_byte_budgets_are_approval_bound():
    first = plan()
    second = plan(budget=ReplayBudget(max_websocket_bytes=4096))
    assert first.plan_digest != second.plan_digest


def scope(resolver=None):
    return ScopeGuard(
        ScopeDefinition(
            included_ips={ipaddress.ip_address("127.0.0.1")}, included_domains={"example.test"}, egress_allowed=True
        ),
        resolver=resolver,
    )


def transport(lab, **options):
    return StandardHttpReplayer(DestinationGuard([lab.url.split("/")[2]]), scope(), **options)


def assert_workers_stop(prior_threads):
    # The call has a bounded cleanup join; verify eventual thread exit separately
    # from call latency, rather than assuming immediate scheduler teardown.
    owned = [t for t in set(threading.enumerate()) - prior_threads if t.name == "cops-api-replay"]
    for worker in owned:
        worker.join(timeout=1)
    remaining = [worker for worker in owned if worker.is_alive()]
    assert not remaining, ["".join(traceback.format_stack(sys._current_frames()[t.ident])) for t in remaining]


def test_actual_masked_text_ping_pong_close_and_payload_redaction(monkeypatch):
    from cops.web_api import websocket

    random_sizes = []
    original = websocket.secrets.token_bytes

    def random_bytes(size):
        random_sizes.append(size)
        return original(size)

    monkeypatch.setattr(websocket.secrets, "token_bytes", random_bytes)
    with WebSocketTestServer(mode="ping") as lab:
        req = request(url=lab.url, websocket_messages=["payload-private-canary"])
        result = transport(lab).send(req, ReplayBudget())
        assert result.replay_success, result.error_message
        assert result.status_code == 101 and result.websocket_replies == ["echo:payload-private-canary"]
        assert result.websocket_metrics == {
            "frames_sent": 3,
            "frames_received": 4,
            "bytes_sent": 6 + 22 + 6 + 14 + 8,
            "bytes_received": 2 + 14 + 2 + 11 + 2 + 27 + 4,
            "close_code": 1000,
        }
        assert [opcode for opcode, _, _ in lab.client_frames] == [1, 10, 8]
        assert lab.client_frames[1][1] == b"control-canary"
        assert all(len(mask) == 4 for _, _, mask in lab.client_frames)
        assert random_sizes == [16, 4, 4, 4]
        saved = json.dumps(result.to_dict())
        assert "payload-private-canary" not in saved and "server-private-canary" not in saved
        assert "control-canary" not in saved
        assert lab.closed.wait(1)


@pytest.mark.parametrize("mode", ["redirect", "bad-accept", "large-handshake", "extension", "subprotocol", "duplicate"])
def test_handshake_rejections_never_send_application_messages(mode):
    with WebSocketTestServer(mode=mode) as lab:
        result = transport(lab).send(request(url=lab.url), ReplayBudget(timeout_seconds=1))
        assert not result.replay_success
        assert not lab.messages
        assert len(lab.handshakes) == 1


@pytest.mark.parametrize(
    "mode",
    [
        "binary",
        "fragment",
        "rsv",
        "masked-server",
        "utf8",
        "huge-length",
        "noncanonical",
        "oversized-ping",
        "early-close",
        "flood",
        "extra-data",
        "bad-close",
        "invalid-close-code",
        "invalid-close-reason",
        "abnormal-close",
    ],
)
def test_invalid_frames_and_incomplete_exchange_are_not_success(mode):
    with WebSocketTestServer(mode=mode) as lab:
        result = transport(lab).send(request(url=lab.url), ReplayBudget(timeout_seconds=1))
        assert not result.replay_success, mode
        metrics = result.websocket_metrics
        assert metrics["frames_sent"] + metrics["frames_received"] <= 10
        assert metrics["bytes_sent"] + metrics["bytes_received"] <= 1048576
        assert lab.closed.wait(1)


@pytest.mark.parametrize("size", [0, 125, 126, 65531])
def test_supported_text_size_boundaries(size):
    with WebSocketTestServer() as lab:
        result = transport(lab).send(
            request(url=lab.url, websocket_messages=["x" * size]), ReplayBudget(timeout_seconds=2)
        )
        assert result.replay_success, result.error_message
        assert result.websocket_replies == ["echo:" + "x" * size]


def test_incoming_message_limit_checked_before_payload_is_read():
    with WebSocketTestServer(mode="huge-length") as lab:
        result = transport(lab).send(request(url=lab.url), ReplayBudget(timeout_seconds=1))
        assert not result.replay_success and result.error_message == "WebSocketBudgetError"
        assert result.websocket_metrics["bytes_received"] == 10


def test_exact_frame_and_encoded_byte_budget_and_one_byte_short():
    # Client 'hello': 11 bytes, peer 'echo:hello': 12, close: 8+4.
    with WebSocketTestServer() as lab:
        result = transport(lab).send(request(url=lab.url), ReplayBudget(max_websocket_frames=4, max_websocket_bytes=35))
        assert result.replay_success
    with WebSocketTestServer() as lab:
        result = transport(lab).send(request(url=lab.url), ReplayBudget(max_websocket_frames=4, max_websocket_bytes=34))
        assert not result.replay_success and result.websocket_replies == ["echo:hello"]
        assert result.error_message == "WebSocketBudgetError"


def test_empty_message_list_does_not_invent_an_application_payload():
    with WebSocketTestServer() as lab:
        result = transport(lab).send(request(url=lab.url, websocket_messages=[]), ReplayBudget(max_websocket_frames=2))
        assert result.replay_success and not lab.messages
        assert [opcode for opcode, _, _ in lab.client_frames] == [8]


def test_one_dns_resolution_and_no_proxy_or_second_lookup(monkeypatch):
    with WebSocketTestServer() as lab:
        port = lab.url.split(":")[2].split("/")[0]
        answers = []
        guard = scope(lambda host: answers.append(host) or ["127.0.0.1"])

        def forbidden(*args, **kwargs):
            raise AssertionError("second DNS lookup")

        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        monkeypatch.setenv("ALL_PROXY", "http://unapproved.test:9999")
        url = f"ws://example.test:{port}/socket"
        result = StandardHttpReplayer(DestinationGuard([f"example.test:{port}"]), guard).send(
            request(url=url), ReplayBudget()
        )
        assert result.replay_success and answers == ["example.test"]
        assert lab.handshakes[0][1]["host"] == f"example.test:{port}"


def test_scope_rejection_precedes_handshake():
    with WebSocketTestServer() as lab:
        replayer = StandardHttpReplayer(DestinationGuard([lab.url.split("/")[2]]), ScopeGuard(ScopeDefinition()))
        with pytest.raises(ScopeViolationError):
            replayer.send(request(url=lab.url), ReplayBudget())
        assert not lab.handshakes


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_or_cancellation_closes_socket_and_worker(cancel):
    prior_threads = set(threading.enumerate())
    with WebSocketTestServer(mode="stall") as lab:
        event = threading.Event()
        timer = None
        if cancel:

            def cancel_after_message():
                if lab.message_received.wait(1):
                    event.set()

            timer = threading.Thread(target=cancel_after_message)
            timer.start()
        started = time.monotonic()
        result = transport(lab).send(
            request(url=lab.url), ReplayBudget(timeout_seconds=1 if cancel else 0.08), cancellation_event=event
        )
        assert time.monotonic() - started < 0.6
        assert not result.replay_success
        assert result.error_message == ("ReplayCancelledError" if cancel else "TimeoutError")
        assert lab.closed.wait(1)
        if timer:
            timer.join(timeout=1)
        assert_workers_stop(prior_threads)


@pytest.mark.parametrize("trusted,hostname", [(True, "127.0.0.1"), (False, "127.0.0.1"), (True, "example.test")])
def test_wss_verifies_chain_original_hostname_and_tls_policy(tmp_path, trusted, hostname):
    material = _certificate_material(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(material["server_cert"], material["server_key"])
    client_context = ssl.create_default_context(cafile=material["ca"] if trusted else None)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    with WebSocketTestServer(tls_context=server_context) as lab:
        port = lab.url.split(":")[2].split("/")[0]
        guard = ScopeGuard(
            ScopeDefinition(
                included_ips={ipaddress.ip_address("127.0.0.1")}, included_domains={hostname}, egress_allowed=True
            ),
            resolver=lambda host: ["127.0.0.1"],
        )
        result = StandardHttpReplayer(DestinationGuard([f"{hostname}:{port}"]), guard, tls_context=client_context).send(
            request(url=f"wss://{hostname}:{port}/socket"), ReplayBudget(timeout_seconds=1)
        )
        assert result.replay_success is (trusted and hostname == "127.0.0.1")
        assert bool(lab.handshakes) is result.replay_success


def execute(lab, requests, budget, action_plan, auth_id, control, sessions=None, *, worker, **kwargs):
    active_scope = kwargs.pop("scope_guard", worker.scope_guard)
    return execute_authorized_replay_session(
        requests=requests,
        sessions=sessions or [],
        allowed_destinations=[lab.url.split("/")[2]],
        scope_guard=active_scope,
        budget=budget,
        action_plan=action_plan,
        authorization_id=auth_id,
        approval_control=control,
        worker_identity=worker.config.worker_id,
        worker=worker,
        transport="laboratory",
        **kwargs,
    )


def live_plan(lab, requests, budget, sessions=None):
    return build_replay_action_plan(
        plan_id="plan-websocket",
        engagement_id="eng-websocket",
        scenario_id="scen-websocket",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        allowed_destinations=[lab.url.split("/")[2]],
        budget=budget,
        sessions=sessions or [],
        transport="laboratory",
    )


@pytest.mark.parametrize("mutation", ["messages", "protocol", "frames", "bytes", "message_bytes", "session", "url"])
def test_plan_drift_rejected_before_consumption_or_dispatch(tmp_path, monkeypatch, mutation):
    with WebSocketTestServer() as lab:
        sessions = [SessionContext(session_id="session-one", role_id="owner", headers={"X-Replay-Variant": "owner"})]
        requests = [request(url=lab.url, session_id="session-one", role_id="owner")]
        budget = ReplayBudget()
        action_plan = live_plan(lab, requests, budget, sessions)
        worker, auth_id, control = loopback_worker(tmp_path, monkeypatch, action_plan, scope())
        if mutation == "messages":
            requests[0].websocket_messages = ["different"]
        elif mutation == "protocol":
            requests[0].protocol = "http"
        elif mutation == "frames":
            budget.max_websocket_frames += 1
        elif mutation == "bytes":
            budget.max_websocket_bytes = 4096
        elif mutation == "message_bytes":
            budget.max_websocket_message_bytes = 2048
        elif mutation == "session":
            sessions[0].headers["X-Replay-Variant"] = "changed-owner"
        else:
            requests[0].url += "?changed=yes"
        with pytest.raises(ReplayAuthorizationError):
            execute(lab, requests, budget, action_plan, auth_id, control, sessions, worker=worker)
        assert control.consume_calls == [] and not lab.handshakes


def test_inputs_are_frozen_during_consumption_and_approval_is_single_use(tmp_path, monkeypatch):
    with WebSocketTestServer() as lab:
        requests, budget = [request(url=lab.url)], ReplayBudget()
        action_plan = live_plan(lab, requests, budget)
        worker, auth_id, control = loopback_worker(tmp_path, monkeypatch, action_plan, scope())
        original = control.consume_authorization

        def consume(*args):
            requests[0].websocket_messages.append("unapproved-canary")
            budget.max_websocket_bytes = 1
            return original(*args)

        monkeypatch.setattr(control, "consume_authorization", consume)
        report = execute(lab, requests, budget, action_plan, auth_id, control, worker=worker)
        assert report.responses[0].replay_success
        assert lab.messages == [(None, "hello")]
        assert not control._issued_receipts
        assert control.store.get_authorization(auth_id).status == "consumed"
        monkeypatch.setattr(control, "consume_authorization", original)
        with pytest.raises(CleanupPersistenceError, match="already contains execution run"):
            execute(
                lab,
                [request(url=lab.url)],
                ReplayBudget(),
                action_plan,
                auth_id,
                control,
                worker=worker,
            )
        assert len(control.consume_calls) == 1 and len(lab.handshakes) == 1


def test_cancel_before_approval_has_no_dispatch_or_consumption(tmp_path, monkeypatch):
    with WebSocketTestServer() as lab:
        requests, budget = [request(url=lab.url)], ReplayBudget()
        action_plan = live_plan(lab, requests, budget)
        worker, auth_id, control = loopback_worker(tmp_path, monkeypatch, action_plan, scope())
        event = threading.Event()
        event.set()
        with pytest.raises(ReplayAuthorizationError, match="cancelled"):
            execute(
                lab,
                requests,
                budget,
                action_plan,
                auth_id,
                control,
                worker=worker,
                cancellation_event=event,
            )
        assert not control.consume_calls and not lab.handshakes


def test_failed_exchange_stops_batch_and_releases_consumed_receipt(tmp_path, monkeypatch):
    with WebSocketTestServer(mode="binary") as lab:
        requests = [request(url=lab.url), request(url=lab.url, request_id="ws-two")]
        budget = ReplayBudget()
        action_plan = live_plan(lab, requests, budget)
        worker, auth_id, control = loopback_worker(tmp_path, monkeypatch, action_plan, scope())
        report = execute(lab, requests, budget, action_plan, auth_id, control, worker=worker)
        assert len(report.responses) == 1 and not report.responses[0].replay_success
        assert len(lab.handshakes) == 1 and not control._issued_receipts
        # Recovery requires a fresh plan/approval, not a retry of the consumed grant.
        with pytest.raises(CleanupPersistenceError, match="already contains execution run"):
            execute(lab, requests, budget, action_plan, auth_id, control, worker=worker)
        assert len(control.consume_calls) == 1 and len(lab.handshakes) == 1


def test_http_plan_uses_same_worker_contract_and_explicit_byte_budgets():
    req = request(url="https://example.test/", protocol="http", websocket_messages=[])
    budget = ReplayBudget()
    operation = plan(req, budget).operations[0]
    assert operation["tool"] == WEB_API_REPLAY_TOOL
    assert operation["tool_version"] == WEB_API_REPLAY_VERSION and operation["action"] == "replay"
    envelope = validate_web_api_operation(operation).to_dict()
    assert envelope["request"]["protocol"] == "http"
    assert envelope["budgets"]["timeout_seconds"] == budget.timeout_seconds
    assert envelope["budgets"]["max_websocket_bytes"] == budget.max_websocket_bytes
    assert envelope["budgets"]["max_websocket_message_bytes"] == budget.max_websocket_message_bytes
    assert envelope["destination_policy"] == {
        "transport": "production",
        "request_urls": ["https://example.test/"],
    }


@pytest.mark.parametrize(
    "name,value",
    [
        ("max_websocket_bytes", True),
        ("max_websocket_bytes", 1048577),
        ("max_websocket_message_bytes", 0),
        ("max_websocket_message_bytes", 65537),
    ],
)
def test_invalid_byte_budgets_fail_before_plan(name, value):
    budget = ReplayBudget()
    setattr(budget, name, value)
    with pytest.raises(ReplayBudgetExceededError):
        plan(budget=budget)


def test_cancelled_approved_exchange_releases_receipt_and_recovers_with_fresh_approval(tmp_path, monkeypatch):
    with WebSocketTestServer(mode="stall") as lab:
        requests, budget = [request(url=lab.url)], ReplayBudget()
        action_plan = live_plan(lab, requests, budget)
        worker, auth_id, control = loopback_worker(tmp_path / "first", monkeypatch, action_plan, scope())
        event = threading.Event()

        def cancel():
            if lab.message_received.wait(1):
                event.set()

        operator = threading.Thread(target=cancel)
        operator.start()
        report = execute(
            lab,
            requests,
            budget,
            action_plan,
            auth_id,
            control,
            worker=worker,
            cancellation_event=event,
        )
        operator.join(timeout=1)
        assert not report.responses[0].replay_success and not control._issued_receipts
        assert lab.closed.wait(1)
        lab.mode = "echo"
        fresh = live_plan(lab, requests, budget)
        fresh_worker, fresh_id, fresh_control = loopback_worker(
            tmp_path / "recovery",
            monkeypatch,
            fresh,
            scope(),
        )
        recovered = execute(
            lab,
            requests,
            budget,
            fresh,
            fresh_id,
            fresh_control,
            worker=fresh_worker,
        )
        assert recovered.responses[0].replay_success and not fresh_control._issued_receipts
        assert len(lab.handshakes) == 2


def test_late_dns_after_websocket_timeout_cannot_create_a_socket(monkeypatch):
    with WebSocketTestServer() as lab:
        release = threading.Event()
        started = threading.Event()
        before = set(threading.enumerate())

        def resolve(host):
            started.set()
            assert release.wait(1)
            return ["127.0.0.1"]

        port = lab.url.split(":")[2].split("/")[0]
        replayer = StandardHttpReplayer(DestinationGuard([f"example.test:{port}"]), scope(resolve))
        created = []
        original = socket.socket

        def socket_factory(*args, **kwargs):
            created.append(True)
            return original(*args, **kwargs)

        monkeypatch.setattr(socket, "socket", socket_factory)
        now = time.monotonic()
        result = replayer.send(request(url=f"ws://example.test:{port}/socket"), ReplayBudget(timeout_seconds=0.04))
        assert time.monotonic() - now < 0.15
        assert started.is_set() and not result.replay_success
        release.set()
        for worker in set(threading.enumerate()) - before:
            if worker.name == "cops-api-replay":
                worker.join(timeout=1)
        assert not created and not lab.handshakes


def test_preview_exposes_byte_limits_without_network_or_side_effects(monkeypatch):
    from cops.web_api.replay import preview_replay_session

    def forbidden(*args, **kwargs):
        raise AssertionError("preview attempted network activity")

    monkeypatch.setattr(socket, "socket", forbidden)
    result = preview_replay_session([request()], ["example.test"])
    assert result.total_dispatched == 0
    assert result.to_dict()["budget"]["max_websocket_bytes"] == 1048576
    assert result.to_dict()["budget"]["max_websocket_message_bytes"] == 65536


def test_oversized_request_headers_and_hostile_query_fail_before_plan():
    class Hostile:
        def __str__(self):
            raise AssertionError("preflight rendered hostile query")

    with pytest.raises(ReplayAuthorizationError):
        plan(request(headers={"X-Large": "x" * 8192}))
    with pytest.raises(ReplayAuthorizationError):
        plan(request(query_parameters={"unsafe": Hostile()}))


@pytest.mark.parametrize("payload", ["x" * 65536, "\U0001f600" * 16384])
def test_exact_maximum_utf8_message_uses_valid_extended_lengths(payload):
    with WebSocketTestServer(mode="identity") as lab:
        result = transport(lab).send(
            request(url=lab.url, websocket_messages=[payload]), ReplayBudget(timeout_seconds=2)
        )
        assert result.replay_success and result.websocket_replies == [payload]
        assert result.websocket_metrics["bytes_sent"] == 65536 + 14 + 8


def test_partial_frame_timeout_retains_no_invented_reply_and_cleans_up():
    with WebSocketTestServer(mode="partial-frame") as lab:
        result = transport(lab).send(request(url=lab.url), ReplayBudget(timeout_seconds=0.08))
        assert not result.replay_success and result.error_message == "TimeoutError"
        assert not result.websocket_replies and lab.closed.wait(1)


@pytest.mark.parametrize("protocol", ["http", "websocket"])
@pytest.mark.parametrize("stop", ["cancellation", "timeout"])
def test_tls_shutdown_preserves_worker_owned_ssl_state_and_descriptor(protocol, stop):
    unsafe_mutations = []

    class WorkerOwnedSSLSocket(ssl.SSLSocket):
        def shutdown(self, how):
            if threading.current_thread().name != "cops-api-replay":
                unsafe_mutations.append("SSL shutdown outside worker")
            return super().shutdown(how)

        def close(self):
            if threading.current_thread().name != "cops-api-replay":
                unsafe_mutations.append("descriptor close outside worker")
            return super().close()

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.sslsocket_class = WorkerOwnedSSLSocket
    before = set(threading.enumerate())
    with WebSocketTestServer(mode="tls-stall") as lab:
        event = threading.Event()

        def cancel():
            if lab.connected.wait(1):
                event.set()

        operator = threading.Thread(target=cancel)
        if stop == "cancellation":
            operator.start()
        scheme = "https://" if protocol == "http" else "wss://"
        req = request(url=lab.url.replace("ws://", scheme), protocol=protocol)
        started = time.monotonic()
        result = transport(lab, tls_context=context).send(
            req,
            ReplayBudget(timeout_seconds=2 if stop == "cancellation" else 0.1),
            cancellation_event=event,
        )
        if stop == "cancellation":
            operator.join(timeout=1)
            assert not operator.is_alive()
        assert time.monotonic() - started < 0.6
        assert lab.connected.is_set() and not lab.handshakes and not lab.messages
        assert not result.replay_success
        assert result.error_message == ("ReplayCancelledError" if stop == "cancellation" else "TimeoutError")
        assert not unsafe_mutations
        assert lab.closed.wait(1)
        assert_workers_stop(before)


@pytest.mark.parametrize("mode", ["tls-stall", "handshake-stall"])
def test_cancellation_interrupts_tls_and_http_handshake_owned_socket(mode):
    before = set(threading.enumerate())
    with WebSocketTestServer(mode=mode) as lab:
        event = threading.Event()

        def cancel():
            if lab.connected.wait(1):
                event.set()

        operator = threading.Thread(target=cancel)
        operator.start()
        url = lab.url.replace("ws://", "wss://") if mode == "tls-stall" else lab.url
        started = time.monotonic()
        result = transport(lab).send(request(url=url), ReplayBudget(timeout_seconds=2), cancellation_event=event)
        operator.join(timeout=1)
        assert time.monotonic() - started < 0.6
        assert not result.replay_success and result.error_message == "ReplayCancelledError"
        assert not lab.messages and lab.closed.wait(1)
        assert_workers_stop(before)


@pytest.mark.parametrize(
    "metrics",
    [
        {"close_code": 1005},
        {"close_code": True},
        {"frames_sent": -1},
        {"bytes_received": "private-metric-canary"},
        {"unknown": 1},
    ],
)
def test_websocket_metrics_validate_at_both_public_boundaries(metrics):
    document = {"request_id": "ws-one", "status_code": 101, "websocket_metrics": metrics}
    with pytest.raises(ValueError, match="invalid WebSocket metrics") as caught:
        ReplayResponse.from_dict(document)
    assert "private-metric-canary" not in str(caught.value)
    response = ReplayResponse("ws-one", 101, websocket_metrics=metrics)
    with pytest.raises(ValueError, match="invalid WebSocket metrics"):
        response.to_dict()


def test_disabled_runtime_egress_rejects_even_explicitly_included_websocket_target():
    with WebSocketTestServer() as lab:
        guard = scope()
        guard.scope.egress_allowed = False
        replayer = StandardHttpReplayer(DestinationGuard([lab.url.split("/")[2]]), guard)
        with pytest.raises(ScopeViolationError, match="egress is disabled"):
            replayer.send(request(url=lab.url), ReplayBudget())
        assert not lab.handshakes


@pytest.mark.parametrize("during_consumption", [False, True])
def test_runtime_egress_is_checked_before_consumption_and_rechecked_before_connect(
    tmp_path, monkeypatch, during_consumption
):
    with WebSocketTestServer() as lab:
        requests, budget = [request(url=lab.url)], ReplayBudget()
        action_plan = live_plan(lab, requests, budget)
        guard = scope()
        worker, auth_id, control = loopback_worker(tmp_path, monkeypatch, action_plan, guard)
        if during_consumption:
            original = control.consume_authorization

            def consume(*args):
                guard.scope.egress_allowed = False
                return original(*args)

            monkeypatch.setattr(control, "consume_authorization", consume)
        else:
            guard.scope.egress_allowed = False
        if during_consumption:
            report = execute(
                lab,
                requests,
                budget,
                action_plan,
                auth_id,
                control,
                worker=worker,
                scope_guard=guard,
            )
            assert len(report.responses) == 1 and not report.responses[0].replay_success
        else:
            with pytest.raises(ScopeViolationError, match="egress is disabled"):
                execute(
                    lab,
                    requests,
                    budget,
                    action_plan,
                    auth_id,
                    control,
                    worker=worker,
                    scope_guard=guard,
                )
        assert len(control.consume_calls) == int(during_consumption)
        assert not control._issued_receipts and not lab.handshakes


def test_legacy_http_websocket_inventory_remains_previewable_but_not_executable():
    from cops.web_api.replay import preview_replay_session

    req = request(url="https://example.test/socket")
    preview = preview_replay_session([req], ["example.test"])
    assert preview.requests[0].url == req.url and preview.total_dispatched == 0
    with pytest.raises(ReplayAuthorizationError, match="unsupported WebSocket request"):
        plan(req)


def test_offline_model_does_not_invent_or_truncate_websocket_messages():
    from cops.web_api.replay import OfflineSyntheticReplayer, execute_replay_session

    replayer = OfflineSyntheticReplayer()
    with pytest.raises(ReplayBudgetExceededError):
        execute_replay_session(
            [request(websocket_messages=["a", "b"])],
            ["example.test"],
            budget=ReplayBudget(max_websocket_frames=5),
            replayer=replayer,
        )
    assert replayer.requests_sent == []
    report = execute_replay_session([request(websocket_messages=[])], ["example.test"], replayer=replayer)
    assert report.responses[0].websocket_replies == []
