"""Local protocol fixtures provide replay evidence, not production qualification."""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.web_api.laboratory import WebApiAssessmentLaboratory
from cops.web_api.models import AuthenticationMechanism, ReplayBudget, ReplayRequest, SessionContext
from cops.web_api.replay import (
    DestinationGuard,
    ReplayBudgetExceededError,
    StandardHttpReplayer,
    build_replay_action_plan,
    execute_authorized_replay_session,
)
from cops.web_api.sanitization import sanitize_body
from tests.web_api_worker_testkit import loopback_worker

QUERY = "query Object($objectId: ID!) { object(id: $objectId) { id owner } }"
IDENTITIES = ("owner", "other", "anonymous", "owner")


def scope():
    return ScopeGuard(ScopeDefinition(included_ips={ipaddress.ip_address("127.0.0.1")}, egress_allowed=True))


def request(lab, protocol, identity="owner", *, session=False, index=0):
    options = {}
    if protocol == "rest":
        url, method, wire_protocol = lab.base_url + "/objects/owner-object", "GET", "http"
    elif protocol == "websocket":
        url, method, wire_protocol = lab.websocket_url, "GET", "websocket"
        options["websocket_messages"] = ["owner-object"]
    else:
        url, method, wire_protocol = lab.base_url + "/graphql", protocol.split("-")[1].upper(), "graphql"
        variables = {"objectId": "owner-object"}
        options["graphql_query"] = QUERY
        if method == "GET":
            options["query_parameters"] = {"query": QUERY, "variables": json.dumps(variables)}
        else:
            options["body"] = json.dumps({"query": QUERY, "variables": variables})
    return ReplayRequest(
        f"request-{index}",
        "object",
        method,
        url,
        protocol=wire_protocol,
        headers={} if session or identity == "anonymous" else {"Authorization": f"Bearer {identity}-token"},
        session_id=identity if session else None,
        role_id=identity if session else None,
        **options,
    )


def transport(lab):
    return StandardHttpReplayer(
        DestinationGuard([lab.base_url.split("/")[2]]),
        scope(),
        **({"tls_context": lab.tls_context} if lab.base_url.startswith("https:") else {}),
    )


def accessible(response, protocol):
    assert response.replay_success, response.error_message
    if protocol == "websocket":
        assert response.status_code == 101
        assert response.websocket_metrics["close_code"] == 1000
        document = json.loads(response.websocket_replies[0])
        return document.get("owner") == "owner"
    if protocol.startswith("graphql"):
        assert response.status_code == 200
        return json.loads(response.body_excerpt)["data"]["object"] is not None
    return response.status_code == 200


@pytest.mark.parametrize("profile", ["vulnerable", "corrected"])
@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("protocol", ["rest", "graphql-get", "graphql-post", "websocket"])
def test_real_transport_role_matrix_has_no_session_carryover(profile, tls, protocol):
    with WebApiAssessmentLaboratory(profile, tls=tls) as lab:
        replayer = transport(lab)
        for index, identity in enumerate(IDENTITIES):
            response = replayer.send(request(lab, protocol, identity, index=index), ReplayBudget())
            assert accessible(response, protocol) == (
                identity == "owner" or (identity == "other" and profile == "vulnerable")
            )
            assert len(response.body_excerpt.encode()) <= 2048
            assert sum(len(value.encode()) for value in response.websocket_replies) <= 65536
        assert lab.request_count == 4


@pytest.mark.parametrize("profile", ["vulnerable", "corrected"])
def test_approved_session_batch_exercises_all_plaintext_lab_protocols(tmp_path, monkeypatch, profile):
    # The approved entry point owns its TLS trust store. Disposable custom-CA TLS
    # is exercised above through the verified-context transport API instead.
    sessions = [
        SessionContext(
            identity,
            identity,
            auth_mechanism=(
                AuthenticationMechanism()
                if identity == "anonymous"
                else AuthenticationMechanism(auth_type="bearer", token_name="Authorization")
            ),
        )
        for identity in ("owner", "other", "anonymous")
    ]
    bindings = {
        identity: [{"reference": f"credential-{identity}", "header": "Authorization"}]
        for identity in ("owner", "other")
    }
    credentials = {f"credential-{identity}": f"Bearer {identity}-token" for identity in ("owner", "other")}
    with WebApiAssessmentLaboratory(profile) as lab:
        protocols = [protocol for protocol in ("rest", "graphql-get", "graphql-post", "websocket") for _ in IDENTITIES]
        identities = list(IDENTITIES) * 4
        requests = [
            request(lab, protocol, identity, session=True, index=index)
            for index, (protocol, identity) in enumerate(zip(protocols, identities, strict=True))
        ]
        budget = ReplayBudget(max_requests=len(requests), rate_limit_rps=1000)
        destinations = [lab.base_url.split("/")[2]]
        plan = build_replay_action_plan(
            plan_id="plan-laboratory",
            engagement_id="eng-laboratory",
            scenario_id="scen-laboratory",
            specialist_id="web-api-assessment-workbench",
            requests=requests,
            sessions=sessions,
            allowed_destinations=destinations,
            budget=budget,
            session_credential_bindings=bindings,
            transport="laboratory",
        )
        guard = scope()
        worker, authorization_id, control = loopback_worker(
            tmp_path,
            monkeypatch,
            plan,
            guard,
            credentials=credentials,
        )
        report = execute_authorized_replay_session(
            requests=requests,
            sessions=sessions,
            allowed_destinations=destinations,
            scope_guard=guard,
            budget=budget,
            action_plan=plan,
            authorization_id=authorization_id,
            approval_control=control,
            worker_identity="test-worker-01",
            worker=worker,
            session_credential_bindings=bindings,
            transport="laboratory",
        )
        assert len(report.responses) == len(requests) == lab.request_count
        for response, protocol, identity in zip(report.responses, protocols, identities, strict=True):
            allowed = identity == "owner" or (identity == "other" and profile == "vulnerable")
            assert response.replay_success
            if protocol.startswith("graphql"):
                assert response.observed_graphql_object_access() is allowed
            elif protocol == "websocket":
                expected = (
                    {"id": "owner-object", "owner": "owner", "value": "evidence"}
                    if allowed
                    else {"error": "authentication required" if identity == "anonymous" else "object access denied"}
                )
                assert response.status_code == 101 and response.websocket_metrics["close_code"] == 1000
                assert response.websocket_replies == [sanitize_body(json.dumps(expected, sort_keys=True))]
            else:
                assert (response.status_code == 200) is allowed
        assert [(req.session_id, req.role_id) for req in report.requests] == [(value, value) for value in identities]
        saved = json.dumps(report.to_dict())
        assert "owner-token" not in saved and "other-token" not in saved
        assert not control._issued_receipts


@pytest.mark.parametrize("tls", [False, True])
def test_concurrent_websocket_sessions_remain_separate(tls):
    with WebApiAssessmentLaboratory("corrected", tls=tls) as lab:
        replayer = transport(lab)
        barrier = threading.Barrier(3)

        def exchange(identity):
            barrier.wait(timeout=2)
            return accessible(replayer.send(request(lab, "websocket", identity), ReplayBudget()), "websocket")

        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(exchange, ("owner", "other", "anonymous"))) == [True, False, False]
        assert lab.request_count == 3


@pytest.mark.parametrize("protocol", ["rest", "graphql-get", "graphql-post", "websocket"])
@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("cancel", [False, True])
def test_deadline_or_cancellation_closes_replay_and_lab_resources(protocol, tls, cancel):
    prior_threads = set(threading.enumerate())
    with WebApiAssessmentLaboratory("corrected", tls=tls, request_delay_seconds=5) as lab:
        event = threading.Event()
        replayer = transport(lab)
        with ThreadPoolExecutor(max_workers=1) as pool:
            started = time.monotonic()
            future = pool.submit(
                replayer.send,
                request(lab, protocol),
                ReplayBudget(timeout_seconds=2 if cancel else 0.2),
                cancellation_event=event,
            )
            assert lab.request_received.wait(1)
            if cancel:
                event.set()
            response = future.result(timeout=2)
            assert not response.replay_success
            assert response.error_message == ("ReplayCancelledError" if cancel else "TimeoutError")
            assert time.monotonic() - started < 2
    assert lab.active_connection_count == 0
    assert not [thread for thread in set(threading.enumerate()) - prior_threads if thread.is_alive()]


def test_replay_request_frame_and_byte_limits_reject_before_dispatch():
    with WebApiAssessmentLaboratory("corrected") as lab:
        req = request(lab, "websocket")
        for budget, oversized in (
            (ReplayBudget(max_websocket_frames=3), req),
            (ReplayBudget(max_websocket_message_bytes=11), req),
            (ReplayBudget(max_websocket_bytes=10), req),
            (ReplayBudget(), replace(req, websocket_messages=["x" * 65537])),
        ):
            with pytest.raises(ReplayBudgetExceededError):
                transport(lab).send(oversized, budget)
        with pytest.raises(ReplayBudgetExceededError, match="request count"):
            build_replay_action_plan(
                plan_id="bounded",
                engagement_id="bounded",
                scenario_id="bounded",
                specialist_id="bounded",
                requests=[req, replace(req, request_id="second")],
                allowed_destinations=[lab.base_url.split("/")[2]],
                budget=ReplayBudget(max_requests=1),
            )
        assert lab.request_count == 0
