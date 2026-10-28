"""End-to-end acceptance for approved Web API replay assessments."""

from __future__ import annotations

import ipaddress
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cops.execution.scope_guard import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    ScopeDefinition,
    ScopeGuard,
)
from cops.execution.store import ApprovalStore  # noqa: E402
from cops.web_api import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    AssessmentVerdict,
    AuthorizationCase,
    ReplayAuthorizationError,
    WebApiAssessmentLaboratory,
    assess_object_authorization,
    assess_rate_limit,
    build_replay_action_plan,
    execute_authorized_replay_session,
    preview_replay_session,
)
from cops.web_api.models import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    ReplayBudget,
    ReplayRequest,
    SessionContext,
)
from tests.auth_testkit import TestApprovalControl, authorize_test_plan  # noqa: E402
from tests.web_api_worker_testkit import loopback_worker  # noqa: E402


def _bindings():
    return {f"{actor}-session": [{"reference": f"lab-{actor}-session", "header": "Authorization"}]
            for actor in ("owner", "other")}


def _authority(tmp_path, plan):
    """Persist a signed fixture approval and use the existing verifier/consumer."""
    auth, trust, engagement = authorize_test_plan(plan, worker_identity="worker-web-api-lab")
    store = ApprovalStore(tmp_path / "authority" / "approvals.sqlite3")
    store.store_authorization(auth)
    return auth.authorization_id, TestApprovalControl(store, trust, engagement)


def _sessions() -> list[SessionContext]:
    return [
        SessionContext(
            session_id="owner-session",
            role_id="owner",
        ),
        SessionContext(
            session_id="other-session",
            role_id="other",
        ),
        SessionContext(session_id="anonymous-session", role_id="anonymous"),
    ]


def _scope_guard() -> ScopeGuard:
    return ScopeGuard(
        ScopeDefinition(
            included_ips={ipaddress.ip_address("127.0.0.1")},
            egress_allowed=True,
        )
    )


def _authorization_requests(base_url: str) -> list[ReplayRequest]:
    requests: list[ReplayRequest] = []
    for actor in ("owner", "other", "anonymous"):
        session_id = f"{actor}-session"
        requests.append(
            ReplayRequest(
                request_id=f"rest-{actor}",
                endpoint_id="GET-/objects/{id}",
                method="GET",
                url=f"{base_url}/objects/owner-object",
                session_id=session_id,
                role_id=actor,
            )
        )
        graphql_body = json.dumps(
            {
                "query": "query Object($objectId: ID!) { object(id: $objectId) { id owner } }",
                "variables": {"objectId": "owner-object"},
            }
        )
        requests.append(
            ReplayRequest(
                request_id=f"graphql-{actor}",
                endpoint_id="POST-/graphql",
                method="POST",
                url=f"{base_url}/graphql",
                headers={"Content-Type": "application/json"},
                body=graphql_body,
                protocol="graphql",
                graphql_query=json.loads(graphql_body)["query"],
                session_id=session_id,
                role_id=actor,
            )
        )
    return requests


def _rate_requests(base_url: str, count: int = 4) -> list[ReplayRequest]:
    return [
        ReplayRequest(
            request_id=f"rate-owner-{index}",
            endpoint_id="GET-/rate-limited",
            method="GET",
            url=f"{base_url}/rate-limited",
            session_id="owner-session",
            role_id="owner",
        )
        for index in range(count)
    ]


def _execute(laboratory, requests, tmp_path, monkeypatch, *, plan_id: str):
    port = laboratory.base_url.rsplit(":", 1)[1]
    destinations = [f"127.0.0.1:{port}"]
    budget = ReplayBudget(max_requests=len(requests), rate_limit_rps=1000, timeout_seconds=2)
    plan = build_replay_action_plan(
        plan_id=plan_id,
        engagement_id="eng-web-api-lab",
        scenario_id="scen-web-api-assessment",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        sessions=_sessions(),
        allowed_destinations=destinations,
        budget=budget,
        session_credential_bindings=_bindings(),
        transport="laboratory",
        created_at="2026-10-15T00:00:00Z",
    )
    guard = _scope_guard()
    worker, authorization_id, approval = loopback_worker(
        tmp_path, monkeypatch, plan, guard,
        {"lab-owner-session": "Bearer owner-token", "lab-other-session": "Bearer other-token"},
    )
    report = execute_authorized_replay_session(
        requests=requests,
        sessions=_sessions(),
        allowed_destinations=destinations,
        scope_guard=guard,
        budget=budget,
        action_plan=plan,
        authorization_id=authorization_id,
        approval_control=approval,
        worker_identity="test-worker-01",
        worker=worker,
        session_credential_bindings=_bindings(),
        transport="laboratory",
    )
    return report, approval, plan, budget, destinations


@pytest.mark.parametrize(
    ("profile", "expected_verdict"),
    [("vulnerable", AssessmentVerdict.FAIL), ("corrected", AssessmentVerdict.PASS)],
)
def test_owner_other_and_anonymous_authorization_evidence(profile, expected_verdict, tmp_path, monkeypatch) -> None:
    with WebApiAssessmentLaboratory(profile) as laboratory:
        requests = _authorization_requests(laboratory.base_url)
        port = laboratory.base_url.rsplit(":", 1)[1]
        budget = ReplayBudget(max_requests=6, rate_limit_rps=1000, timeout_seconds=2)

        preview = preview_replay_session(requests, [f"127.0.0.1:{port}"], budget)
        assert preview.total_dispatched == 0
        assert laboratory.request_count == 0

        report, approval, _, _, _ = _execute(laboratory, requests, tmp_path, monkeypatch, plan_id=f"plan-auth-{profile}")
        assert laboratory.request_count == 6
        assert approval.ready_workers == ["test-worker-01"]
        assert len(approval.consume_calls) == 1
        assert not approval._issued_receipts

        response_by_request = {response.request_id: response for response in report.responses}
        cases = [
            AuthorizationCase(
                request_id=f"{surface}-{actor}",
                surface=surface,
                actor=actor,
                object_id="owner-object",
                expected_allowed=actor == "owner",
                response=response_by_request[f"{surface}-{actor}"],
            )
            for actor in ("owner", "other", "anonymous")
            for surface in ("rest", "graphql")
        ]
        assessment = assess_object_authorization(cases)
        assert assessment.verdict is expected_verdict

        serialized = json.dumps(report.to_dict())
        assert "owner-token" not in serialized
        assert "other-token" not in serialized


@pytest.mark.parametrize(
    ("profile", "expected_verdict"),
    [("vulnerable", AssessmentVerdict.FAIL), ("corrected", AssessmentVerdict.PASS)],
)
def test_bounded_request_rate_evidence(profile, expected_verdict, tmp_path, monkeypatch) -> None:
    with WebApiAssessmentLaboratory(profile) as laboratory:
        report, approval, _, _, _ = _execute(
            laboratory, _rate_requests(laboratory.base_url), tmp_path, monkeypatch, plan_id=f"plan-rate-{profile}"
        )
        assessment = assess_rate_limit(report.responses, minimum_attempts=3)
        assert assessment.verdict is expected_verdict
        assert len(approval.consume_calls) == 1
        assert not approval._issued_receipts


def test_rate_limit_requires_enough_evidence(tmp_path, monkeypatch) -> None:
    with WebApiAssessmentLaboratory("corrected") as laboratory:
        report, _, _, _, _ = _execute(
            laboratory, _rate_requests(laboratory.base_url, count=2), tmp_path, monkeypatch, plan_id="plan-rate-insufficient"
        )
        assessment = assess_rate_limit(report.responses, minimum_attempts=3)
        assert assessment.verdict is AssessmentVerdict.INSUFFICIENT_EVIDENCE


def test_plan_mismatch_is_rejected_before_approval_or_dispatch(tmp_path, monkeypatch) -> None:
    with WebApiAssessmentLaboratory("corrected") as laboratory:
        original = _rate_requests(laboratory.base_url, count=1)
        _, _, plan, budget, destinations = _execute(
            laboratory, original, tmp_path / "original", monkeypatch, plan_id="plan-original"
        )
        laboratory.reset()
        authorization_id, approval = _authority(tmp_path / "changed", plan)
        changed = [
            ReplayRequest(
                request_id="rate-owner-0",
                endpoint_id="GET-/objects/{id}",
                method="GET",
                url=f"{laboratory.base_url}/objects/owner-object",
                session_id="owner-session",
                role_id="owner",
            )
        ]
        with pytest.raises(ReplayAuthorizationError, match="action plan does not match"):
            execute_authorized_replay_session(
                requests=changed,
                sessions=_sessions(),
                allowed_destinations=destinations,
                scope_guard=_scope_guard(),
                budget=budget,
                action_plan=plan,
                authorization_id=authorization_id,
                approval_control=approval,
                worker_identity="worker-web-api-lab",
                session_credential_bindings=_bindings(),
                transport="laboratory",
            )
        assert approval.consume_calls == []
        assert laboratory.request_count == 0


def test_request_cannot_override_isolated_session_credentials(tmp_path) -> None:
    with WebApiAssessmentLaboratory("corrected") as laboratory:
        requests = [
            ReplayRequest(
                request_id="credential-override",
                endpoint_id="GET-/objects/{id}",
                method="GET",
                url=f"{laboratory.base_url}/objects/owner-object",
                headers={"Authorization": "Bearer attacker-token"},
                session_id="owner-session",
                role_id="owner",
            )
        ]
        port = laboratory.base_url.rsplit(":", 1)[1]
        destinations = [f"127.0.0.1:{port}"]
        budget = ReplayBudget(max_requests=1, timeout_seconds=2)
        plan = build_replay_action_plan(
            plan_id="plan-credential-override",
            engagement_id="eng-web-api-lab",
            scenario_id="scen-web-api-assessment",
            specialist_id="web-api-assessment-workbench",
            requests=[replace(requests[0], headers={})],
            sessions=_sessions(),
            allowed_destinations=destinations,
            budget=budget,
            session_credential_bindings=_bindings(),
            transport="laboratory",
            created_at="2026-10-15T00:00:00Z",
        )
        authorization_id, approval = _authority(tmp_path, plan)
        with pytest.raises(ReplayAuthorizationError, match="bounded replay worker contract"):
            execute_authorized_replay_session(
                requests=requests,
                sessions=_sessions(),
                allowed_destinations=destinations,
                scope_guard=_scope_guard(),
                budget=budget,
                action_plan=plan,
                authorization_id=authorization_id,
                approval_control=approval,
                worker_identity="worker-web-api-lab",
                session_credential_bindings=_bindings(),
                transport="laboratory",
            )
        assert approval.consume_calls == []
        assert laboratory.request_count == 0
