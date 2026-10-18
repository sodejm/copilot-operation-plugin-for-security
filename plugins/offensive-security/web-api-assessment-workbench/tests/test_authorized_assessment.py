"""End-to-end acceptance for approved Web API replay assessments."""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cops.execution.control import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    ApprovalConsumptionReceipt,
)
from cops.execution.scope_guard import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    ScopeDefinition,
    ScopeGuard,
)
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


class _ApprovalControl:
    """Small authority double that records the approval-boundary interactions."""

    def __init__(self) -> None:
        self.ready_workers: list[str] = []
        self.consume_count = 0
        self.released = False

    def assert_ready(self, worker_identity: str) -> None:
        self.ready_workers.append(worker_identity)

    def consume_authorization(self, authorization_id, action_plan, worker_identity):
        self.consume_count += 1
        return ApprovalConsumptionReceipt(
            authorization_id=authorization_id,
            authorization_digest="a" * 64,
            action_plan_id=action_plan.plan_id,
            plan_digest=action_plan.plan_digest,
            engagement_id=action_plan.engagement_id,
            worker_identity=worker_identity,
            target=action_plan.target,
        )

    def validate_receipt_provenance(self, receipt):
        return receipt

    def release_receipt_provenance(self, receipt) -> None:
        del receipt
        self.released = True


def _sessions() -> list[SessionContext]:
    return [
        SessionContext(
            session_id="owner-session",
            role_id="owner",
            headers={"Authorization": "Bearer owner-token"},
        ),
        SessionContext(
            session_id="other-session",
            role_id="other",
            headers={"Authorization": "Bearer other-token"},
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
                graphql_query=graphql_body,
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


def _execute(laboratory, requests, *, plan_id: str):
    port = laboratory.base_url.rsplit(":", 1)[1]
    destinations = [f"127.0.0.1:{port}"]
    budget = ReplayBudget(max_requests=len(requests), rate_limit_rps=1000, timeout_seconds=2)
    plan = build_replay_action_plan(
        plan_id=plan_id,
        engagement_id="eng-web-api-lab",
        scenario_id="scen-web-api-assessment",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        allowed_destinations=destinations,
        budget=budget,
        credential_references=["lab-owner-session", "lab-other-session"],
        created_at="2026-10-15T00:00:00Z",
    )
    approval = _ApprovalControl()
    report = execute_authorized_replay_session(
        requests=requests,
        sessions=_sessions(),
        allowed_destinations=destinations,
        scope_guard=_scope_guard(),
        budget=budget,
        action_plan=plan,
        authorization_id=f"auth-{plan_id}",
        approval_control=approval,
        worker_identity="worker-web-api-lab",
    )
    return report, approval, plan, budget, destinations


@pytest.mark.parametrize(
    ("profile", "expected_verdict"),
    [("vulnerable", AssessmentVerdict.FAIL), ("corrected", AssessmentVerdict.PASS)],
)
def test_owner_other_and_anonymous_authorization_evidence(profile, expected_verdict) -> None:
    with WebApiAssessmentLaboratory(profile) as laboratory:
        requests = _authorization_requests(laboratory.base_url)
        port = laboratory.base_url.rsplit(":", 1)[1]
        budget = ReplayBudget(max_requests=6, rate_limit_rps=1000, timeout_seconds=2)

        preview = preview_replay_session(requests, [f"127.0.0.1:{port}"], budget)
        assert preview.total_dispatched == 0
        assert laboratory.request_count == 0

        report, approval, _, _, _ = _execute(laboratory, requests, plan_id=f"plan-auth-{profile}")
        assert laboratory.request_count == 6
        assert approval.ready_workers == ["worker-web-api-lab"]
        assert approval.consume_count == 1
        assert approval.released

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
def test_bounded_request_rate_evidence(profile, expected_verdict) -> None:
    with WebApiAssessmentLaboratory(profile) as laboratory:
        report, approval, _, _, _ = _execute(
            laboratory, _rate_requests(laboratory.base_url), plan_id=f"plan-rate-{profile}"
        )
        assessment = assess_rate_limit(report.responses, minimum_attempts=3)
        assert assessment.verdict is expected_verdict
        assert approval.consume_count == 1
        assert approval.released


def test_rate_limit_requires_enough_evidence() -> None:
    with WebApiAssessmentLaboratory("corrected") as laboratory:
        report, _, _, _, _ = _execute(
            laboratory, _rate_requests(laboratory.base_url, count=2), plan_id="plan-rate-insufficient"
        )
        assessment = assess_rate_limit(report.responses, minimum_attempts=3)
        assert assessment.verdict is AssessmentVerdict.INSUFFICIENT_EVIDENCE


def test_plan_mismatch_is_rejected_before_approval_or_dispatch() -> None:
    with WebApiAssessmentLaboratory("corrected") as laboratory:
        original = _rate_requests(laboratory.base_url, count=1)
        _, _, plan, budget, destinations = _execute(laboratory, original, plan_id="plan-original")
        laboratory.reset()
        approval = _ApprovalControl()
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
                authorization_id="auth-plan-original",
                approval_control=approval,
                worker_identity="worker-web-api-lab",
            )
        assert approval.consume_count == 0
        assert laboratory.request_count == 0


def test_request_cannot_override_isolated_session_credentials() -> None:
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
            requests=requests,
            allowed_destinations=destinations,
            budget=budget,
            created_at="2026-10-15T00:00:00Z",
        )
        approval = _ApprovalControl()
        with pytest.raises(ReplayAuthorizationError, match="cannot override"):
            execute_authorized_replay_session(
                requests=requests,
                sessions=_sessions(),
                allowed_destinations=destinations,
                scope_guard=_scope_guard(),
                budget=budget,
                action_plan=plan,
                authorization_id="auth-credential-override",
                approval_control=approval,
                worker_identity="worker-web-api-lab",
            )
        assert approval.consume_count == 0
        assert laboratory.request_count == 0
