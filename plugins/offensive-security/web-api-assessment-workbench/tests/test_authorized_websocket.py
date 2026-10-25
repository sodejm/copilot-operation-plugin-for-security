"""Real WebSocket role-session observations with persisted exact-plan approval."""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.execution.scope_guard import ScopeDefinition, ScopeGuard  # noqa: E402
from cops.execution.store import ApprovalStore  # noqa: E402
from cops.web_api.models import ReplayBudget, ReplayRequest, SessionContext  # noqa: E402
from cops.web_api.replay import build_replay_action_plan, execute_authorized_replay_session  # noqa: E402
from cops.web_api.sanitization import sanitize_body  # noqa: E402
from tests.auth_testkit import TestApprovalControl, authorize_test_plan  # noqa: E402
from tests.websocket_testkit import WebSocketTestServer  # noqa: E402


@pytest.mark.parametrize("profile", ["vulnerable", "corrected"])
def test_approved_websocket_role_sessions_and_clean_close(tmp_path, profile):
    with WebSocketTestServer(mode="authorization", profile=profile) as lab:
        sessions = [
            SessionContext(
                session_id="owner-session", role_id="owner", headers={"Authorization": "Bearer owner-token"}
            ),
            SessionContext(
                session_id="other-session", role_id="other", headers={"Authorization": "Bearer other-token"}
            ),
            SessionContext(session_id="anonymous-session", role_id="anonymous"),
        ]
        requests = [
            ReplayRequest(
                f"ws-{actor}",
                "ws-object",
                "GET",
                lab.url,
                protocol="websocket",
                session_id=f"{actor}-session",
                role_id=actor,
                websocket_messages=["owner-object"],
            )
            for actor in ("owner", "other", "anonymous")
        ]
        destinations = [lab.url.split("/")[2]]
        budget = ReplayBudget(max_requests=3, rate_limit_rps=1000, timeout_seconds=2)
        plan = build_replay_action_plan(
            plan_id="plan-websocket-roles",
            engagement_id="eng-websocket-roles",
            scenario_id="scen-websocket-roles",
            specialist_id="web-api-assessment-workbench",
            requests=requests,
            sessions=sessions,
            allowed_destinations=destinations,
            budget=budget,
        )
        auth, trust, engagement = authorize_test_plan(plan, worker_identity="worker-websocket-roles")
        store = ApprovalStore(tmp_path / "authority" / "approvals.sqlite3")
        store.store_authorization(auth)
        control = TestApprovalControl(store, trust, engagement)
        report = execute_authorized_replay_session(
            requests=requests,
            sessions=sessions,
            allowed_destinations=destinations,
            scope_guard=ScopeGuard(
                ScopeDefinition(included_ips={ipaddress.ip_address("127.0.0.1")}, egress_allowed=True)
            ),
            budget=budget,
            action_plan=plan,
            authorization_id=auth.authorization_id,
            approval_control=control,
            worker_identity="worker-websocket-roles",
        )
        assert len(control.consume_calls) == 1 and not control._issued_receipts
        assert len(lab.handshakes) == 3
        assert [headers.get("authorization") for _, headers in lab.handshakes] == [
            "Bearer owner-token",
            "Bearer other-token",
            None,
        ]
        assert len({headers["sec-websocket-key"] for _, headers in lab.handshakes}) == 3
        for actor, response in zip(("owner", "other", "anonymous"), report.responses, strict=True):
            allowed = actor == "owner" or (actor == "other" and profile == "vulnerable")
            expected = ("allow:" if allowed else "deny:") + "owner-object"
            assert response.replay_success and response.websocket_replies == [sanitize_body(expected)]
            assert response.websocket_metrics["close_code"] == 1000
        serialized = json.dumps(report.to_dict())
        assert "owner-token" not in serialized and "other-token" not in serialized
        assert "allow:owner-object" not in serialized and "deny:owner-object" not in serialized
    assert not lab.active and not lab.thread.is_alive()
