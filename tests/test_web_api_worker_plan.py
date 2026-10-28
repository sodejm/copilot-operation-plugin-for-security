"""The public replay API compiles exact plans and delegates transport to workers."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, replace
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from cops.contracts.models import CleanupReceipt, RunResult
from cops.evidence.canonical import digest
from cops.execution.control import ApprovalConsumptionReceipt
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.worker import AuthorizedExecution, IsolatedWorker
from cops.web_api.models import (
    AuthenticationMechanism,
    ReplayBudget,
    ReplayRequest,
    ReplaySessionReport,
    SessionContext,
)
from cops.web_api.replay import ReplayAuthorizationError, build_replay_action_plan, execute_authorized_replay_session
from cops.web_api.worker_replay import _wire_request, validate_web_api_operation


def request(**changes):
    return replace(ReplayRequest("request-one", "endpoint-one", "GET", "https://api.example.test/items"), **changes)


def plan(requests=None, **changes):
    return build_replay_action_plan(
        plan_id="plan-worker-replay", engagement_id="eng-worker-replay", scenario_id="scen-worker-replay",
        specialist_id="web-api-assessment-workbench", requests=requests or [request()],
        allowed_destinations=changes.pop("allowed_destinations", ["api.example.test"]),
        created_at="2026-10-27T00:00:00Z", **changes,
    )


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("source", ["explicit", "body", "parameters"])
def test_graphql_forms_compile_to_one_exact_worker_target(method, source):
    query, variables = "query Object($id: ID!) { object(id: $id) { id } }", {"id": "owner-object"}
    changes = {"graphql_query": query, "graphql_variables": variables}
    if source == "body":
        changes = {"body": json.dumps({"query": query, "variables": variables})}
    elif source == "parameters":
        changes = {"query_parameters": {"query": query, "variables": json.dumps(variables)}}
    operation = plan([request(method=method, protocol="graphql", **changes)]).approved_snapshot()["operations"][0]
    envelope = validate_web_api_operation(operation).to_dict()
    assert envelope["request"]["graphql_query"] == query
    assert envelope["request"]["graphql_variables"] == variables
    assert envelope["request"]["body"] is None
    wire = _wire_request(envelope)
    if method == "GET":
        parameters = parse_qs(urlsplit(wire.url).query)
        assert parameters["query"] == [query]
        assert json.loads(parameters["variables"][0]) == variables
    else:
        assert json.loads(wire.body) == {"query": query, "variables": variables}
    assert envelope["destination_policy"]["request_urls"] == [wire.url]
    assert envelope["request_digest"] == digest({key: envelope[key] for key in (
        "session_id", "role_id", "request", "credential_references",
    )})


def test_session_credentials_bind_explicit_roles_and_references_without_values():
    sessions = [SessionContext(name, name, AuthenticationMechanism(auth_type="bearer", token_name="Authorization"))
                for name in ("owner", "unrelated")]
    requests = [request(request_id=name, session_id=name, role_id=name) for name in ("owner", "unrelated")]
    bindings = {name: [{"reference": f"credential-{name}", "header": "Authorization"}]
                for name in ("owner", "unrelated")}
    compiled = plan(requests, sessions=sessions, session_credential_bindings=bindings)
    assert list(compiled.credential_references) == ["credential-owner", "credential-unrelated"]
    for operation in compiled.approved_snapshot()["operations"]:
        envelope = validate_web_api_operation(operation).to_dict()
        assert envelope["session_id"] == envelope["role_id"] == operation["step_id"]
        assert envelope["request"]["headers"] == {}
        assert envelope["credential_references"] == bindings[operation["step_id"]]
    with pytest.raises(ReplayAuthorizationError):
        plan(requests, sessions=sessions)
    with pytest.raises(ReplayAuthorizationError):
        plan([replace(requests[0], role_id="unrelated")], sessions=sessions, session_credential_bindings=bindings)


@pytest.mark.parametrize("url,transport,allowed", [
    ("http://api.example.test/items", "production", False),
    ("http://localhost/items", "laboratory", False),
    ("http://127.0.0.1/items", "laboratory", True),
    ("ws://127.0.0.1/socket", "laboratory", True),
    ("wss://api.example.test/socket", "production", True),
])
def test_plaintext_requires_explicit_literal_loopback_laboratory(url, transport, allowed):
    req = request(url=url, protocol="websocket" if url.startswith(("ws:", "wss:")) else "http")
    kwargs = {"transport": transport, "allowed_destinations": [urlsplit(url).hostname]}
    if allowed:
        validate_web_api_operation(plan([req], **kwargs).approved_snapshot()["operations"][0])
    else:
        with pytest.raises(ReplayAuthorizationError):
            plan([req], **kwargs)


def execution_case(requests=None, outputs=None, status="success", attempted_ids=None):
    requests = requests or [request()]
    scope = ScopeGuard(ScopeDefinition(included_domains=["api.example.test"], egress_allowed=True))
    approval = SimpleNamespace(consume=lambda *_args, **_kwargs: pytest.fail("caller consumed approval"))
    calls = []
    if outputs is None:
        outputs = {req.request_id: {"request_id": req.request_id, "status": 200, "headers": {}, "body": "ok",
                                    "redirect_count": 0} for req in requests}
    if attempted_ids is None:
        attempted_ids = tuple(req.request_id for req in requests if req.request_id in outputs)

    def execute(action_plan, **kwargs):
        calls.append((action_plan, kwargs))
        receipt = ApprovalConsumptionReceipt(
            "authorization-replay", "a" * 64, action_plan.plan_id, action_plan.plan_digest,
            action_plan.engagement_id, "worker-replay", action_plan.target,
        )
        result = RunResult(
            "cops.run-result/v1", "res-replay", action_plan.plan_id, action_plan.engagement_id,
            status, "2026-10-27T00:00:00Z", "2026-10-27T00:00:01Z", {"summary": "Replay completed"},
            ["a" * 64, "b" * 64], [], "completed", "worker-replay",
        )
        cleanup = CleanupReceipt(
            "cops.cleanup-receipt/v1", "cln-replay", action_plan.plan_id, action_plan.engagement_id,
            "worker-replay", "completed", "2026-10-27T00:00:00Z", "2026-10-27T00:00:01Z", [], [], "b" * 64,
        )
        return AuthorizedExecution(result, receipt, cleanup, outputs, attempted_ids)

    # A concrete worker instance with only execution stubbed exercises the public
    # type boundary without starting a sandbox or claiming process isolation.
    worker = object.__new__(IsolatedWorker)
    worker.config = SimpleNamespace(worker_id="worker-replay")
    worker.approval_control, worker.scope_guard = approval, scope
    worker.execute_plan_with_receipt = execute
    kwargs = dict(requests=requests, sessions=[], allowed_destinations=["api.example.test"], scope_guard=scope,
                  budget=ReplayBudget(), action_plan=plan(requests), authorization_id="authorization-replay",
                  approval_control=approval, worker_identity="worker-replay", worker=worker)
    return kwargs, calls


def test_executor_delegates_once_and_converts_outputs_in_plan_order(monkeypatch):
    requests = [request(request_id="first"), request(request_id="second")]
    kwargs, calls = execution_case(requests)
    import cops.web_api.replay as replay
    monkeypatch.setattr(replay.StandardHttpReplayer, "send", lambda *_args: pytest.fail("caller transport dispatched"))
    cancellation = threading.Event()
    report = execute_authorized_replay_session(**kwargs, cancellation_event=cancellation)
    assert [response.request_id for response in report.responses] == ["first", "second"]
    assert report.total_successful == 2
    assert report.total_dispatched == 2
    assert len(calls) == 1 and calls[0][0] is kwargs["action_plan"]
    assert calls[0][1] == {"authorization_id": "authorization-replay", "cancellation_event": cancellation}
    assert calls[0][0].operations[0]["arguments"]["envelope"]["budgets"]["rate_limit_rps"] == 10.0


@pytest.mark.parametrize("case", ["missing", "extra", "mismatched", "no-worker", "duck-worker", "identity", "control", "scope"])
def test_executor_rejects_unbound_worker_or_invalid_outputs(case):
    kwargs, calls = execution_case()
    if case == "missing":
        kwargs, calls = execution_case(outputs={})
    elif case == "extra":
        kwargs, calls = execution_case(outputs={"unexpected": {}})
    elif case == "mismatched":
        kwargs, calls = execution_case(outputs={"request-one": {"request_id": "other"}})
    elif case == "no-worker":
        kwargs["worker"] = None
    elif case == "duck-worker":
        kwargs["worker"] = SimpleNamespace(**vars(kwargs["worker"]))
    elif case == "identity":
        kwargs["worker"].config.worker_id = "other-worker"
    elif case == "control":
        kwargs["worker"].approval_control = object()
    elif case == "scope":
        kwargs["worker"].scope_guard = object()
    with pytest.raises(ReplayAuthorizationError):
        execute_authorized_replay_session(**kwargs)
    assert len(calls) == (1 if case in {"missing", "extra", "mismatched"} else 0)


@pytest.mark.parametrize("attempted_ids", [(), ("unexpected",), ["request-one"]])
def test_executor_rejects_invalid_dispatch_evidence(attempted_ids):
    kwargs, calls = execution_case(attempted_ids=attempted_ids)
    with pytest.raises(ReplayAuthorizationError, match="dispatch evidence"):
        execute_authorized_replay_session(**kwargs)
    assert len(calls) == 1


def test_executor_rejects_reordered_dispatch_evidence():
    requests = [request(request_id="first"), request(request_id="second")]
    kwargs, calls = execution_case(requests, attempted_ids=("second", "first"))
    with pytest.raises(ReplayAuthorizationError, match="dispatch evidence"):
        execute_authorized_replay_session(**kwargs)
    assert len(calls) == 1


@pytest.mark.parametrize("field", [
    "authorization_id", "action_plan_id", "plan_digest", "engagement_id", "worker_identity", "target",
    "authorization_digest", "untyped-execution", "untyped-receipt", "result-plan", "cleanup-worker",
])
def test_executor_rejects_unbound_execution_results_and_receipts(field):
    kwargs, calls = execution_case()
    original = kwargs["worker"].execute_plan_with_receipt

    def execute(*args, **kw):
        result = original(*args, **kw)
        if field == "untyped-execution":
            return SimpleNamespace(**vars(result))
        if field == "untyped-receipt":
            return replace(result, approval_receipt=SimpleNamespace(**vars(result.approval_receipt)))
        if field == "result-plan":
            return replace(result, result=replace(result.result, plan_id="other-plan"))
        if field == "cleanup-worker":
            return replace(result, cleanup_receipt=replace(result.cleanup_receipt, worker_identity="other-worker"))
        return replace(result, approval_receipt=replace(result.approval_receipt, **{field: "unbound"}))

    kwargs["worker"].execute_plan_with_receipt = execute
    with pytest.raises(ReplayAuthorizationError):
        execute_authorized_replay_session(**kwargs)
    assert len(calls) == 1


@pytest.mark.parametrize("status", ["failed", "partial", "cancelled", "uncertain"])
def test_worker_failures_cannot_be_reported_as_success(status):
    kwargs, _calls = execution_case(outputs={}, status=status)
    report = execute_authorized_replay_session(**kwargs)
    assert report.total_failed == 1 and report.total_successful == 0
    assert report.total_dispatched == 0
    assert report.to_dict()["execution_evidence"]["status"] == status


def test_uncertain_dispatch_is_counted_without_completed_output():
    kwargs, _calls = execution_case(outputs={}, status="uncertain", attempted_ids=("request-one",))
    report = execute_authorized_replay_session(**kwargs)
    assert report.total_failed == 1 and report.total_successful == 0
    assert report.total_dispatched == 1
    assert report.to_dict()["execution_evidence"]["attempted_operation_ids"] == ["request-one"]


def test_authorized_report_binds_safe_plan_authority_and_request_evidence(tmp_path):
    kwargs, _calls = execution_case()
    report = execute_authorized_replay_session(**kwargs)
    value = report.to_dict()
    approved = kwargs["action_plan"].approved_snapshot()
    envelope = validate_web_api_operation(approved["operations"][0])
    assert value["application_context"] == {
        "engagement_id": kwargs["action_plan"].engagement_id,
        "scenario_id": kwargs["action_plan"].scenario_id,
        "specialist_id": kwargs["action_plan"].specialist_id,
        "target": kwargs["action_plan"].target,
        "worker_identity": "worker-replay",
        "execution_status": "success",
    }
    assert value["authorization_evidence"]["authorization_id"] == "authorization-replay"
    assert value["authorization_evidence"]["authorization_digest"] == "a" * 64
    assert value["authorization_evidence"]["plan_id"] == kwargs["action_plan"].plan_id
    assert value["authorization_evidence"]["plan_digest"] == kwargs["action_plan"].plan_digest
    assert value["request_provenance"] == [{
        "request_id": "request-one", "session_id": "anonymous", "role_id": "anonymous",
        "protocol": "http", "method": "GET", "request_digest": envelope.to_dict()["request_digest"],
        "envelope_digest": envelope.digest,
    }]
    assert value["execution_evidence"]["result_id"] == "res-replay"
    assert value["execution_evidence"]["status"] == "success"
    assert value["execution_evidence"]["evidence_hashes"] == ["a" * 64, "b" * 64]
    assert value["execution_evidence"]["attempted_operation_ids"] == ["request-one"]
    assert "artifacts" not in value["execution_evidence"]
    assert value["replay_limits"] == {
        "budget": asdict(kwargs["budget"]), "limits": approved["limits"], "batch": approved["batch"],
    }
    assert value["cleanup_receipt"]["receipt_id"] == "cln-replay"
    assert value["cleanup_receipt"]["status"] == "completed"
    assert value["cleanup_receipt"]["evidence_hash"] == "b" * 64
    assert value["cleanup_receipt"]["cleaned_effect_count"] == 0
    assert value["cleanup_receipt"]["unresolved_effect_count"] == 0
    assert "cleaned_effects" not in value["cleanup_receipt"]
    assert "unresolved_effects" not in value["cleanup_receipt"]
    assert value["redirect_decisions"] == []
    assert value["unsupported_features"]
    for feature in value["unsupported_features"]:
        assert feature["protocol"] and feature["feature_name"] and feature["reason"]
    assert value["total_dispatched"] == 1
    path = tmp_path / "authorized-report.json"
    report.save(path)
    assert ReplaySessionReport.load(path).to_dict() == value


def test_authorized_report_preserves_final_url_and_digest_only_redirect_decisions():
    initial_url = "https://api.example.test/items"
    final_url = "https://api.example.test/items/final"
    decisions = [{
        "status_code": 307, "from_url_digest": digest(initial_url), "to_url_digest": digest(final_url),
        "cross_origin": False, "method_before": "GET", "method_after": "GET", "body_removed": False,
        "credentials_removed": False, "headers_removed": [], "decision": "followed",
    }]
    kwargs, _calls = execution_case(outputs={"request-one": {
        "request_id": "request-one", "status": 200, "headers": {}, "body": "ok",
        "redirect_count": 1, "final_url": final_url, "redirect_decisions": decisions,
    }})
    kwargs["redirect_targets"] = {"request-one": ["/items/final"]}
    kwargs["action_plan"] = plan(redirect_targets=kwargs["redirect_targets"])
    policy = validate_web_api_operation(kwargs["action_plan"].approved_snapshot()["operations"][0]).to_dict()[
        "destination_policy"
    ]
    assert policy["request_urls"] == [initial_url, final_url]
    report = execute_authorized_replay_session(**kwargs)
    assert report.responses[0].final_url == final_url
    assert report.responses[0].redirect_count == 1
    assert report.to_dict()["redirect_decisions"] == decisions
    assert ReplaySessionReport.from_dict(report.to_dict()).to_dict()["redirect_decisions"] == decisions


def test_authorized_report_excludes_payload_credentials_and_raw_cleanup_metadata():
    credential_canary = "credential-canary-for-report"
    request_body_canary = "request-body-canary-for-report"
    response_body_canary = "response-body-canary-for-report"
    header_canary = "header-canary-for-report"
    cleanup_canary = "cleanup-resource-canary-for-report"
    kwargs, _calls = execution_case(
        [request(method="POST", body=request_body_canary)],
        outputs={"request-one": {
            "request_id": "request-one", "status": 200,
            "headers": {"Authorization": f"Bearer {credential_canary}", "Set-Cookie": header_canary},
            "body": response_body_canary, "redirect_count": 0,
        }},
    )
    original = kwargs["worker"].execute_plan_with_receipt

    def execute(*args, **kw):
        execution = original(*args, **kw)
        return replace(
            execution,
            result=replace(execution.result, status_details={"summary": cleanup_canary}, artifacts=[{
                "name": "worker-log", "path": f"/private/{cleanup_canary}", "sha256": "d" * 64,
            }]),
            cleanup_receipt=replace(execution.cleanup_receipt, cleaned_effects=[{
                "target": f"/private/{cleanup_canary}", "resource_type": "temporary_file",
                "action_taken": "removed",
            }]),
        )

    kwargs["worker"].execute_plan_with_receipt = execute
    report = execute_authorized_replay_session(**kwargs)
    value = report.to_dict()
    assert value["cleanup_receipt"]["cleaned_effect_count"] == 1
    assert value["cleanup_receipt"]["unresolved_effect_count"] == 0
    serialized = json.dumps(value, sort_keys=True)
    for canary in (credential_canary, request_body_canary, response_body_canary, header_canary, cleanup_canary):
        assert canary not in serialized
    assert ReplaySessionReport.from_dict(value).to_dict() == value


def test_historical_report_remains_readable_without_claiming_authorization():
    historical = {
        "session_id": "historical-replay", "target_hosts": ["api.example.test"],
        "allowed_destinations": ["api.example.test"], "budget": {"max_requests": 1},
        "requests": [], "responses": [], "total_dispatched": 0,
        "created_at_utc": "2026-10-27T00:00:00Z",
    }
    report = ReplaySessionReport.from_dict(historical)
    value = report.to_dict()
    assert report.session_id == "historical-replay" and report.total_dispatched == 0
    for field in ("application_context", "request_provenance", "authorization_evidence", "execution_evidence",
                  "replay_limits", "redirect_decisions", "cleanup_receipt", "unsupported_features"):
        assert not value.get(field)


def test_pre_cancelled_replay_never_dispatches_or_consumes():
    kwargs, calls = execution_case()
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(ReplayAuthorizationError, match="cancelled"):
        execute_authorized_replay_session(**kwargs, cancellation_event=cancelled)
    assert calls == []
