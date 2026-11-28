"""Worker regressions for consumed-plan-bound egress capabilities."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import cops.execution.worker as worker_module
from cops.contracts.models import ActionPlan
from cops.execution.egress import BROKER_FD_ENV
from tests.auth_testkit import TestExecutionSandbox
from tests.test_adapter_execution import (
    _approval_control,
    _fake_action_plan,
    _fake_worker,
    _sandbox,
)


def _egress_plan(tmp_path: Path, *, egress_allowed: bool) -> ActionPlan:
    base = _fake_action_plan(tmp_path)
    snapshot = base.approved_snapshot()
    operation = snapshot["operations"][0]
    operation["egress_policy"] = {
        "https_endpoint": {
            "host": "api.example.test",
            "port": 443,
            "identity": {
                "provider": "example",
                "service": "inventory",
                "account": "account-a",
                "tenant": "tenant-a",
                "cluster": "cluster-a",
                "namespace": "namespace-a",
                "resource": "resource-a",
            },
            "request_targets": ["/v1/accounts/account-a/resources/resource-a"],
        }
    }
    limits = snapshot["limits"]
    limits["egress_allowed"] = egress_allowed
    return ActionPlan.create(
        plan_id=snapshot["plan_id"],
        engagement_id=snapshot["engagement_id"],
        scenario_id=snapshot["scenario_id"],
        target=snapshot["target"],
        specialist_id=snapshot["specialist_id"],
        operations=snapshot["operations"],
        limits=limits,
        credential_references=snapshot["credential_references"],
        created_at=snapshot["created_at"],
        platform_prerequisites=snapshot["platform_prerequisites"],
        batch=snapshot["batch"],
    )


def test_egress_preflight_rejects_before_approval_consumption(tmp_path: Path) -> None:
    plan = _egress_plan(tmp_path, egress_allowed=False)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    control = _approval_control(worker)

    with pytest.raises(worker_module.WorkerExecutionError, match="explicitly allow operation egress"):
        worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert control.consume_calls == []
    assert control.store.get_authorization(authorization_id).status == "approved"


def test_consumed_plan_exact_egress_policy_is_wired_to_sandbox_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _egress_plan(tmp_path, egress_allowed=True)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    control = _approval_control(worker)
    sandbox = _sandbox(worker)
    scope_guard = SimpleNamespace(
        scope=SimpleNamespace(egress_allowed=True),
        check_destination=lambda _destination: None,
    )
    identity_verifier = object()
    worker.scope_guard = scope_guard
    worker._egress_identity_verifier = identity_verifier

    monkeypatch.setattr(worker_module, "LinuxBubblewrapSandbox", TestExecutionSandbox)
    monkeypatch.setattr(worker_module, "verify_executable_launch_support", lambda: None)
    monkeypatch.setattr(
        worker_module,
        "prepare_executable",
        lambda *_args, **_kwargs: SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None),
    )

    mediator_arguments: dict[str, Any] = {}
    mediator = object()

    def build_mediator(**kwargs: Any) -> object:
        mediator_arguments.update(kwargs)
        return mediator

    class RecordingBroker:
        def __init__(self, actual_mediator: object) -> None:
            assert actual_mediator is mediator

        @contextmanager
        def open_channel(self, *, deadline: float):
            assert deadline > 0
            assert control.consume_calls == [(authorization_id, plan.plan_id, worker.config.worker_id)]
            yield SimpleNamespace(
                environment={BROKER_FD_ENV: "71"},
                pass_fds=(71,),
            )

    monkeypatch.setattr(worker_module, "HTTPSExecutionMediator", build_mediator)
    monkeypatch.setattr(worker_module, "ExecutionEgressBroker", RecordingBroker)

    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == "success"
    assert mediator_arguments["scope_guard"] is scope_guard
    assert mediator_arguments["identity_verifier"] is identity_verifier
    assert mediator_arguments["approved_origin"] == ("api.example.test", 443)
    allowlist = mediator_arguments["identity_allowlist"]
    assert {identity.as_dict()["resource"] for identity in allowlist.identities} == {"resource-a"}
    assert allowlist.request_targets[next(iter(allowlist.identities))] == frozenset(
        {"/v1/accounts/account-a/resources/resource-a"}
    )
    assert sandbox.run_calls[-1]["operation_env"] == {BROKER_FD_ENV: "71"}
    assert sandbox.run_calls[-1]["capability_fds"] == (71,)
