from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import cops.workflows.runtime as workflow_runtime
from cops.contracts import ActionPlan
from cops.evidence.canonical import digest
from cops.execution.store import ApprovalStore
from cops.workflows import (
    StageExecutionResult,
    WorkflowContractError,
    WorkflowDefinition,
    WorkflowRunner,
    compile_action_plan,
)
from cops.workflows.runtime import WorkflowRuntimeError
from tests.auth_testkit import TestApprovalControl, authorize_test_plan
from tests.test_workflow_runtime import NOW, WORKER, QueueExecutor, authorized_runner, workflow_document


def _baseline_compile_action_plan(
    definition: WorkflowDefinition,
    run_id: str,
    stage_id: str,
    resolved_inputs: dict[str, object],
    created_at: str,
    *,
    attempt: int = 1,
) -> ActionPlan:
    """Reproduce the baseline compiler that implicitly marked every action safe."""
    stage = definition.stage(stage_id)
    action = stage["action"]
    identity = digest(
        {
            "workflow_digest": definition.definition_digest,
            "run_id": run_id,
            "stage_id": stage_id,
            "attempt": attempt,
            "inputs": resolved_inputs,
        }
    )
    operation = {
        "step_id": f"{stage_id}-{attempt}",
        "tool": action["tool"],
        "tool_version": action["tool_version"],
        "action": action["action"],
        "arguments": resolved_inputs,
        "timeout_seconds": action["timeout_seconds"],
        "idempotent": True,
    }
    for key in ("cleanup", "expected_evidence", "side_effects", "egress_policy"):
        if key in action:
            operation[key] = action[key]
    return ActionPlan.create(
        plan_id=f"plan-{identity[:24]}",
        engagement_id=definition.engagement_id,
        scenario_id=definition.scenario_id,
        target=action["target"],
        specialist_id=action["specialist_id"],
        operations=[operation],
        limits=action["limits"],
        credential_references=action.get("credential_references", []),
        created_at=created_at,
        platform_prerequisites=action.get("platform_prerequisites", []),
    )


class _BaselineDefinitionView:
    """Expose the implicit retry policy used with baseline workflow documents."""

    def __init__(self, definition: WorkflowDefinition) -> None:
        self._definition = definition

    def __getattr__(self, name: str) -> Any:
        return getattr(self._definition, name)

    @property
    def stages(self) -> list[dict[str, Any]]:
        stages = self._definition.stages
        for stage in stages:
            stage["action"]["idempotent"] = True
        return stages

    def stage(self, stage_id: str) -> dict[str, Any]:
        stage = self._definition.stage(stage_id)
        stage["action"]["idempotent"] = True
        return stage


def _legacy_final_planned_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *final_results: StageExecutionResult | Exception,
) -> tuple[WorkflowDefinition, WorkflowRunner, QueueExecutor, TestApprovalControl, list[str], Path]:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=3, cleanup=True))
    baseline_definition = _BaselineDefinitionView(definition)
    plans = [
        _baseline_compile_action_plan(definition, "run-1", "probe", {"query": "ioc"}, NOW, attempt=attempt)
        for attempt in (1, 2)
    ]
    store = ApprovalStore(tmp_path / "approval" / "approvals.sqlite3")
    authorization_ids: list[str] = []
    control = None
    for plan in plans:
        authorization, trust_store, engagement = authorize_test_plan(plan, worker_identity=WORKER)
        store.store_authorization(authorization)
        authorization_ids.append(authorization.authorization_id)
        if control is None:
            control = TestApprovalControl(store, trust_store, engagement)
    assert control is not None
    executor = QueueExecutor(
        StageExecutionResult("failed", {}, (), "baseline retryable failure"),
        *final_results,
    )
    runner = WorkflowRunner(tmp_path / "state", control, WORKER, executor, clock=lambda: NOW)
    consume = control.consume_authorization

    def stop_before_final_consume(authorization_id: str, *args: Any, **kwargs: Any) -> Any:
        if authorization_id == authorization_ids[1]:
            raise RuntimeError("crash before final consume")
        return consume(authorization_id, *args, **kwargs)

    monkeypatch.setattr(workflow_runtime, "compile_action_plan", _baseline_compile_action_plan)
    monkeypatch.setattr(control, "consume_authorization", stop_before_final_consume)
    with pytest.raises(RuntimeError, match="crash before final consume"):
        runner.run(
            baseline_definition,
            "run-1",
            {"query": "ioc"},
            {"probe:1": authorization_ids[0], "probe:2": authorization_ids[1]},
        )
    monkeypatch.setattr(workflow_runtime, "compile_action_plan", compile_action_plan)
    monkeypatch.setattr(control, "consume_authorization", consume)
    state_path = next((tmp_path / "state").glob("run-*.json"))
    return definition, runner, executor, control, authorization_ids, state_path


def test_compiled_action_plan_defaults_non_idempotent_and_binds_explicit_opt_in() -> None:
    default_definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2))
    opted_in_definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, idempotent=True))

    default_plan = compile_action_plan(default_definition, "run-1", "probe", {"query": "ioc"}, NOW)
    opted_in_plan = compile_action_plan(opted_in_definition, "run-1", "probe", {"query": "ioc"}, NOW)

    assert default_plan.operations[0]["idempotent"] is False
    assert opted_in_plan.operations[0]["idempotent"] is True
    assert default_plan.plan_digest != opted_in_plan.plan_digest


@pytest.mark.parametrize("malformed", [0, 1, "true", None, [], {}])
def test_action_idempotent_rejects_nonboolean_values(malformed: object) -> None:
    document = workflow_document()
    document["stages"][0]["action"]["idempotent"] = malformed

    with pytest.raises(WorkflowContractError, match="idempotent_flag"):
        WorkflowDefinition.from_dict(document)

    schema = json.loads(
        (Path(__file__).parents[1] / "catalog/schemas/workflow-definition.schema.json").read_text(encoding="utf-8")
    )
    assert list(Draft202012Validator(schema).iter_errors(document))


@pytest.mark.parametrize("status", ["failed", "partial"])
def test_non_idempotent_result_never_retries_or_consumes_second_approval(tmp_path: Path, status: str) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, cleanup=True))
    executor = QueueExecutor(
        StageExecutionResult(status, {}, (), "uncertain side effects"),
        StageExecutionResult("success", {"count": 1}),
    )
    runner, authorizations, control = authorized_runner(tmp_path, definition, executor, attempts=2)

    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    reloaded = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    assert result.status == reloaded.status == "partial_failure"
    assert result.stages["probe"]["status"] == status
    assert len(executor.execute_calls) == 1
    assert len(executor.cleanup_calls) == 1
    assert [call[0] for call in control.consume_calls] == [authorizations["probe:1"]]


def test_non_idempotent_interruption_reconciles_and_cleans_up_without_retry(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, cleanup=True))
    executor = QueueExecutor(RuntimeError("process lost"), StageExecutionResult("success", {"count": 1}))
    runner, authorizations, control = authorized_runner(tmp_path, definition, executor, attempts=2)

    with pytest.raises(RuntimeError, match="process lost"):
        runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    reloaded = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    assert result.status == reloaded.status == "partial_failure"
    assert result.stages["probe"]["status"] == "interrupted"
    assert len(executor.execute_calls) == 1
    assert len(executor.cleanup_calls) == 1
    assert [call[0] for call in control.consume_calls] == [authorizations["probe:1"]]


def test_explicit_idempotence_allows_fresh_approval_with_stable_logical_key(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, idempotent=True))
    executor = QueueExecutor(
        StageExecutionResult("failed", {}, (), "retryable failure"),
        StageExecutionResult("success", {"count": 1}),
    )
    runner, authorizations, control = authorized_runner(tmp_path, definition, executor, attempts=2)

    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    assert result.status == "success"
    assert len(executor.execute_calls) == 2
    assert executor.execute_calls[0][1] == executor.execute_calls[1][1]
    assert [call[0] for call in control.consume_calls] == [authorizations["probe:1"], authorizations["probe:2"]]


@pytest.mark.parametrize("final_status", ["success", "failed", "partial"])
def test_legacy_multi_attempt_final_result_remains_valid_and_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, final_status: str
) -> None:
    outputs = {"count": 1} if final_status == "success" else {}
    definition, runner, executor, control, authorization_ids, _ = _legacy_final_planned_attempt(
        tmp_path,
        monkeypatch,
        StageExecutionResult(final_status, outputs, (), "final legacy result"),
        StageExecutionResult("success", {"count": 2}),
    )

    result = runner.run(definition, "run-1", {"query": "ioc"}, {})
    reloaded = runner.run(definition, "run-1", {"query": "ioc"}, {"probe:3": "unused"})

    expected_status = "success" if final_status == "success" else "partial_failure"
    assert result.status == reloaded.status == expected_status
    assert result.stages["probe"]["status"] == final_status
    assert len(executor.execute_calls) == 2
    assert [call[0] for call in control.consume_calls] == authorization_ids


def test_legacy_multi_attempt_interruption_reconciles_cleanup_and_remains_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    definition, runner, executor, control, authorization_ids, _ = _legacy_final_planned_attempt(
        tmp_path,
        monkeypatch,
        RuntimeError("legacy final interrupted"),
        StageExecutionResult("success", {"count": 2}),
    )

    with pytest.raises(RuntimeError, match="legacy final interrupted"):
        runner.run(definition, "run-1", {"query": "ioc"}, {})
    result = runner.run(definition, "run-1", {"query": "ioc"}, {})
    reloaded = runner.run(definition, "run-1", {"query": "ioc"}, {})

    assert result.status == reloaded.status == "partial_failure"
    assert result.stages["probe"]["status"] == "interrupted"
    assert len(executor.execute_calls) == 2
    assert len(executor.cleanup_calls) == 2
    assert [call[0] for call in control.consume_calls] == authorization_ids


def test_legacy_multi_attempt_requires_every_plan_to_match_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    definition, runner, executor, control, authorization_ids, state_path = _legacy_final_planned_attempt(
        tmp_path, monkeypatch, StageExecutionResult("success", {"count": 1})
    )
    envelope = json.loads(state_path.read_text(encoding="utf-8"))
    envelope["payload"]["stages"]["probe"]["attempts"][0]["plan"]["plan_digest"] = "b" * 64
    envelope["digest"] = digest(envelope["payload"])
    state_path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(WorkflowRuntimeError, match="state_tampering"):
        runner.run(definition, "run-1", {"query": "ioc"}, {})
    assert len(executor.execute_calls) == 1
    assert [call[0] for call in control.consume_calls] == authorization_ids[:1]


def test_idempotence_change_invalidates_persisted_planned_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = WorkflowDefinition.from_dict(workflow_document(idempotent=True))
    executor = QueueExecutor(StageExecutionResult("success", {"count": 1}))
    runner, authorizations, control = authorized_runner(tmp_path, original, executor, attempts=1)
    monkeypatch.setattr(
        control,
        "consume_authorization",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("crash before consume")),
    )

    with pytest.raises(RuntimeError, match="crash before consume"):
        runner.run(original, "run-1", {"query": "ioc"}, authorizations)

    changed_document = deepcopy(original.to_dict())
    changed_document["stages"][0]["action"]["idempotent"] = False
    changed = WorkflowDefinition.from_dict(changed_document)
    with pytest.raises(WorkflowRuntimeError, match="resume_binding_mismatch"):
        runner.run(changed, "run-1", {"query": "ioc"}, {})
