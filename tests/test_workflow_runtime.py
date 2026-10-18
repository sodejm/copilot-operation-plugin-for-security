from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from cops.execution.authorization import AuthorizationError
from cops.execution.store import ApprovalStore
from cops.workflows import (
    StageExecutionResult,
    WorkflowContractError,
    WorkflowDefinition,
    WorkflowRunner,
    WorkflowRuntimeError,
    compile_action_plan,
)
from tests.auth_testkit import TestApprovalControl, authorize_test_plan

NOW = "2026-10-15T12:00:00Z"
WORKER = "workflow-worker"


def workflow_document(*, max_attempts: int = 1, cleanup: bool = False) -> dict[str, Any]:
    action: dict[str, Any] = {
        "target": "lab://fixture",
        "specialist_id": "lab-worker",
        "tool": "fixture-probe",
        "tool_version": "1.0.0",
        "action": "probe",
        "timeout_seconds": 30,
        "limits": {
            "max_duration_seconds": 30,
            "max_output_bytes": 4096,
            "egress_allowed": False,
        },
    }
    if cleanup:
        action["cleanup"] = {"strategy": "none", "resources": []}
    return {
        "schema_version": "cops.workflow-definition/v1",
        "workflow_id": "ioc-flow",
        "engagement_id": "eng-workflows",
        "scenario_id": "COPS-E99.01-S01",
        "inputs": {"query": {"type": "string", "required": True}},
        "outputs": {"count": {"type": "integer", "source": "stage.probe.output.count"}},
        "budget": {
            "max_stages": 4,
            "max_total_attempts": max_attempts,
            "max_output_bytes": 4096,
            "max_evidence_refs": 4,
        },
        "stages": [
            {
                "stage_id": "probe",
                "depends_on": [],
                "inputs": {"query": {"type": "string", "source": "workflow.input.query"}},
                "outputs": {"count": {"type": "integer"}},
                "retry": {"max_attempts": max_attempts},
                "action": action,
            }
        ],
    }


class QueueExecutor:
    def __init__(self, *results: StageExecutionResult | Exception, cleanup_failures: int = 0) -> None:
        self.results = list(results)
        self.cleanup_failures = cleanup_failures
        self.execute_calls: list[tuple[Any, str]] = []
        self.cleanup_calls: list[tuple[Any, str]] = []

    def execute(self, plan: Any, receipt: Any, *, idempotency_key: str) -> StageExecutionResult:
        self.execute_calls.append((plan, idempotency_key))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def cleanup(self, plan: Any, *, idempotency_key: str) -> None:
        self.cleanup_calls.append((plan, idempotency_key))
        if self.cleanup_failures:
            self.cleanup_failures -= 1
            raise RuntimeError("cleanup interrupted")


def authorized_runner(
    tmp_path: Path,
    definition: WorkflowDefinition,
    executor: QueueExecutor,
    *,
    attempts: int,
) -> tuple[WorkflowRunner, dict[str, str], TestApprovalControl]:
    store = ApprovalStore(tmp_path / "approval" / "approvals.sqlite3")
    authorizations: dict[str, str] = {}
    control = None
    for attempt in range(1, attempts + 1):
        plan = compile_action_plan(definition, "run-1", "probe", {"query": "ioc"}, NOW, attempt=attempt)
        authorization, trust_store, engagement = authorize_test_plan(plan, worker_identity=WORKER)
        store.store_authorization(authorization)
        authorizations[f"probe:{attempt}"] = authorization.authorization_id
        if control is None:
            control = TestApprovalControl(store, trust_store, engagement)
    assert control is not None
    return WorkflowRunner(tmp_path / "state", control, WORKER, executor, clock=lambda: NOW), authorizations, control


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda doc: doc["stages"][0]["inputs"].update({"query": {"type": "integer", "value": "bad"}}),
            "binding_value_type",
        ),
        (lambda doc: doc["stages"][0]["outputs"].update({"count": {"type": "string"}}), "workflow_output_type"),
        (lambda doc: doc["stages"][0].update({"depends_on": ["probe"]}), "dependency_cycle"),
        (lambda doc: doc["outputs"]["count"].update({"source": "stage.probe.output.missing"}), "missing_output_ref"),
        (lambda doc: doc["budget"].update({"max_total_attempts": 1}), "attempt_budget"),
        (
            lambda doc: doc["stages"][0]["action"].update({"target": "${workflow.input.query}"}),
            "literal_action_binding",
        ),
    ],
)
def test_contract_rejects_invalid_types_graphs_outputs_and_budgets(mutate: Any, code: str) -> None:
    document = workflow_document(max_attempts=2)
    mutate(document)
    with pytest.raises(WorkflowContractError, match=code):
        WorkflowDefinition.from_dict(document)


def test_action_plan_binds_exact_action_target_inputs_and_attempt() -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2))
    first = compile_action_plan(definition, "run-1", "probe", {"query": "ioc"}, NOW)
    second = compile_action_plan(definition, "run-1", "probe", {"query": "ioc"}, NOW, attempt=2)

    assert first.target == "lab://fixture"
    assert first.operations[0]["action"] == "probe"
    assert first.operations[0]["arguments"] == {"query": "ioc"}
    assert first.plan_digest != second.plan_digest


def test_success_persists_outputs_and_safe_resume_does_not_duplicate_execution(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document())
    executor = QueueExecutor(StageExecutionResult("success", {"count": 2}, ("evidence://probe",)))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=1)

    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    resumed = runner.run(definition, "run-1", {"query": "ioc"}, {})

    assert result.status == "success"
    assert result.outputs == {"count": 2}
    assert resumed.outputs == {"count": 2}
    assert len(executor.execute_calls) == 1


def test_retry_uses_fresh_authorization_same_idempotency_key_and_cleanup(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, cleanup=True))
    executor = QueueExecutor(
        StageExecutionResult("failed", {}, (), "temporary failure"),
        StageExecutionResult("success", {"count": 1}, ("evidence://retry",)),
    )
    runner, authorizations, control = authorized_runner(tmp_path, definition, executor, attempts=2)

    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    assert result.status == "success"
    assert len({call[1] for call in executor.execute_calls}) == 1
    assert len(executor.cleanup_calls) == 1
    assert [call[0] for call in control.consume_calls] == [authorizations["probe:1"], authorizations["probe:2"]]


def test_interrupted_authorized_attempt_cannot_replay_approval(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, cleanup=True))
    executor = QueueExecutor(RuntimeError("process lost"), StageExecutionResult("success", {"count": 1}))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=2)

    with pytest.raises(RuntimeError, match="process lost"):
        runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    replayed = {"probe:2": authorizations["probe:1"]}
    with pytest.raises(WorkflowRuntimeError, match="replayed_authorization"):
        runner.run(definition, "run-1", {"query": "ioc"}, replayed)

    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    assert result.status == "success"
    assert len(executor.cleanup_calls) == 1


def test_restart_finishes_interrupted_cleanup_before_retry(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(max_attempts=2, cleanup=True))
    executor = QueueExecutor(
        StageExecutionResult("failed", {}, (), "failure"),
        StageExecutionResult("success", {"count": 1}),
        cleanup_failures=1,
    )
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=2)

    with pytest.raises(RuntimeError, match="cleanup interrupted"):
        runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    assert result.status == "success"
    assert len(executor.cleanup_calls) == 2
    assert executor.cleanup_calls[0][1] == executor.cleanup_calls[1][1]


def test_cancellation_before_stage_does_not_consume_or_execute(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document())
    executor = QueueExecutor(StageExecutionResult("success", {"count": 1}))
    runner, authorizations, control = authorized_runner(tmp_path, definition, executor, attempts=1)

    result = runner.run(
        definition,
        "run-1",
        {"query": "ioc"},
        authorizations,
        cancellation_requested=lambda: True,
    )

    assert result.status == "cancelled"
    assert executor.execute_calls == []
    assert control.consume_calls == []


def test_changed_action_requires_new_exact_plan_authorization(tmp_path: Path) -> None:
    original = WorkflowDefinition.from_dict(workflow_document())
    executor = QueueExecutor(StageExecutionResult("success", {"count": 1}))
    runner, authorizations, _ = authorized_runner(tmp_path, original, executor, attempts=1)
    changed_doc = workflow_document()
    changed_doc["stages"][0]["action"]["action"] = "contain"
    changed = WorkflowDefinition.from_dict(changed_doc)

    with pytest.raises(AuthorizationError):
        runner.run(changed, "run-2", {"query": "ioc"}, {"probe": authorizations["probe:1"]})
    assert executor.execute_calls == []


def test_tampered_artifact_is_detected_before_resume(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document())
    executor = QueueExecutor(StageExecutionResult("success", {"count": 1}))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=1)
    runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    artifact = next((tmp_path / "state").glob("stage-*.json"))
    envelope = json.loads(artifact.read_text(encoding="utf-8"))
    envelope["payload"]["outputs"]["count"] = 999
    artifact.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(WorkflowRuntimeError, match="output_tampering"):
        runner.run(definition, "run-1", {"query": "ioc"}, {})


def test_duplicate_output_write_and_stage_output_type_fail_closed(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document())
    executor = QueueExecutor(StageExecutionResult("success", {"count": "wrong"}))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=1)
    with pytest.raises(WorkflowRuntimeError, match="stage_output_type"):
        runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    first = StageExecutionResult("success", {"count": 1})
    second = StageExecutionResult("success", {"count": 2})
    runner._persist_artifact("other-run", "probe", 1, first, 4096)
    with pytest.raises(WorkflowRuntimeError, match="duplicate_output_write"):
        runner._persist_artifact("other-run", "probe", 1, second, 4096)


def test_evidence_budget_is_checked_before_artifact_write(tmp_path: Path) -> None:
    document = workflow_document()
    document["budget"]["max_evidence_refs"] = 1
    definition = WorkflowDefinition.from_dict(document)
    executor = QueueExecutor(StageExecutionResult("success", {"count": 1}, ("a", "b")))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=1)

    with pytest.raises(WorkflowRuntimeError, match="evidence_budget_exceeded"):
        runner.run(definition, "run-1", {"query": "ioc"}, authorizations)
    assert list((tmp_path / "state").glob("stage-*.json")) == []


def test_exhausted_failure_returns_partial_failure_and_runs_cleanup(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document(cleanup=True))
    executor = QueueExecutor(StageExecutionResult("failed", {}, (), "permanent failure"))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=1)

    result = runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    assert result.status == "partial_failure"
    assert result.stages["probe"]["status"] == "failed"
    assert len(executor.cleanup_calls) == 1


def test_workflow_json_schema_is_strict_and_rejects_dynamic_action_scope() -> None:
    schema = json.loads(
        (Path(__file__).parents[1] / "catalog/schemas/workflow-definition.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    document = workflow_document()
    validator.validate(document)

    unexpected = deepcopy(document)
    unexpected["unexpected"] = True
    assert list(validator.iter_errors(unexpected))

    dynamic_target = deepcopy(document)
    dynamic_target["stages"][0]["action"]["target"] = "${workflow.input.query}"
    assert list(validator.iter_errors(dynamic_target))


def test_resume_rejects_changed_inputs(tmp_path: Path) -> None:
    definition = WorkflowDefinition.from_dict(workflow_document())
    executor = QueueExecutor(StageExecutionResult("success", {"count": 1}))
    runner, authorizations, _ = authorized_runner(tmp_path, definition, executor, attempts=1)
    runner.run(definition, "run-1", {"query": "ioc"}, authorizations)

    with pytest.raises(WorkflowRuntimeError, match="resume_binding_mismatch"):
        runner.run(definition, "run-1", {"query": "changed"}, {})


def test_definition_is_immutable_from_caller_mutation() -> None:
    document = workflow_document()
    definition = WorkflowDefinition.from_dict(document)
    document["stages"][0]["action"]["target"] = "lab://changed"
    exported = definition.to_dict()
    exported["stages"][0]["action"]["target"] = "lab://also-changed"

    assert definition.stage("probe")["action"]["target"] == "lab://fixture"
