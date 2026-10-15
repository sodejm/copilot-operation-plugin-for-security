"""Crash-aware execution of validated workflow definitions.

The runtime deliberately delegates authorization to ``ApprovalControl``.  A
workflow never creates or broadens an authorization; every stage compiles to an
exact ``ActionPlan`` which must be consumed by the existing authority.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import canonical, decode_json, digest, utc_now
from cops.execution.control import ApprovalConsumptionReceipt, ApprovalControl, ApprovalControlError

from .contracts import WorkflowContractError, WorkflowDefinition, value_matches_type


class WorkflowRuntimeError(RuntimeError):
    """Execution or persisted state could not be trusted."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class StageExecutionResult:
    status: str
    outputs: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class WorkflowRunResult:
    run_id: str
    status: str
    outputs: dict[str, Any]
    stages: dict[str, dict[str, Any]]


class WorkflowExecutor(Protocol):
    def execute(
        self, plan: ActionPlan, receipt: ApprovalConsumptionReceipt, *, idempotency_key: str
    ) -> StageExecutionResult: ...

    def cleanup(self, plan: ActionPlan, *, idempotency_key: str) -> None: ...


def compile_action_plan(
    definition: WorkflowDefinition,
    run_id: str,
    stage_id: str,
    resolved_inputs: dict[str, Any],
    created_at: str,
    *,
    attempt: int = 1,
) -> ActionPlan:
    """Compile one stage to the repository's immutable approval-bound plan."""
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
    operation: dict[str, Any] = {
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


class WorkflowRunner:
    """Execute a typed DAG with tamper-evident, resumable receipts."""

    def __init__(
        self,
        state_dir: str | Path,
        approval_control: ApprovalControl,
        worker_identity: str,
        executor: WorkflowExecutor,
        *,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.approval_control = approval_control
        self.worker_identity = worker_identity
        self.executor = executor
        self.clock = clock

    def run(
        self,
        definition: WorkflowDefinition,
        run_id: str,
        inputs: dict[str, Any],
        authorization_ids: dict[str, str],
        *,
        cancellation_requested: Callable[[], bool] = lambda: False,
    ) -> WorkflowRunResult:
        resolved_workflow_inputs = _validate_inputs(definition, inputs)
        self.approval_control.assert_ready(self.worker_identity)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_path = self.state_dir / f"run-{digest({'run_id': run_id})[:32]}.json"
        state = self._load_or_create_state(state_path, definition, run_id, resolved_workflow_inputs)

        # A process stopped after consuming approval has an uncertain side effect.
        # It advances to a separately authorized retry with the same idempotency key.
        for stage_state in state["stages"].values():
            if stage_state.get("status") == "authorized":
                stage_state["status"] = "interrupted"
                if stage_state.get("attempts"):
                    stage_state["attempts"][-1]["status"] = "interrupted"
                self._write_state(state_path, state)

        stage_map = {stage["stage_id"]: stage for stage in definition.stages}
        for stage_id in _topological_order(stage_map):
            stage = stage_map[stage_id]
            existing = state["stages"].get(stage_id)
            if existing and existing["status"] in {"success", "skipped"}:
                continue
            if existing:
                self._resume_cleanup(definition, run_id, stage, existing, state_path, state)
            if cancellation_requested():
                state["status"] = "cancelled"
                self._write_state(state_path, state)
                return self._result(state, definition)
            if any(state["stages"].get(dep, {}).get("status") != "success" for dep in stage["depends_on"]):
                state["status"] = "partial_failure"
                self._write_state(state_path, state)
                return self._result(state, definition)
            if not _condition_matches(stage.get("condition"), resolved_workflow_inputs, state):
                state["stages"][stage_id] = {"status": "skipped", "attempts": [], "outputs": {}, "evidence_refs": []}
                self._write_state(state_path, state)
                continue

            resolved = _resolve_bindings(stage["inputs"], resolved_workflow_inputs, state)
            attempts = list(existing.get("attempts", [])) if existing else []
            max_attempts = stage.get("retry", {}).get("max_attempts", 1)
            start_attempt = len(attempts) + 1
            succeeded = False
            for attempt in range(start_attempt, max_attempts + 1):
                if cancellation_requested():
                    state["status"] = "cancelled"
                    self._write_state(state_path, state)
                    return self._result(state, definition)
                if len(state["consumed_authorizations"]) >= definition.budget["max_total_attempts"]:
                    raise WorkflowRuntimeError("attempt_budget_exhausted")
                created_at = self.clock()
                plan = compile_action_plan(definition, run_id, stage_id, resolved, created_at, attempt=attempt)
                key = f"{stage_id}:{attempt}"
                authorization_id = authorization_ids.get(key) or (
                    authorization_ids.get(stage_id) if attempt == 1 else None
                )
                if not authorization_id:
                    raise WorkflowRuntimeError("missing_stage_authorization")
                if authorization_id in state["consumed_authorizations"]:
                    raise WorkflowRuntimeError("replayed_authorization")
                attempt_record = {
                    "attempt": attempt,
                    "authorization_id": authorization_id,
                    "plan": plan.approved_snapshot(include_digest=True),
                    "status": "planned",
                }
                attempts.append(attempt_record)
                state["stages"][stage_id] = {
                    "status": "planned",
                    "attempts": attempts,
                    "outputs": {},
                    "evidence_refs": [],
                }
                self._write_state(state_path, state)
                receipt: ApprovalConsumptionReceipt | None = None
                idempotency_key = digest(
                    {"workflow_digest": definition.definition_digest, "run_id": run_id, "stage_id": stage_id}
                )
                try:
                    receipt = self.approval_control.consume_authorization(authorization_id, plan, self.worker_identity)
                    verified = self.approval_control.validate_receipt_provenance(receipt)
                    if verified is not receipt or not _receipt_matches(
                        receipt, authorization_id, plan, self.worker_identity
                    ):
                        raise ApprovalControlError("approval authority receipt does not match the workflow stage plan")
                    state["consumed_authorizations"].append(authorization_id)
                    attempt_record["authorization_digest"] = receipt.authorization_digest
                    attempt_record["status"] = "authorized"
                    state["stages"][stage_id]["status"] = "authorized"
                    self._write_state(state_path, state)
                    result = self.executor.execute(plan, receipt, idempotency_key=idempotency_key)
                    _validate_stage_result(result, stage)
                    self._check_prospective_budgets(definition, state, stage_id, result)
                    artifact = self._persist_artifact(
                        run_id, stage_id, attempt, result, stage["action"]["limits"]["max_output_bytes"]
                    )
                    attempt_record.update({"status": result.status, "artifact": artifact, "reason": result.reason})
                    stage_state = state["stages"][stage_id]
                    stage_state.update(
                        {
                            "status": result.status,
                            "outputs": result.outputs,
                            "evidence_refs": list(result.evidence_refs),
                        }
                    )
                    self._check_budgets(definition, state)
                    self._write_state(state_path, state)
                    if result.status == "success":
                        succeeded = True
                        break
                    self._cleanup(stage, plan, idempotency_key, attempt_record, state_path, state)
                finally:
                    if receipt is not None:
                        self.approval_control.release_receipt_provenance(receipt)
            if not succeeded:
                state["status"] = "partial_failure"
                self._write_state(state_path, state)
                return self._result(state, definition)

        state["status"] = "success"
        self._write_state(state_path, state)
        return self._result(state, definition)

    def _resume_cleanup(
        self,
        definition: WorkflowDefinition,
        run_id: str,
        stage: dict[str, Any],
        stage_state: dict[str, Any],
        state_path: Path,
        state: dict[str, Any],
    ) -> None:
        """Finish an authorized cleanup before cancellation or another attempt."""
        attempts = stage_state.get("attempts", [])
        if "cleanup" not in stage["action"] or not attempts:
            return
        attempt_record = attempts[-1]
        if attempt_record.get("status") not in {"failed", "partial", "interrupted"}:
            return
        if attempt_record.get("cleanup_completed") is True:
            return
        snapshot = attempt_record.get("plan")
        if not isinstance(snapshot, dict):
            raise WorkflowRuntimeError("state_tampering")
        try:
            plan = ActionPlan.from_dict({**snapshot, "status": "draft"})
        except Exception as exc:
            raise WorkflowRuntimeError("state_tampering") from exc
        idempotency_key = digest(
            {"workflow_digest": definition.definition_digest, "run_id": run_id, "stage_id": stage["stage_id"]}
        )
        self._cleanup(stage, plan, idempotency_key, attempt_record, state_path, state)

    def _cleanup(
        self,
        stage: dict[str, Any],
        plan: ActionPlan,
        idempotency_key: str,
        attempt_record: dict[str, Any],
        state_path: Path,
        state: dict[str, Any],
    ) -> None:
        if "cleanup" not in stage["action"]:
            return
        self.executor.cleanup(plan, idempotency_key=idempotency_key)
        attempt_record["cleanup_completed"] = True
        self._write_state(state_path, state)

    def _load_or_create_state(
        self, path: Path, definition: WorkflowDefinition, run_id: str, inputs: dict[str, Any]
    ) -> dict[str, Any]:
        if path.exists():
            try:
                envelope = decode_json(path.read_bytes(), max_bytes=definition.budget["max_output_bytes"] + 2_097_152)
            except Exception as exc:
                raise WorkflowRuntimeError("state_tampering") from exc
            state = _verify_envelope(envelope, "state_tampering")
            if (
                state.get("run_id") != run_id
                or state.get("workflow_digest") != definition.definition_digest
                or state.get("inputs_digest") != digest(inputs)
            ):
                raise WorkflowRuntimeError("resume_binding_mismatch")
            self._verify_artifacts(state)
            return state
        state = {
            "schema_version": "cops.workflow-run-state/v1",
            "run_id": run_id,
            "workflow_digest": definition.definition_digest,
            "inputs_digest": digest(inputs),
            "status": "running",
            "stages": {},
            "consumed_authorizations": [],
        }
        self._write_state(path, state)
        return state

    def _persist_artifact(
        self, run_id: str, stage_id: str, attempt: int, result: StageExecutionResult, max_output_bytes: int
    ) -> dict[str, str]:
        payload = {
            "schema_version": "cops.workflow-stage-result/v1",
            "run_id": run_id,
            "stage_id": stage_id,
            "attempt": attempt,
            "status": result.status,
            "outputs": result.outputs,
            "evidence_refs": list(result.evidence_refs),
            "reason": result.reason,
        }
        envelope = {"payload": payload, "digest": digest(payload)}
        name = f"stage-{digest({'run_id': run_id, 'stage_id': stage_id, 'attempt': attempt})[:32]}.json"
        path = self.state_dir / name
        encoded = canonical(envelope, max_bytes=max_output_bytes + 1_048_576)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.read_bytes() != encoded:
                raise WorkflowRuntimeError("duplicate_output_write") from None
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        return {"file": name, "digest": envelope["digest"]}

    def _verify_artifacts(self, state: dict[str, Any]) -> None:
        for stage_id, stage in state.get("stages", {}).items():
            for attempt in stage.get("attempts", []):
                artifact = attempt.get("artifact")
                if not artifact:
                    continue
                expected_name = f"stage-{digest({'run_id': state['run_id'], 'stage_id': stage_id, 'attempt': attempt['attempt']})[:32]}.json"
                if (
                    not isinstance(artifact, dict)
                    or set(artifact) != {"file", "digest"}
                    or artifact["file"] != expected_name
                ):
                    raise WorkflowRuntimeError("output_tampering")
                path = self.state_dir / expected_name
                if not path.is_file():
                    raise WorkflowRuntimeError("missing_stage_artifact")
                try:
                    envelope = decode_json(path.read_bytes(), max_bytes=106_954_752)
                except Exception as exc:
                    raise WorkflowRuntimeError("output_tampering") from exc
                payload = _verify_envelope(envelope, "output_tampering")
                expected = {
                    "run_id": state["run_id"],
                    "stage_id": stage_id,
                    "attempt": attempt["attempt"],
                    "status": attempt["status"],
                    "reason": attempt.get("reason", ""),
                }
                if (
                    any(payload.get(key) != value for key, value in expected.items())
                    or digest(payload) != artifact["digest"]
                ):
                    raise WorkflowRuntimeError("output_tampering")
                if stage["attempts"][-1] is attempt and stage.get("status") == payload["status"]:
                    if (
                        stage.get("outputs") != payload["outputs"]
                        or stage.get("evidence_refs") != payload["evidence_refs"]
                    ):
                        raise WorkflowRuntimeError("output_tampering")

    def _write_state(self, path: Path, state: dict[str, Any]) -> None:
        envelope = {"payload": state, "digest": digest(state)}
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(canonical(envelope, max_bytes=104_857_600 + 2_097_152))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _check_budgets(self, definition: WorkflowDefinition, state: dict[str, Any]) -> None:
        evidence_count = sum(len(item.get("evidence_refs", [])) for item in state["stages"].values())
        output_size = sum(len(canonical(item.get("outputs", {}))) for item in state["stages"].values())
        if evidence_count > definition.budget["max_evidence_refs"]:
            raise WorkflowRuntimeError("evidence_budget_exceeded")
        if output_size > definition.budget["max_output_bytes"]:
            raise WorkflowRuntimeError("output_budget_exceeded")

    def _check_prospective_budgets(
        self, definition: WorkflowDefinition, state: dict[str, Any], stage_id: str, result: StageExecutionResult
    ) -> None:
        stages = {name: value for name, value in state["stages"].items() if name != stage_id}
        stages[stage_id] = {"outputs": result.outputs, "evidence_refs": list(result.evidence_refs)}
        self._check_budgets(definition, {"stages": stages})

    @staticmethod
    def _result(state: dict[str, Any], definition: WorkflowDefinition) -> WorkflowRunResult:
        outputs: dict[str, Any] = {}
        if state["status"] == "success":
            for name, spec in definition.outputs.items():
                outputs[name] = _resolve_source(spec["source"], {}, state)
        return WorkflowRunResult(state["run_id"], state["status"], outputs, json.loads(json.dumps(state["stages"])))


def _validate_inputs(definition: WorkflowDefinition, inputs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, dict) or set(inputs) - set(definition.inputs):
        raise WorkflowContractError("workflow_inputs")
    result: dict[str, Any] = {}
    for name, spec in definition.inputs.items():
        if name in inputs:
            value = inputs[name]
        elif "default" in spec:
            value = spec["default"]
        elif spec.get("required", True):
            raise WorkflowContractError("missing_workflow_input")
        else:
            continue
        if not value_matches_type(value, spec["type"]):
            raise WorkflowContractError("workflow_input_type")
        result[name] = value
    return result


def _topological_order(stage_map: dict[str, dict[str, Any]]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    def visit(stage_id: str) -> None:
        if stage_id in seen:
            return
        for dependency in stage_map[stage_id]["depends_on"]:
            visit(dependency)
        seen.add(stage_id)
        result.append(stage_id)

    for stage_id in stage_map:
        visit(stage_id)
    return result


def _resolve_source(source: str, inputs: dict[str, Any], state: dict[str, Any]) -> Any:
    parts = source.split(".")
    try:
        if parts[:2] == ["workflow", "input"]:
            return inputs[parts[2]]
        return state["stages"][parts[1]]["outputs"][parts[3]]
    except (KeyError, IndexError) as exc:
        code = "missing_bound_input" if parts[:2] == ["workflow", "input"] else "invalid_persisted_output"
        raise WorkflowRuntimeError(code) from exc


def _resolve_bindings(bindings: dict[str, Any], inputs: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    resolved = {
        name: (binding["value"] if "value" in binding else _resolve_source(binding["source"], inputs, state))
        for name, binding in bindings.items()
    }
    if any(not value_matches_type(resolved[name], binding["type"]) for name, binding in bindings.items()):
        raise WorkflowRuntimeError("binding_runtime_type")
    return resolved


def _condition_matches(condition: dict[str, Any] | None, inputs: dict[str, Any], state: dict[str, Any]) -> bool:
    if condition is None:
        return True
    try:
        actual = _resolve_source(condition["source"], inputs, state)
        exists = True
    except WorkflowRuntimeError:
        actual = None
        exists = False
    if condition["operator"] == "exists":
        return exists
    return (actual == condition["value"]) == (condition["operator"] == "eq")


def _validate_stage_result(result: StageExecutionResult, stage: dict[str, Any]) -> None:
    if not isinstance(result, StageExecutionResult) or result.status not in {"success", "failed", "partial"}:
        raise WorkflowRuntimeError("invalid_stage_result")
    if set(result.outputs) - set(stage["outputs"]):
        raise WorkflowRuntimeError("undeclared_stage_output")
    if result.status == "success" and set(result.outputs) != set(stage["outputs"]):
        raise WorkflowRuntimeError("missing_stage_output")
    for name, value in result.outputs.items():
        if not value_matches_type(value, stage["outputs"][name]["type"]):
            raise WorkflowRuntimeError("stage_output_type")
    if not all(isinstance(item, str) and item for item in result.evidence_refs):
        raise WorkflowRuntimeError("invalid_evidence_ref")
    try:
        canonical(result.outputs, max_bytes=stage["action"]["limits"]["max_output_bytes"])
    except Exception as exc:
        raise WorkflowRuntimeError("stage_output_budget_exceeded") from exc


def _receipt_matches(
    receipt: ApprovalConsumptionReceipt, authorization_id: str, plan: ActionPlan, worker_identity: str
) -> bool:
    return (
        receipt.authorization_id == authorization_id
        and receipt.action_plan_id == plan.plan_id
        and receipt.plan_digest == plan.plan_digest
        and receipt.engagement_id == plan.engagement_id
        and receipt.worker_identity == worker_identity
        and receipt.target == plan.target
    )


def _verify_envelope(envelope: Any, code: str) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "digest"}:
        raise WorkflowRuntimeError(code)
    if not isinstance(envelope["payload"], dict) or digest(envelope["payload"]) != envelope["digest"]:
        raise WorkflowRuntimeError(code)
    return envelope["payload"]
