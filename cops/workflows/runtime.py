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
    return _compile_action_plan(
        definition,
        run_id,
        stage_id,
        resolved_inputs,
        created_at,
        attempt=attempt,
        idempotent=action.get("idempotent", False),
    )


def _compile_action_plan(
    definition: WorkflowDefinition,
    run_id: str,
    stage_id: str,
    resolved_inputs: dict[str, Any],
    created_at: str,
    *,
    attempt: int,
    idempotent: bool,
) -> ActionPlan:
    """Compile a plan with an explicit effective idempotence value."""
    action = definition.stage(stage_id)["action"]
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
        "idempotent": idempotent,
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
        self._pending_receipts: dict[str, ApprovalConsumptionReceipt] = {}

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

        # An attempt stopped after consuming approval has an uncertain side
        # effect. Advance it only while the issuing authority still recognizes
        # the exact receipt retained by this runner.
        for stage_state in state["stages"].values():
            if stage_state.get("status") == "authorized":
                self._reconcile_authorized_attempt(stage_state)
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
            if (
                existing
                and existing["status"] in {"failed", "partial", "interrupted"}
                and not stage["action"].get("idempotent", False)
            ):
                state["status"] = "partial_failure"
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
            planned_record = attempts[-1] if existing and existing["status"] == "planned" else None
            start_attempt = planned_record["attempt"] if planned_record else len(attempts) + 1
            succeeded = False
            for attempt in range(start_attempt, max_attempts + 1):
                if cancellation_requested():
                    state["status"] = "cancelled"
                    self._write_state(state_path, state)
                    return self._result(state, definition)
                if len(state["consumed_authorizations"]) >= definition.budget["max_total_attempts"]:
                    raise WorkflowRuntimeError("attempt_budget_exhausted")
                if planned_record is not None and attempt == planned_record["attempt"]:
                    attempt_record = planned_record
                    authorization_id = attempt_record["authorization_id"]
                    plan, _ = _validated_attempt_plan(definition, run_id, stage_id, resolved, attempt_record)
                    planned_record = None
                else:
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
                receipt_retained = False
                idempotency_key = digest(
                    {"workflow_digest": definition.definition_digest, "run_id": run_id, "stage_id": stage_id}
                )
                try:
                    if authorization_id in self._pending_receipts:
                        raise WorkflowRuntimeError("unreconciled_authorization")
                    receipt = self.approval_control.consume_authorization(authorization_id, plan, self.worker_identity)
                    verified = self.approval_control.validate_receipt_provenance(receipt)
                    if verified is not receipt or not _receipt_matches(
                        receipt, authorization_id, plan, self.worker_identity
                    ):
                        raise ApprovalControlError("approval authority receipt does not match the workflow stage plan")
                    self._pending_receipts[authorization_id] = receipt
                    receipt_retained = True
                    state["consumed_authorizations"].append(authorization_id)
                    attempt_record["receipt"] = _receipt_to_dict(receipt)
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
                    self._release_pending_receipt(authorization_id)
                    receipt = None
                    receipt_retained = False
                    if result.status == "success":
                        succeeded = True
                        break
                    self._cleanup(stage, plan, idempotency_key, attempt_record, state_path, state)
                    if not stage["action"].get("idempotent", False):
                        break
                finally:
                    if receipt is not None and not receipt_retained:
                        self.approval_control.release_receipt_provenance(receipt)
            if not succeeded:
                state["status"] = "partial_failure"
                self._write_state(state_path, state)
                return self._result(state, definition)

        state["status"] = "success"
        self._write_state(state_path, state)
        return self._result(state, definition)

    def _reconcile_authorized_attempt(self, stage_state: dict[str, Any]) -> None:
        """Bind an interrupted state to the still-live authority receipt."""
        attempt_record = stage_state["attempts"][-1]
        persisted = _receipt_from_record(attempt_record)
        trusted = self._pending_receipts.get(persisted.authorization_id)
        if trusted is None:
            raise WorkflowRuntimeError("unreconciled_authorization")
        try:
            verified = self.approval_control.validate_receipt_provenance(trusted)
        except ApprovalControlError as exc:
            raise WorkflowRuntimeError("unreconciled_authorization") from exc
        if verified is not trusted or trusted != persisted:
            raise WorkflowRuntimeError("unreconciled_authorization")
        self._release_pending_receipt(persisted.authorization_id)

    def _release_pending_receipt(self, authorization_id: str) -> None:
        receipt = self._pending_receipts[authorization_id]
        self.approval_control.release_receipt_provenance(receipt)
        del self._pending_receipts[authorization_id]

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
            _validate_persisted_state(definition, run_id, inputs, state, self.worker_identity)
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


def _validated_attempt_plan(
    definition: WorkflowDefinition,
    run_id: str,
    stage_id: str,
    resolved_inputs: dict[str, Any],
    attempt_record: dict[str, Any],
) -> tuple[ActionPlan, bool]:
    snapshot = attempt_record.get("plan")
    attempt = attempt_record.get("attempt")
    if not isinstance(snapshot, dict) or type(attempt) is not int:
        raise WorkflowRuntimeError("state_tampering")
    try:
        plan = ActionPlan.from_dict({**snapshot, "status": "draft"})
        expected = compile_action_plan(
            definition,
            run_id,
            stage_id,
            resolved_inputs,
            plan.created_at,
            attempt=attempt,
        )
        action = definition.stage(stage_id)["action"]
        legacy_expected = None
        if "idempotent" not in action:
            legacy_expected = _compile_action_plan(
                definition,
                run_id,
                stage_id,
                resolved_inputs,
                plan.created_at,
                attempt=attempt,
                idempotent=True,
            )
    except Exception as exc:
        raise WorkflowRuntimeError("state_tampering") from exc
    if plan.approved_snapshot(include_digest=True) != snapshot:
        raise WorkflowRuntimeError("state_tampering")
    current_matches = expected.approved_snapshot(include_digest=True) == snapshot
    legacy_matches = legacy_expected is not None and legacy_expected.approved_snapshot(include_digest=True) == snapshot
    if not current_matches and not legacy_matches:
        raise WorkflowRuntimeError("state_tampering")
    return plan, legacy_matches


def _validate_persisted_state(
    definition: WorkflowDefinition,
    run_id: str,
    inputs: dict[str, Any],
    state: dict[str, Any],
    worker_identity: str,
) -> None:
    stage_map = {stage["stage_id"]: stage for stage in definition.stages}
    stages = state.get("stages")
    consumed = state.get("consumed_authorizations")
    if not isinstance(stages, dict) or not isinstance(consumed, list):
        raise WorkflowRuntimeError("state_tampering")
    if any(not isinstance(item, str) or not item for item in consumed) or len(set(consumed)) != len(consumed):
        raise WorkflowRuntimeError("state_tampering")

    recorded_consumptions: set[str] = set()
    recorded_authorizations: set[str] = set()
    for stage_id, stage_state in stages.items():
        if stage_id not in stage_map or not isinstance(stage_state, dict):
            raise WorkflowRuntimeError("state_tampering")
        status = stage_state.get("status")
        attempts = stage_state.get("attempts")
        if status == "skipped":
            if attempts != [] or stage_state.get("outputs") != {} or stage_state.get("evidence_refs") != []:
                raise WorkflowRuntimeError("state_tampering")
            continue
        if status not in {"planned", "authorized", "interrupted", "success", "failed", "partial"}:
            raise WorkflowRuntimeError("state_tampering")
        if (
            not isinstance(attempts, list)
            or not attempts
            or not isinstance(attempts[-1], dict)
            or stage_state.get("status") != attempts[-1].get("status")
        ):
            raise WorkflowRuntimeError("state_tampering")
        max_attempts = stage_map[stage_id].get("retry", {}).get("max_attempts", 1)
        try:
            resolved = _resolve_bindings(stage_map[stage_id]["inputs"], inputs, state)
        except WorkflowRuntimeError as exc:
            raise WorkflowRuntimeError("state_tampering") from exc
        legacy_attempts: list[bool] = []
        for expected_attempt, attempt_record in enumerate(attempts, start=1):
            if (
                not isinstance(attempt_record, dict)
                or attempt_record.get("attempt") != expected_attempt
                or expected_attempt > max_attempts
            ):
                raise WorkflowRuntimeError("state_tampering")
            authorization_id = attempt_record.get("authorization_id")
            attempt_status = attempt_record.get("status")
            if (
                not isinstance(authorization_id, str)
                or not authorization_id
                or authorization_id in recorded_authorizations
                or attempt_status not in {"planned", "authorized", "interrupted", "success", "failed", "partial"}
                or (expected_attempt != len(attempts) and attempt_status not in {"interrupted", "failed", "partial"})
            ):
                raise WorkflowRuntimeError("state_tampering")
            recorded_authorizations.add(authorization_id)
            plan, is_legacy = _validated_attempt_plan(definition, run_id, stage_id, resolved, attempt_record)
            legacy_attempts.append(is_legacy)
            if attempt_status == "planned":
                if (
                    authorization_id in consumed
                    or "receipt" in attempt_record
                    or "authorization_digest" in attempt_record
                ):
                    raise WorkflowRuntimeError("state_tampering")
            else:
                receipt = _receipt_from_record(attempt_record)
                if not _receipt_matches(receipt, authorization_id, plan, worker_identity):
                    raise WorkflowRuntimeError("state_tampering")
                recorded_consumptions.add(receipt.authorization_id)

        action = stage_map[stage_id]["action"]
        if (
            not action.get("idempotent", False)
            and len(attempts) > 1
            and ("idempotent" in action or not all(legacy_attempts))
        ):
            raise WorkflowRuntimeError("state_tampering")

    if recorded_consumptions != set(consumed):
        raise WorkflowRuntimeError("state_tampering")


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


_RECEIPT_FIELDS = (
    "authorization_id",
    "authorization_digest",
    "action_plan_id",
    "plan_digest",
    "engagement_id",
    "worker_identity",
    "target",
)


def _receipt_to_dict(receipt: ApprovalConsumptionReceipt) -> dict[str, str]:
    return {field: getattr(receipt, field) for field in _RECEIPT_FIELDS}


def _receipt_from_record(attempt_record: dict[str, Any]) -> ApprovalConsumptionReceipt:
    payload = attempt_record.get("receipt")
    if not isinstance(payload, dict) or set(payload) != set(_RECEIPT_FIELDS):
        raise WorkflowRuntimeError("state_tampering")
    if any(not isinstance(value, str) or not value for value in payload.values()):
        raise WorkflowRuntimeError("state_tampering")
    authorization_digest = payload["authorization_digest"]
    if len(authorization_digest) != 64 or any(
        character not in "0123456789abcdef" for character in authorization_digest
    ):
        raise WorkflowRuntimeError("state_tampering")
    return ApprovalConsumptionReceipt(
        authorization_id=payload["authorization_id"],
        authorization_digest=authorization_digest,
        action_plan_id=payload["action_plan_id"],
        plan_digest=payload["plan_digest"],
        engagement_id=payload["engagement_id"],
        worker_identity=payload["worker_identity"],
        target=payload["target"],
    )


def _verify_envelope(envelope: Any, code: str) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "digest"}:
        raise WorkflowRuntimeError(code)
    if not isinstance(envelope["payload"], dict) or digest(envelope["payload"]) != envelope["digest"]:
        raise WorkflowRuntimeError(code)
    return envelope["payload"]
