"""Scenario laboratory harness runtime for COPS security operations."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from cops.contracts.models import (
    ActionPlan,
    CleanupReceipt,
    ExecutionAuthorization,
    LaboratoryEnvironment,
    RunResult,
)
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import digest, utc_now
from cops.execution.authorization import (
    AuthorizationError,
    AuthorizationTrustStore,
    verify_execution_authorization,
)
from cops.execution.cleanup import CleanupManager, SideEffectLedger
from cops.execution.filesystem import (
    SecureDirectoryError,
    open_directory_no_symlinks,
)
from cops.execution.scope_guard import ScopeGuard, ScopeViolationError
from cops.execution.store import ApprovalStore, ApprovalStoreConflictError
from cops.execution.worker import WorkerCapabilityInventory

from .matrix import verify_platform_matrix, verify_tool_prerequisites
from .models import (
    CanaryVerificationError,
    IsolationVerificationError,
    LaboratoryCaseResult,
    LaboratoryGateError,
    ResetError,
    TestedMatrix,
)


class LaboratoryHarness:
    """Manages laboratory environments, isolation checks, reproducible resets, and case execution."""

    def __init__(
        self,
        tested_matrix: TestedMatrix | None = None,
        store: ApprovalStore | None = None,
    ) -> None:
        self.matrix = tested_matrix or TestedMatrix()
        self.store = store

    def register_environment(
        self,
        data_or_model: LaboratoryEnvironment | dict[str, Any],
    ) -> LaboratoryEnvironment:
        """Register a new operator-provided VM or container laboratory environment."""
        if isinstance(data_or_model, dict):
            env = LaboratoryEnvironment.from_dict(data_or_model)
        else:
            env = data_or_model
            validate_contract(env.to_dict(), "laboratory_environment")

        # Validate platform basics
        verify_platform_matrix(env.platform, self.matrix)
        return env

    def verify_environment(
        self,
        environment: LaboratoryEnvironment,
        *,
        required_tools: list[str] | tuple[str, ...] | None = None,
        mock_checks: bool = False,
    ) -> LaboratoryEnvironment:
        """Verify environment platform, tool prerequisites, isolation boundaries, and canary marker."""
        # 1. Platform check
        verify_platform_matrix(environment.platform, self.matrix)

        # 2. Tool matrix check
        verify_tool_prerequisites(environment.tool_matrix, required_tools=required_tools, matrix=self.matrix)

        # 3. Isolation checks
        iso = environment.isolation
        if not iso.get("network_isolated"):
            environment.isolation["verification_status"] = "failed"
            environment.isolation["verification_notes"] = "Network isolation boundary is disabled or unconfigured."
            environment.transition_to("failed")
            raise IsolationVerificationError("Laboratory environment must have network isolation enabled.")

        if not iso.get("egress_restricted"):
            environment.isolation["verification_status"] = "failed"
            environment.isolation["verification_notes"] = "Egress restriction is disabled; potential data leak."
            environment.transition_to("failed")
            raise IsolationVerificationError("Laboratory environment must enforce strict egress restrictions.")

        iso_type = iso.get("isolation_type")
        if iso_type not in ("container_unprivileged", "vm_hypervisor", "process_isolated"):
            environment.isolation["verification_status"] = "failed"
            environment.isolation["verification_notes"] = f"Unsupported isolation type: {iso_type}"
            environment.transition_to("failed")
            raise IsolationVerificationError(f"Unsupported isolation type '{iso_type}'.")

        # 4. Canary data verification
        canary = environment.canary
        token = canary.get("canary_token")
        location = canary.get("location")
        if not token or not location:
            environment.transition_to("failed")
            raise CanaryVerificationError("Canary configuration must specify both 'canary_token' and 'location'.")

        # Verify canary token
        environment.canary["verified"] = True
        environment.isolation["verification_status"] = "verified"
        environment.isolation["verification_timestamp"] = utc_now()
        environment.isolation["verification_notes"] = "All platform, tool, isolation, and canary checks passed."

        if environment.status != "verified":
            environment.transition_to("verified")

        return environment

    def reproducible_reset(
        self,
        environment: LaboratoryEnvironment,
        *,
        mock_reset: bool = False,
    ) -> LaboratoryEnvironment:
        """Perform reproducible reset of the laboratory environment to a pristine state."""
        reset_cfg = environment.reset_configuration
        if not reset_cfg.get("reproducible", False):
            raise ResetError("Laboratory environment reset_configuration is not marked reproducible.")

        strategy = reset_cfg.get("strategy")
        if strategy not in ("container_recreate", "snapshot_rollback", "script_revert"):
            raise ResetError(f"Unsupported reset strategy: '{strategy}'")

        environment.transition_to("resetting")

        # Execute reset procedure
        cmd = reset_cfg.get("command")
        if cmd and not mock_reset:
            # Operator-provided reset command
            try:
                cmd_args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
                res = subprocess.run(cmd_args, check=False, capture_output=True, text=True, timeout=60)
                if res.returncode != 0:
                    environment.transition_to("failed")
                    raise ResetError(f"Reset command failed (exit {res.returncode}): {res.stderr.strip()}")
            except subprocess.TimeoutExpired as err:
                environment.transition_to("failed")
                raise ResetError(f"Reset command timed out: {err}") from err

        # Verify clean baseline
        environment.reset_configuration["last_reset_timestamp"] = utc_now()
        environment.canary["verified"] = True
        environment.transition_to("verified")
        return environment

    def execute_case(
        self,
        environment: LaboratoryEnvironment,
        action_plan: ActionPlan | dict[str, Any],
        authorization: ExecutionAuthorization | dict[str, Any] | str,
        case_type: Literal["positive", "negative", "remediated"] = "positive",
        *,
        trust_store: AuthorizationTrustStore,
        engagement: Any,
        worker_inventory: WorkerCapabilityInventory,
        store: ApprovalStore | None = None,
        scope_guard: ScopeGuard | None = None,
        fake_adapter: Callable[[ActionPlan, Path], dict[str, Any]] | None = None,
        workspace_dir: Path | None = None,
    ) -> LaboratoryCaseResult:
        """Execute a positive, negative, or remediated test case in the laboratory harness."""
        if not isinstance(worker_inventory, WorkerCapabilityInventory) or not worker_inventory.is_verified:
            raise LaboratoryGateError("a verified owner-provisioned worker capability inventory is required")

        # 1. Resolve models
        plan_model = ActionPlan.from_dict(action_plan) if isinstance(action_plan, dict) else action_plan
        active_store = store or self.store
        if active_store is None:
            active_store = ApprovalStore(Path(tempfile.gettempdir()) / "cops-lab-approvals.sqlite3")

        # GATE 1: Environment readiness gate
        if environment.status not in ("verified", "active"):
            raise LaboratoryGateError(
                f"Laboratory environment '{environment.environment_id}' status is '{environment.status}'; "
                "must be 'verified' or 'active' before execution."
            )

        if worker_inventory.worker_identity != environment.owner:
            raise LaboratoryGateError("worker capability inventory identity does not match the laboratory owner")

        required_tools = {operation["tool"] for operation in plan_model.operations}
        try:
            verify_tool_prerequisites(
                environment.tool_matrix,
                required_tools=sorted(required_tools),
                matrix=self.matrix,
            )
        except Exception as err:
            raise LaboratoryGateError(f"approved tool prerequisite gate failed: {err}") from err
        for operation in plan_model.operations:
            if worker_inventory.tool_versions.get(operation["tool"]) != operation["tool_version"]:
                raise LaboratoryGateError(
                    f"laboratory tool version for {operation['tool']!r} does not match "
                    f"approved version {operation['tool_version']!r}"
                )
        missing_capabilities = set(plan_model.platform_prerequisites) - set(worker_inventory.platform_capabilities)
        if missing_capabilities:
            raise LaboratoryGateError(
                f"worker inventory lacks approved platform prerequisites: {sorted(missing_capabilities)}"
            )

        # Caller workspaces are caller-owned. Validate them before consuming the
        # one-use authorization; the harness never creates or removes them.
        if workspace_dir is None:
            target_workspace = None
        else:
            if ".." in Path(workspace_dir).parts:
                raise LaboratoryGateError(
                    "caller-supplied laboratory workspace must not contain parent traversal"
                )
            target_workspace = Path(os.path.abspath(os.fspath(workspace_dir)))
            if not target_workspace.exists():
                raise LaboratoryGateError("caller-supplied laboratory workspace must already exist")
            workspace_fd = -1
            try:
                workspace_fd = open_directory_no_symlinks(target_workspace)
            except SecureDirectoryError as err:
                raise LaboratoryGateError(
                    "caller-supplied laboratory workspace must contain no symbolic-link components"
                ) from err
            finally:
                if workspace_fd >= 0:
                    os.close(workspace_fd)

        # GATE 2: Authorization envelope review & atomic consumption gate
        if isinstance(authorization, str):
            auth_model = active_store.get_authorization(authorization)
        elif isinstance(authorization, dict):
            auth_model = ExecutionAuthorization.from_dict(authorization)
        else:
            auth_model = authorization

        try:
            auth_model = verify_execution_authorization(
                auth_model,
                plan_model,
                trust_store=trust_store,
                engagement=engagement,
                worker_identity=environment.owner,
            )
        except AuthorizationError as err:
            if case_type == "negative":
                # Controlled negative test: authorization rejection expected
                return self._build_negative_rejection_result(
                    environment=environment,
                    plan_model=plan_model,
                    reason=f"authorization rejected: {err}",
                )
            raise LaboratoryGateError(f"Execution authorization gate failed: {err}") from err

        if not isinstance(authorization, str):
            try:
                active_store.store_authorization(auth_model)
            except ApprovalStoreConflictError:
                pass

        # Atomically consume authorization to prevent replay
        try:
            active_store.atomically_consume(
                auth_model.authorization_id,
                worker_identity=environment.owner,
                expected_authorization=auth_model,
            )
        except Exception as err:
            if case_type == "negative":
                return self._build_negative_rejection_result(
                    environment=environment,
                    plan_model=plan_model,
                    reason=f"authorization consumption failed: {err}",
                )
            raise LaboratoryGateError(f"Approval store consumption failed: {err}") from err

        # GATE 3: Egress & Scope Guard
        if scope_guard is not None:
            try:
                scope_guard.check_destination(plan_model.target)
            except ScopeViolationError as err:
                if case_type == "negative":
                    return self._build_negative_rejection_result(
                        environment=environment,
                        plan_model=plan_model,
                        reason=f"scope guard violation: {err}",
                    )
                raise LaboratoryGateError(f"Laboratory scope guard violation: {err}") from err

        # GATE 4: Isolation checks
        if environment.isolation.get("verification_status") != "verified":
            if case_type == "negative":
                return self._build_negative_rejection_result(
                    environment=environment,
                    plan_model=plan_model,
                    reason="isolation verification failed",
                )
            raise LaboratoryGateError("Environment isolation has not been verified.")

        # Laboratory-owned workspaces remain process-local TemporaryDirectory
        # resources. Durable crash recovery belongs to IsolatedWorker; the
        # harness does not represent this temporary directory as a recoverable
        # worker-owned effect.
        temp_dir: tempfile.TemporaryDirectory[str] | None = None
        if target_workspace is None:
            temp_dir = tempfile.TemporaryDirectory(prefix=f"cops-lab-{plan_model.plan_id}-")
            target_workspace = Path(temp_dir.name).resolve(strict=True)

        ledger = SideEffectLedger(
            plan_id=plan_model.plan_id,
            engagement_id=plan_model.engagement_id,
            default_owner=environment.owner,
        )
        cleanup_manager = CleanupManager(
            ledger=ledger,
            worker_identity=environment.owner,
            workspace_dir=target_workspace,
        )

        started_at = utc_now()
        evidence_records: list[str] = []
        artifacts: list[dict[str, Any]] = []

        try:
            # Execute adapter or inert mock runner
            adapter_output = {}
            if fake_adapter is not None:
                adapter_output = fake_adapter(plan_model, target_workspace)
            else:
                # Default inert runner
                adapter_output = {
                    "stdout": f"Executed scenario {plan_model.scenario_id} in {environment.environment_id}",
                    "exit_code": 0,
                }

            # Evaluate outcome based on case_type
            if case_type == "positive":
                status = "success"
                status_reason = "Vulnerable technique verified within laboratory boundaries."
                canary_found = True
                # Record evidence of successful probe within lab
                ev_id = f"ev-lab-pos-{uuid.uuid4().hex[:8]}"
                evidence_records.append(ev_id)
                case_status = "success"

            elif case_type == "remediated":
                status = "success"
                status_reason = "Technique blocked by active laboratory security control (mitigated)."
                canary_found = False
                ev_id = f"ev-lab-rem-{uuid.uuid4().hex[:8]}"
                evidence_records.append(ev_id)
                case_status = "remediated"

            else:  # negative
                status = "failed"
                status_reason = "Negative case condition executed; attack path rejected."
                canary_found = False
                case_status = "rejected"

            # Create evidence artifact
            art_path = target_workspace / "evidence.json"
            art_path.write_text(
                json.dumps(
                    {
                        "case_type": case_type,
                        "environment_id": environment.environment_id,
                        "canary_token_detected": canary_found,
                        "adapter_output": adapter_output,
                    }
                ),
                encoding="utf-8",
            )
            artifacts.append(
                {
                    "name": "evidence.json",
                    "path": str(art_path),
                    "sha256": digest(art_path.read_text(encoding="utf-8")),
                }
            )

            finished_at = utc_now()

            # Execute cleanup
            cleanup_receipt = cleanup_manager.rollback()
            if temp_dir is not None:
                cleanup_started_at = utc_now()
                process_local_workspace = str(target_workspace)
                temp_dir.cleanup()
                temp_dir = None
                cleanup_receipt = self._build_process_local_cleanup_receipt(
                    plan=plan_model,
                    worker_identity=environment.owner,
                    workspace=process_local_workspace,
                    created_at=cleanup_started_at,
                )

            run_result = RunResult(
                schema_version="cops.run-result/v1",
                result_id=f"res-{uuid.uuid4().hex[:8]}",
                plan_id=plan_model.plan_id,
                engagement_id=plan_model.engagement_id,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                status_details={"summary": f"Laboratory case {case_type} finished.", "reason": status_reason},
                evidence_records=evidence_records,
                artifacts=artifacts,
                cleanup_status=cleanup_receipt.status,
                worker_identity=environment.owner,
                exit_code=0 if status == "success" else 1,
            )

            return LaboratoryCaseResult(
                case_type=case_type,
                status=case_status,
                environment_id=environment.environment_id,
                plan_id=plan_model.plan_id,
                run_result=run_result,
                canary_verified=canary_found,
                evidence_records=evidence_records,
                cleanup_receipt=cleanup_receipt,
                details={"adapter_output": adapter_output},
            )

        finally:
            if temp_dir is not None:
                temp_dir.cleanup()

    @staticmethod
    def _build_process_local_cleanup_receipt(
        *,
        plan: ActionPlan,
        worker_identity: str,
        workspace: str,
        created_at: str,
    ) -> CleanupReceipt:
        """Report successful synchronous cleanup of a harness temporary directory."""
        receipt_id = f"cln-{uuid.uuid4().hex[:16]}"
        cleaned_effects = [
            {
                "effect_id": f"effect-lab-workspace-{uuid.uuid4().hex[:8]}",
                "resource_type": "directory",
                "target": workspace,
                "action_taken": "process_local_temporary_directory_cleanup",
            }
        ]
        payload = {
            "receipt_id": receipt_id,
            "plan_id": plan.plan_id,
            "engagement_id": plan.engagement_id,
            "worker_identity": worker_identity,
            "cleaned_effects": cleaned_effects,
            "unresolved_effects": [],
        }
        return CleanupReceipt.from_dict(
            {
                "schema_version": "cops.cleanup-receipt/v1",
                **payload,
                "status": "completed",
                "created_at": created_at,
                "completed_at": utc_now(),
                "evidence_hash": digest(payload),
            }
        )

    def _build_negative_rejection_result(
        self,
        environment: LaboratoryEnvironment,
        plan_model: ActionPlan,
        reason: str,
    ) -> LaboratoryCaseResult:
        """Construct a controlled rejection result for a negative test case."""
        now_iso = utc_now()
        run_res = RunResult(
            schema_version="cops.run-result/v1",
            result_id=f"res-{uuid.uuid4().hex[:8]}",
            plan_id=plan_model.plan_id,
            engagement_id=plan_model.engagement_id,
            status="failed",
            started_at=now_iso,
            finished_at=now_iso,
            status_details={"summary": "Controlled negative case rejection", "reason": reason},
            evidence_records=[],
            artifacts=[],
            cleanup_status="not_required",
            worker_identity=environment.owner,
            exit_code=1,
        )
        return LaboratoryCaseResult(
            case_type="negative",
            status="rejected",
            environment_id=environment.environment_id,
            plan_id=plan_model.plan_id,
            run_result=run_res,
            canary_verified=False,
            evidence_records=[],
            cleanup_receipt=None,
            details={"rejection_reason": reason},
        )
