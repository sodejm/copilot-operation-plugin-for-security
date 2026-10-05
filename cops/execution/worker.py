"""Isolated execution worker runtime for COPS security operations.

Executes authorized ActionPlans within strict process boundaries, enforcing:
- Mandatory pre-execution authorization verification via ApprovalStore
- Host identity and unprivileged process boundary checks
- Atomic consumption of execution authorizations
- Process execution resource limits (CPU/wall-clock timeouts, max output bytes)
- Ephemeral workspace scratch isolation and verified cleanup
- Deterministic RunResult contract emission
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from cops.contracts.models import ActionPlan, ExecutionAuthorization, RunResult
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import digest, utc_now
from .authorization import AuthorizationError, verify_execution_authorization
from .store import ApprovalStore, ApprovalStoreError


class WorkerError(RuntimeError):
    """Base error for execution worker operations."""


class WorkerIsolationError(WorkerError):
    """Required execution isolation or process sandboxing is unavailable or unsafe."""


class WorkerExecutionError(WorkerError):
    """An operation within the action plan failed or exceeded allowed limits."""


@dataclass
class WorkerConfig:
    """Configuration for an isolated execution worker node."""

    worker_id: str = field(default_factory=lambda: f"worker-{platform.system().lower()}-{uuid.uuid4().hex[:8]}")
    allowed_tools: tuple[str, ...] = ("echo", "python3", "pytest", "nmap", "cat", "git")
    max_wall_time_seconds: int = 300
    max_output_bytes: int = 1048576  # 1MB
    enforce_unprivileged: bool = True


class IsolatedWorker:
    """Isolated execution worker that executes authorized ActionPlans."""

    def __init__(
        self,
        config: WorkerConfig | None = None,
        store: ApprovalStore | None = None,
        scope_guard: Any | None = None,
    ) -> None:
        self.config = config or WorkerConfig()
        self.store = store
        self.scope_guard = scope_guard
        self.last_cleanup_receipt: Any | None = None
        self._verify_worker_environment()

    def _verify_worker_environment(self) -> None:
        """Verify process execution boundaries and environment safety."""
        # Fail closed if running as root without explicit override in production
        if self.config.enforce_unprivileged and hasattr(os, "geteuid"):
            if os.geteuid() == 0 and os.environ.get("COPS_ALLOW_ROOT_WORKER") != "1":
                raise WorkerIsolationError(
                    "Worker cannot run as root (UID 0); unprivileged execution boundary required."
                )

    def execute_plan(
        self,
        action_plan: ActionPlan | dict[str, Any],
        *,
        authorization: ExecutionAuthorization | dict[str, Any] | str,
        workspace_dir: Path | None = None,
        cancel_requested: bool = False,
        failure_injection: dict[str, Any] | None = None,
    ) -> RunResult:
        """Execute an ActionPlan under verified authorization envelope."""
        # 1. Resolve ActionPlan model
        if isinstance(action_plan, dict):
            plan_model = ActionPlan.from_dict(action_plan)
        else:
            plan_model = action_plan

        if plan_model.status in ("fulfilled", "rejected", "cancelled"):
            raise WorkerExecutionError(
                f"cannot execute action plan '{plan_model.plan_id}' with terminal status '{plan_model.status}'"
            )

        # Failure injection: before approval consumption
        if failure_injection and failure_injection.get("inject_at") == "before_consume":
            raise WorkerExecutionError("injected failure before approval consumption")

        # 2. Resolve Authorization envelope and ensure durable storage
        if self.store is None:
            self.store = ApprovalStore(Path.home() / ".cops" / "approvals.sqlite3")

        if isinstance(authorization, str):
            auth_model = self.store.get_authorization(authorization)
        elif isinstance(authorization, dict):
            auth_model = ExecutionAuthorization.from_dict(authorization)
            try:
                self.store.store_authorization(auth_model)
            except Exception:
                pass
        else:
            auth_model = authorization
            try:
                self.store.store_authorization(auth_model)
            except Exception:
                pass

        # 3. Cryptographically verify authorization against plan and worker identity
        verify_execution_authorization(
            auth_model,
            plan_model,
            worker_identity=self.config.worker_id if auth_model.bound_parameters.get("worker_identity") else None,
        )

        # 4. Atomically consume authorization envelope to prevent replay
        consumed_auth = self.store.atomically_consume(
            auth_model.authorization_id,
            worker_identity=self.config.worker_id,
        )

        # Failure injection: after approval consumption
        if failure_injection and failure_injection.get("inject_at") == "after_consume":
            raise WorkerExecutionError("injected failure after approval consumption")

        # 5. Set up isolated ephemeral workspace and side-effect ledger
        ephemeral = False
        if workspace_dir is None:
            temp_scratch = tempfile.mkdtemp(prefix=f"cops-worker-{plan_model.plan_id}-")
            target_workspace = Path(temp_scratch)
            ephemeral = True
        else:
            target_workspace = Path(workspace_dir).resolve()
            target_workspace.mkdir(parents=True, exist_ok=True)

        from .cleanup import CleanupManager, SideEffectLedger
        ledger = SideEffectLedger(
            plan_id=plan_model.plan_id,
            engagement_id=plan_model.engagement_id,
            default_owner=self.config.worker_id,
        )
        cleanup_manager = CleanupManager(
            ledger=ledger,
            worker_identity=self.config.worker_id,
            workspace_dir=target_workspace,
        )
        if ephemeral:
            ledger.record_effect(
                step_id="workspace-scratch",
                resource_type="directory",
                target=str(target_workspace),
                cleanup_action="delete",
            )

        started_at = utc_now()
        overall_exit_code = 0
        status = "success"
        status_reason = ""

        from .evidence import EvidenceRecorder
        from .redaction import StreamRedactor
        # Initialize evidence recorder with redactor
        redactor = StreamRedactor()
        evidence_recorder = EvidenceRecorder(workspace_dir=target_workspace, redactor=redactor)

        max_duration_seconds = plan_model.limits.get("max_duration_seconds", self.config.max_wall_time_seconds)
        max_output_bytes = plan_model.limits.get("max_output_bytes", self.config.max_output_bytes)
        start_dt = datetime.now(timezone.utc)

        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(target_workspace),
            "TMPDIR": str(target_workspace),
        }

        try:
            # 5.5. Enforce execution-time scope boundary on plan target
            if hasattr(self, "scope_guard") and self.scope_guard is not None:
                from .scope_guard import ScopeViolationError
                try:
                    self.scope_guard.check_destination(plan_model.target)
                except ScopeViolationError as err:
                    status = "failed"
                    status_reason = f"scope violation: {err}"
                    overall_exit_code = 2

            # Check pre-execution cancellation or injected failure
            if status == "success":
                if cancel_requested:
                    status = "cancelled"
                    status_reason = "execution cancelled by operator before start"
                    overall_exit_code = 130
                elif failure_injection and failure_injection.get("inject_at") == "before_process":
                    status = "failed"
                    status_reason = "injected failure before process start"
                    overall_exit_code = 1

            # 6. Execute operations in sequence (if checks passed)
            if status == "success":
                for op in plan_model.operations:
                    step_id = op["step_id"]
                    tool = op["tool"]
                    action = op["action"]
                    is_idempotent = bool(op.get("idempotent", False))
                    # Track declared cleanup in side-effect ledger
                    if "cleanup" in op and isinstance(op["cleanup"], dict):
                        clean_spec = op["cleanup"]
                        clean_target = clean_spec.get("target") or str(target_workspace / f"{step_id}.tmp")
                        ledger.record_effect(
                            step_id=step_id,
                            resource_type=clean_spec.get("resource_type", "file"),
                            target=clean_target,
                            cleanup_action=clean_spec.get("action", "delete"),
                            metadata=clean_spec,
                        )

                    if cancel_requested:
                        if not is_idempotent:
                            status = "uncertain"
                            status_reason = f"interrupted during non-idempotent step '{step_id}'; automatic repeat disallowed"
                        else:
                            status = "cancelled"
                            status_reason = f"execution cancelled by operator at step '{step_id}'"
                        overall_exit_code = 130
                        break

                    if failure_injection and failure_injection.get("inject_at") == "during_execution":
                        target_step = failure_injection.get("step_id")
                        if target_step in (None, step_id):
                            if not is_idempotent:
                                status = "uncertain"
                                status_reason = f"interrupted during non-idempotent step '{step_id}'; automatic repeat disallowed"
                            else:
                                status = "failed"
                                status_reason = f"injected failure during execution at step '{step_id}'"
                            overall_exit_code = 1
                            break

                    # Check overall plan duration limit
                    elapsed_seconds = (datetime.now(timezone.utc) - start_dt).total_seconds()
                    if elapsed_seconds >= max_duration_seconds:
                        status = "partial"
                        status_reason = f"operation exceeded action plan max_duration_seconds limit ({max_duration_seconds}s)"
                        overall_exit_code = 124
                        break

                    remaining_time = max(1, int(max_duration_seconds - elapsed_seconds))
                    timeout = min(op.get("timeout_seconds", 60), remaining_time)
                    step_started = utc_now()

                    # Tool whitelist boundary
                    if tool not in self.config.allowed_tools and tool != "inert":
                        status = "failed"
                        status_reason = f"tool '{tool}' is not in worker allowed tools: {sorted(self.config.allowed_tools)}"
                        overall_exit_code = 127
                        break

                    # Enforce scope on any destination-bearing arguments
                    if hasattr(self, "scope_guard") and self.scope_guard is not None:
                        from .scope_guard import ScopeViolationError
                        op_args = op.get("arguments", {})
                        if isinstance(op_args, dict):
                            for dest_key in ("target", "host", "destination", "ip"):
                                dest_val = op_args.get(dest_key)
                                if dest_val and isinstance(dest_val, str):
                                    try:
                                        self.scope_guard.check_destination(dest_val)
                                    except ScopeViolationError as err:
                                        status = "failed"
                                        status_reason = f"scope violation in step '{step_id}': {err}"
                                        overall_exit_code = 2
                                        break
                        if status != "success":
                            break

                    # Prepare isolated execution via adapter or simulated inert
                    stdout_bytes = b""
                    stderr_bytes = b""
                    try:
                        if tool == "inert":
                            # Simulated execution for testing
                            stdout_bytes = f"Inert step {step_id} executed successfully: {action}".encode("utf-8")
                            exit_code = 0
                        else:
                            from cops.adapters import ToolAdapterRegistry, AdapterError
                            registry = ToolAdapterRegistry()
                            if tool in registry.list_tools():
                                adapter = registry.get_adapter(tool)
                                try:
                                    cmd = adapter.assemble_command(action, op.get("arguments"))
                                except AdapterError as err:
                                    redacted_err = redactor.redact_string(str(err))
                                    status = "failed"
                                    status_reason = f"adapter validation error: {redacted_err}"
                                    overall_exit_code = 1
                                    break
                                exec_cmd = [shutil.which(cmd[0]) or cmd[0]] + cmd[1:]
                                proc = subprocess.run(
                                    exec_cmd,
                                    cwd=target_workspace,
                                    env=clean_env,
                                    start_new_session=(os.name == "posix"),
                                    capture_output=True,
                                    timeout=timeout,
                                    check=False,
                                )
                                stdout_bytes = proc.stdout
                                stderr_bytes = proc.stderr
                                exit_code = 128 + abs(proc.returncode) if proc.returncode < 0 else proc.returncode
                            else:
                                # Tool has no registered adapter - fail closed
                                status = "failed"
                                status_reason = f"tool '{tool}' has no registered execution adapter"
                                overall_exit_code = 127
                                break
                    except KeyboardInterrupt:
                        if not is_idempotent:
                            status = "uncertain"
                            status_reason = f"interrupted during non-idempotent step '{step_id}'; automatic repeat disallowed"
                        else:
                            status = "cancelled"
                            status_reason = "execution cancelled by operator via interrupt"
                        overall_exit_code = 130
                        break

                    step_finished = utc_now()
                    # Record and redact evidence
                    redacted_output, _ = evidence_recorder.record_step_output(
                        step_id=step_id,
                        tool=tool,
                        action=action,
                        stdout=stdout_bytes,
                        stderr=stderr_bytes,
                        exit_code=exit_code,
                        started_at=step_started,
                        finished_at=step_finished,
                    )

                    # Check max output bytes
                    if len(redacted_output) > max_output_bytes:
                        status = "partial"
                        status_reason = f"step '{step_id}' exceeded max_output_bytes limit ({len(redacted_output)} > {max_output_bytes})"
                        overall_exit_code = 1
                        break

                    if exit_code != 0:
                        status = "failed"
                        status_reason = f"step '{step_id}' exited with non-zero code {exit_code}"
                        overall_exit_code = exit_code
                        break

        except subprocess.TimeoutExpired as err:
            status = "partial"
            status_reason = f"operation timed out after {err.timeout} seconds"
            overall_exit_code = 124
        except Exception as err:
            status = "failed"
            status_reason = f"unexpected worker execution failure: {err}"
            overall_exit_code = 1
        finally:
            finished_at = utc_now()
            # Perform ownership-verified rollback of tracked side effects
            cleanup_receipt = cleanup_manager.rollback()
            self.last_cleanup_receipt = cleanup_receipt
            cleanup_status = cleanup_receipt.status

            if cleanup_receipt.status in ("failed", "partial"):
                unres_summary = [e["target"] for e in cleanup_receipt.unresolved_effects]
                if status == "success":
                    status = "partial"
                    status_reason = f"cleanup {cleanup_receipt.status}: unresolved artifacts: {unres_summary}"
                elif not status_reason:
                    status_reason = f"cleanup {cleanup_receipt.status}: unresolved artifacts: {unres_summary}"

            # Ensure ephemeral workspace removal if still present
            if ephemeral and target_workspace.exists():
                try:
                    shutil.rmtree(target_workspace, ignore_errors=False)
                except Exception:
                    pass
                if target_workspace.exists():
                    cleanup_status = "failed"

        # 7. Build and return RunResult contract
        result_id = f"res-{uuid.uuid4().hex[:16]}"
        summary_text = "All action plan operations completed successfully" if status == "success" else f"Execution finished with status '{status}'"
        status_details: dict[str, Any] = {"summary": summary_text}
        if status != "success":
            status_details["reason"] = status_reason

        # Combine authorization proof, recorded step evidence hashes, and cleanup receipt hash
        evidence_hashes = [
            digest(consumed_auth.to_dict())
        ]
        evidence_hashes.extend(evidence_recorder.get_evidence_hashes())
        evidence_hashes.append(cleanup_receipt.evidence_hash)

        result_doc = {
            "schema_version": "cops.run-result/v1",
            "result_id": result_id,
            "plan_id": plan_model.plan_id,
            "engagement_id": plan_model.engagement_id,
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
            "exit_code": overall_exit_code,
            "status_details": status_details,
            "evidence_records": evidence_hashes,
            "artifacts": evidence_recorder.get_artifact_dicts(),
            "cleanup_status": cleanup_status,
            "worker_identity": self.config.worker_id,
        }

        validate_contract(result_doc, "run_result")
        return RunResult.from_dict(result_doc)
