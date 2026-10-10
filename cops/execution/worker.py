"""Isolated execution worker runtime for COPS security operations.

Executes authorized ActionPlans within strict process boundaries, enforcing:
- Mandatory pre-execution authorization consumption via a separate approval control
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
import stat
import tempfile
import uuid
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from types import MappingProxyType
from typing import Any

from cops.adapters import AdapterError, ToolAdapterRegistry
from cops.contracts.models import ActionPlan, CleanupReceipt, RunResult
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import utc_now

from .cleanup import (
    PLAN_DECLARED_PROVENANCE_KEY,
    PLAN_DECLARED_PROVENANCE_UNVERIFIED,
    CleanupError,
    CleanupJournal,
    CleanupManager,
    CleanupPersistenceError,
    SideEffectLedger,
)
from .control import ApprovalConsumptionReceipt, ApprovalControl, ApprovalControlError
from .credentials import ScopedCredentialResolver
from .egress import CertificateURIIdentityVerifier, ExecutionEgressBroker, HTTPSExecutionMediator
from .egress_policy import HTTPSOperationEgressPolicy, OperationEgressPolicyError, parse_operation_egress_policy
from .executable import (
    ExecutablePreparationTimeoutError,
    ExecutableVerificationError,
    prepare_executable,
    verify_executable_launch_support,
)
from .filesystem import (
    SecureDirectoryError,
    create_directory_exclusive_no_symlinks,
    open_directory_no_symlinks,
    same_directory_identity,
)
from .sandbox import ExecutionSandbox, LinuxBubblewrapSandbox


class WorkerError(RuntimeError):
    """Base error for execution worker operations."""


class WorkerIsolationError(WorkerError):
    """Required execution isolation or process sandboxing is unavailable or unsafe."""


class WorkerExecutionError(WorkerError):
    """An operation within the action plan failed or exceeded allowed limits."""


@dataclass(frozen=True)
class AuthorizedExecution:
    """Execution result paired with the receipt issued by the approval authority."""

    result: RunResult
    approval_receipt: ApprovalConsumptionReceipt


def _supports_secure_evidence_dirs() -> bool:
    return os.name == "posix"


def _open_caller_workspace(workspace: Path) -> int:
    try:
        return open_directory_no_symlinks(workspace)
    except SecureDirectoryError as err:
        if isinstance(err.__cause__, FileNotFoundError):
            raise WorkerIsolationError("caller-supplied worker workspace must already exist") from err
        raise WorkerIsolationError("worker workspace path must not contain symbolic-link components") from err


@dataclass(frozen=True)
class WorkerCapabilityInventory:
    """Owner-provisioned measurement of a worker's execution capabilities."""

    schema_version: str
    worker_identity: str
    measured_at: str
    measurement_source: str
    tool_versions: Mapping[str, str]
    platform_capabilities: tuple[str, ...]
    _file_verified: bool = field(default=False, init=False, repr=False, compare=False)

    SCHEMA_VERSION = "cops.worker-capability-inventory/v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_versions", MappingProxyType(dict(self.tool_versions)))
        object.__setattr__(self, "platform_capabilities", tuple(self.platform_capabilities))

    @classmethod
    def from_file(
        cls,
        path: Path | str,
        *,
        expected_worker_identity: str | None = None,
    ) -> WorkerCapabilityInventory:
        """Load an owner-only inventory artifact and validate its provenance fields."""
        source = Path(path)
        if source.is_symlink():
            raise WorkerIsolationError("worker inventory must not be a symbolic link")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(source, flags)
        except OSError as err:
            raise WorkerIsolationError(f"cannot open worker inventory: {err}") from err

        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise WorkerIsolationError("worker inventory must be a regular file")
            if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
                raise WorkerIsolationError("worker inventory must be owned by the current worker account")
            if stat.S_IMODE(file_stat.st_mode) & 0o077:
                raise WorkerIsolationError("worker inventory permissions must not allow group or other access")
            with os.fdopen(fd, encoding="utf-8") as handle:
                fd = -1
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as err:
            raise WorkerIsolationError(f"invalid worker inventory: {err}") from err
        finally:
            if fd >= 0:
                os.close(fd)

        required = {
            "schema_version",
            "worker_identity",
            "measured_at",
            "measurement_source",
            "tool_versions",
            "platform_capabilities",
        }
        if not isinstance(document, dict) or set(document) != required:
            raise WorkerIsolationError("worker inventory fields do not match the required schema")
        if document["schema_version"] != cls.SCHEMA_VERSION:
            raise WorkerIsolationError("unsupported worker inventory schema version")

        worker_identity = document["worker_identity"]
        measured_at = document["measured_at"]
        measurement_source = document["measurement_source"]
        tool_versions = document["tool_versions"]
        platform_capabilities = document["platform_capabilities"]
        if not isinstance(worker_identity, str) or not worker_identity.strip():
            raise WorkerIsolationError("worker inventory identity must be a non-empty string")
        if expected_worker_identity is not None and worker_identity != expected_worker_identity:
            raise WorkerIsolationError("worker inventory identity does not match the expected worker")
        if not isinstance(measured_at, str):
            raise WorkerIsolationError("worker inventory measurement time must be a canonical timestamp")
        try:
            measured = datetime.fromisoformat(measured_at.replace("Z", "+00:00"))
        except ValueError as err:
            raise WorkerIsolationError("worker inventory measurement time is invalid") from err
        if measured.tzinfo is None or measured_at != measured.astimezone(UTC).isoformat().replace("+00:00", "Z"):
            raise WorkerIsolationError("worker inventory measurement time must be canonical UTC")
        if measured > datetime.now(UTC):
            raise WorkerIsolationError("worker inventory measurement time cannot be in the future")
        if not isinstance(measurement_source, str) or not measurement_source.strip():
            raise WorkerIsolationError("worker inventory measurement source must be a non-empty string")
        if (
            not isinstance(tool_versions, dict)
            or not tool_versions
            or any(
                not isinstance(tool, str) or not tool.strip() or not isinstance(version, str) or not version.strip()
                for tool, version in tool_versions.items()
            )
        ):
            raise WorkerIsolationError("worker inventory tool versions must be a non-empty string mapping")
        if not isinstance(platform_capabilities, list) or any(
            not isinstance(item, str) or not item.strip() for item in platform_capabilities
        ):
            raise WorkerIsolationError("worker inventory platform capabilities must be a string list")

        inventory = cls(
            schema_version=cls.SCHEMA_VERSION,
            worker_identity=worker_identity,
            measured_at=measured_at,
            measurement_source=measurement_source,
            tool_versions=MappingProxyType(dict(tool_versions)),
            platform_capabilities=tuple(platform_capabilities),
        )
        object.__setattr__(inventory, "_file_verified", True)
        return inventory

    @property
    def is_verified(self) -> bool:
        """Whether this inventory passed the protected file loader."""
        return self._file_verified

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON representation of this inventory."""
        return {
            "schema_version": self.schema_version,
            "worker_identity": self.worker_identity,
            "measured_at": self.measured_at,
            "measurement_source": self.measurement_source,
            "tool_versions": dict(self.tool_versions),
            "platform_capabilities": list(self.platform_capabilities),
        }


@dataclass(frozen=True)
class WorkerConfig:
    """Configuration for an isolated execution worker node."""

    worker_id: str = field(default_factory=lambda: f"worker-{platform.system().lower()}-{uuid.uuid4().hex[:8]}")
    allowed_tools: tuple[str, ...] = ("echo", "python3", "pytest", "nmap", "cat", "git")
    tool_versions: Mapping[str, str] = field(default_factory=dict)
    platform_capabilities: tuple[str, ...] = ()
    max_wall_time_seconds: int = 300
    max_output_bytes: int = 1048576  # 1MB
    enforce_unprivileged: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_tools", tuple(self.allowed_tools))
        object.__setattr__(self, "tool_versions", MappingProxyType(dict(self.tool_versions)))
        object.__setattr__(self, "platform_capabilities", tuple(self.platform_capabilities))

    @classmethod
    def from_inventory(cls, inventory: WorkerCapabilityInventory) -> WorkerConfig:
        """Build worker configuration exclusively from a trusted inventory artifact."""
        return cls(
            worker_id=inventory.worker_identity,
            allowed_tools=tuple(inventory.tool_versions),
            tool_versions=inventory.tool_versions,
            platform_capabilities=inventory.platform_capabilities,
        )


class IsolatedWorker:
    """Isolated execution worker backed by a durable cleanup journal."""

    def __init__(
        self,
        worker_inventory: WorkerCapabilityInventory,
        approval_control: ApprovalControl,
        sandbox: ExecutionSandbox,
        scope_guard: Any | None = None,
        *,
        cleanup_journal_path: Path | str,
        adapter_registry: ToolAdapterRegistry | None = None,
        expected_engagement_id: str | None = None,
        egress_trust_domain: str | None = None,
        credential_resolver: ScopedCredentialResolver | None = None,
    ) -> None:
        if not isinstance(worker_inventory, WorkerCapabilityInventory) or not worker_inventory.is_verified:
            raise WorkerIsolationError("a verified owner-provisioned worker capability inventory is required")
        self.worker_inventory = worker_inventory
        self.config = WorkerConfig.from_inventory(worker_inventory)
        self.approval_control = approval_control
        self.sandbox = sandbox
        self.scope_guard = scope_guard
        self.adapter_registry = adapter_registry or ToolAdapterRegistry()
        self.expected_engagement_id = expected_engagement_id
        if credential_resolver is not None and credential_resolver.approval_control is not approval_control:
            raise WorkerIsolationError("credential resolver and worker must use the same approval control client")
        self.credential_resolver = credential_resolver
        try:
            self._egress_identity_verifier = (
                None
                if egress_trust_domain is None
                else CertificateURIIdentityVerifier(trust_domain=egress_trust_domain)
            )
        except ValueError as err:
            raise WorkerIsolationError("worker egress trust domain is invalid") from err
        self.cleanup_journal = CleanupJournal(cleanup_journal_path)
        self.last_cleanup_receipt: CleanupReceipt | None = None
        self.recovery_cleanup_receipts: tuple[CleanupReceipt, ...] = ()
        self._verify_worker_environment()

    def recover_pending_cleanup(self) -> tuple[CleanupReceipt, ...]:
        """Recover journaled cleanup before the supervisor accepts new work."""
        receipts: list[CleanupReceipt] = []
        for recovered in self.cleanup_journal.recoverable_runs(self.config.worker_id):
            ledger = SideEffectLedger(
                recovered.plan_id,
                recovered.engagement_id,
                recovered.worker_identity,
                journal=self.cleanup_journal,
                run_id=recovered.run_id,
                workspace_dir=recovered.workspace_dir,
                recovered_effects=recovered.effects,
                start_run=False,
            )
            receipt = CleanupManager(ledger, recovered.worker_identity, recovered.workspace_dir).rollback(
                recovered=True
            )
            receipts.append(receipt)
        self.recovery_cleanup_receipts = tuple(receipts)
        if receipts:
            self.last_cleanup_receipt = receipts[-1]
        return self.recovery_cleanup_receipts

    def _verify_plan_compatibility(self, plan: ActionPlan) -> None:
        batch = plan.batch
        if batch.get("mode") != "sequential":
            raise WorkerExecutionError("worker supports only sequential approved batches")
        if batch.get("max_operations", 0) < len(plan.operations):
            raise WorkerExecutionError("approved batch operation limit is smaller than the plan")
        missing_capabilities = set(plan.platform_prerequisites) - set(self.config.platform_capabilities)
        if missing_capabilities:
            raise WorkerExecutionError(f"worker lacks approved platform prerequisites: {sorted(missing_capabilities)}")
        for operation in plan.operations:
            tool = operation["tool"]
            if tool not in self.config.allowed_tools and tool != "inert":
                raise WorkerExecutionError(f"tool {tool!r} is not allowed by this worker")
            configured = self.config.tool_versions.get(tool)
            if configured is None or configured != operation["tool_version"]:
                raise WorkerExecutionError(
                    f"worker tool version for {tool!r} does not match approved version {operation['tool_version']!r}"
                )
            if tool != "inert":
                try:
                    adapter = self.adapter_registry.get_adapter(tool)
                except AdapterError as err:
                    raise WorkerExecutionError(f"tool {tool!r} has no registered execution adapter") from err
                if adapter.version != operation["tool_version"]:
                    raise WorkerExecutionError(
                        f"adapter logical version for {tool!r} does not match approved version "
                        f"{operation['tool_version']!r}"
                    )
                try:
                    adapter.assemble_command(operation["action"], operation.get("arguments"))
                except AdapterError as err:
                    raise WorkerExecutionError(
                        f"adapter operation for {tool!r} is incompatible with this worker environment"
                    ) from err
        if any(operation["tool"] != "inert" for operation in plan.operations):
            try:
                verify_executable_launch_support()
            except ExecutableVerificationError as err:
                raise WorkerIsolationError("verified adapter launch is unavailable on this worker") from err

    def _verify_worker_environment(self) -> None:
        """Verify process execution boundaries and environment safety."""
        # Fail closed if running as root without explicit override in production
        if self.config.enforce_unprivileged and hasattr(os, "geteuid"):
            if os.geteuid() == 0 and os.environ.get("COPS_ALLOW_ROOT_WORKER") != "1":
                raise WorkerIsolationError(
                    "Worker cannot run as root (UID 0); unprivileged execution boundary required."
                )

    def _preflight_execution_request(
        self, plan: ActionPlan, *, cancel_requested: bool
    ) -> tuple[HTTPSOperationEgressPolicy | None, ...]:
        """Reject immutable request failures before preparing or consuming an approval."""
        if cancel_requested:
            raise WorkerExecutionError("execution cancelled by operator before start")
        try:
            operation_egress_policies = tuple(parse_operation_egress_policy(op) for op in plan.operations)
        except OperationEgressPolicyError as err:
            raise WorkerExecutionError("operation egress policy is invalid") from err

        active_egress_policies = tuple(policy for policy in operation_egress_policies if policy is not None)
        for operation, policy in zip(plan.operations, operation_egress_policies, strict=True):
            if policy is not None and operation["tool"] == "inert":
                raise WorkerExecutionError("operation egress requires a mediated adapter execution")
        if active_egress_policies:
            if plan.limits.get("egress_allowed") is not True:
                raise WorkerExecutionError("action plan must explicitly allow operation egress")
            if self._egress_identity_verifier is None:
                raise WorkerIsolationError("operation egress requires an owner-provisioned trust domain")
            if self.scope_guard is None or not self.scope_guard.scope.egress_allowed:
                raise WorkerIsolationError("operation egress requires an egress-enabled engagement scope")
            if not isinstance(self.sandbox, LinuxBubblewrapSandbox):
                raise WorkerIsolationError("operation egress requires the production Linux sandbox")

        if self.scope_guard is None:
            return operation_egress_policies

        from .scope_guard import ScopeViolationError

        def check(destination: Any, label: str) -> None:
            if not isinstance(destination, str) or not destination.strip():
                raise WorkerExecutionError(f"{label} must be a nonempty destination")
            try:
                self.scope_guard.check_destination(destination)
            except ScopeViolationError as err:
                raise WorkerExecutionError(f"scope violation in {label}: {err}") from err

        check(plan.target, "plan target")
        for policy in active_egress_policies:
            check(policy.host, "operation egress host")
        for operation in plan.operations:
            arguments = operation.get("arguments", {})
            if not isinstance(arguments, Mapping):
                raise WorkerExecutionError(f"operation {operation['step_id']!r} arguments must be a mapping")
            for key in ("target", "host", "destination", "ip"):
                if key in arguments:
                    check(arguments[key], f"step {operation['step_id']!r} {key}")
        return operation_egress_policies

    def execute_plan(
        self,
        action_plan: ActionPlan | dict[str, Any],
        *,
        authorization: str,
        workspace_dir: Path | None = None,
        cancel_requested: bool = False,
        failure_injection: dict[str, Any] | None = None,
    ) -> RunResult:
        """Execute an ActionPlan under a consume-only authorization identifier."""
        return self.execute_plan_with_receipt(
            action_plan,
            authorization_id=authorization,
            workspace_dir=workspace_dir,
            cancel_requested=cancel_requested,
            failure_injection=failure_injection,
        ).result

    def execute_plan_with_receipt(
        self,
        action_plan: ActionPlan | dict[str, Any],
        *,
        authorization_id: str,
        workspace_dir: Path | None = None,
        cancel_requested: bool = False,
        failure_injection: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
    ) -> AuthorizedExecution:
        """Execute after both boundaries pass readiness, returning authority provenance."""
        with ExitStack() as workspace_stack:
            return self._execute_plan_with_receipt_impl(
                action_plan,
                authorization_id=authorization_id,
                workspace_dir=workspace_dir,
                cancel_requested=cancel_requested,
                failure_injection=failure_injection,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                workspace_stack=workspace_stack,
            )

    def _execute_plan_with_receipt_impl(
        self,
        action_plan: ActionPlan | dict[str, Any],
        *,
        authorization_id: str,
        workspace_dir: Path | None,
        cancel_requested: bool,
        failure_injection: dict[str, Any] | None,
        timeout_seconds: float | None,
        max_output_bytes: int | None,
        workspace_stack: ExitStack,
    ) -> AuthorizedExecution:
        """Keep workspace inode references live through execution and cleanup."""
        # 1. Resolve ActionPlan model
        if isinstance(action_plan, dict):
            plan_model = ActionPlan.from_dict(action_plan)
        else:
            plan_model = action_plan

        if self.expected_engagement_id is not None and plan_model.engagement_id != self.expected_engagement_id:
            raise WorkerExecutionError("action plan engagement does not match the provisioned engagement")

        if plan_model.status in ("fulfilled", "rejected", "cancelled"):
            raise WorkerExecutionError(
                f"cannot execute action plan '{plan_model.plan_id}' with terminal status '{plan_model.status}'"
            )

        # Failure injection: before approval consumption
        if failure_injection and failure_injection.get("inject_at") == "before_consume":
            raise WorkerExecutionError("injected failure before approval consumption")

        if not isinstance(authorization_id, str) or not authorization_id:
            raise WorkerExecutionError("authorization_id must be a nonempty string")
        if timeout_seconds is not None and (
            timeout_seconds <= 0 or timeout_seconds > self.config.max_wall_time_seconds
        ):
            raise WorkerExecutionError("requested timeout exceeds worker limits")
        if max_output_bytes is not None and (max_output_bytes <= 0 or max_output_bytes > self.config.max_output_bytes):
            raise WorkerExecutionError("requested output limit exceeds worker limits")
        if plan_model.credential_references and self.credential_resolver is None:
            raise WorkerIsolationError("credential-bearing plan requires a scoped credential resolver")

        operation_egress_policies = self._preflight_execution_request(plan_model, cancel_requested=cancel_requested)

        # Compatibility and workspace safety are part of the pre-consumption gate.
        secure_evidence_dirs = _supports_secure_evidence_dirs()
        portable_inert = not secure_evidence_dirs and all(op["tool"] == "inert" for op in plan_model.operations)
        if not secure_evidence_dirs and not portable_inert:
            raise WorkerIsolationError("adapter execution requires POSIX secure directory descriptors")
        if portable_inert and workspace_dir is not None:
            raise WorkerIsolationError("portable inert execution requires an isolated ephemeral workspace")
        # Reserve the workspace path before consuming the one-use authorization.
        # Ownership intent is journaled before any directory is created so a
        # worker restart can recover an artifact created immediately before a crash.
        ephemeral = workspace_dir is None
        if workspace_dir is None:
            target_workspace = Path(tempfile.gettempdir()).resolve(strict=True) / (
                f"cops-worker-{plan_model.plan_id}-{uuid.uuid4().hex}"
            )
        else:
            if ".." in Path(workspace_dir).parts:
                raise WorkerIsolationError(
                    "worker workspace path must not contain parent traversal or symbolic-link components"
                )
            target_workspace = Path(os.path.abspath(os.fspath(workspace_dir)))
        workspace_fd = -1
        if ephemeral:
            parent_fd = -1
            try:
                parent_fd = open_directory_no_symlinks(target_workspace.parent)
            except SecureDirectoryError as err:
                raise WorkerIsolationError(
                    "worker workspace parent must exist and contain no symbolic-link components"
                ) from err
            finally:
                if parent_fd >= 0:
                    os.close(parent_fd)
        else:
            workspace_fd = _open_caller_workspace(target_workspace)
            workspace_stack.callback(os.close, workspace_fd)

        receipt: ApprovalConsumptionReceipt | None = None
        cleanup_manager: CleanupManager | None = None
        try:
            ledger = SideEffectLedger(
                plan_id=plan_model.plan_id,
                engagement_id=plan_model.engagement_id,
                default_owner=self.config.worker_id,
                journal=self.cleanup_journal,
                run_id=authorization_id,
                workspace_dir=target_workspace,
            )
            cleanup_manager = CleanupManager(
                ledger=ledger,
                worker_identity=self.config.worker_id,
                workspace_dir=target_workspace,
            )
            workspace_scratch_effect = None
            if ephemeral:
                workspace_scratch_effect = ledger.record_effect(
                    step_id="workspace-scratch",
                    resource_type="directory",
                    target=str(target_workspace),
                    cleanup_action="delete",
                )
            try:
                if workspace_scratch_effect is not None:
                    workspace_fd = create_directory_exclusive_no_symlinks(target_workspace)
                    workspace_stack.callback(os.close, workspace_fd)
                    ledger.record_created_identity(
                        workspace_scratch_effect,
                        creation_fd=workspace_fd,
                    )
                else:
                    # Reject a path replacement before consuming authorization.
                    reopened_fd = _open_caller_workspace(target_workspace)
                    try:
                        if not same_directory_identity(reopened_fd, workspace_fd):
                            raise WorkerIsolationError("worker workspace changed after preflight")
                    finally:
                        os.close(reopened_fd)
            except SecureDirectoryError as err:
                raise WorkerIsolationError("worker workspace path must not contain symbolic-link components") from err
            self.approval_control.assert_ready(self.config.worker_id)
            self.sandbox.assert_ready(self.config.worker_id, cwd=target_workspace, expected_workspace_fd=workspace_fd)
            self._verify_plan_compatibility(plan_model)
            if self.cleanup_journal is not None:
                self.cleanup_journal.record_run_event(
                    authorization_id,
                    "approval_consumption_started",
                    {"plan_digest": plan_model.plan_digest},
                )
            receipt = self.approval_control.consume_authorization(authorization_id, plan_model, self.config.worker_id)
            verified_receipt = self.approval_control.validate_receipt_provenance(receipt)
            if verified_receipt is not receipt:
                raise ApprovalControlError("approval authority receipt provenance is invalid")
            if (
                receipt.authorization_id != authorization_id
                or receipt.action_plan_id != plan_model.plan_id
                or receipt.plan_digest != plan_model.plan_digest
                or receipt.engagement_id != plan_model.engagement_id
                or receipt.worker_identity != self.config.worker_id
                or receipt.target != plan_model.target
            ):
                raise ApprovalControlError("approval authority receipt does not match the execution plan")
            if self.cleanup_journal is not None:
                self.cleanup_journal.record_run_event(
                    authorization_id,
                    "approval_consumed",
                    {"authorization_digest": receipt.authorization_digest},
                )
            if failure_injection and failure_injection.get("inject_at") == "after_consume":
                raise WorkerExecutionError("injected failure after approval consumption")
        except BaseException:
            try:
                if cleanup_manager is not None:
                    self.last_cleanup_receipt = cleanup_manager.rollback()
            finally:
                if receipt is not None:
                    try:
                        self.approval_control.release_receipt_provenance(receipt)
                    except ApprovalControlError:
                        pass
            raise

        from .redaction import StreamRedactor

        redactor: StreamRedactor | None = None
        try:
            # 5. Set up isolated ephemeral workspace and side-effect ledger
            assert cleanup_manager is not None
            ledger = cleanup_manager.ledger

            started_at = utc_now()
            overall_exit_code = 0
            status = "success"
            status_reason = ""

            from .evidence import EvidenceContext, EvidenceRecorder

            # Initialize evidence recorder with redactor
            redactor = StreamRedactor()
            evidence_recorder = EvidenceRecorder(
                workspace_dir=target_workspace,
                expected_workspace_fd=workspace_fd,
                redactor=redactor,
                portable_inert=portable_inert,
                context=EvidenceContext(
                    plan_id=plan_model.plan_id,
                    plan_digest=plan_model.plan_digest,
                    authorization_id=receipt.authorization_id,
                    engagement_id=plan_model.engagement_id,
                    worker_identity=self.config.worker_id,
                    target=plan_model.target,
                ),
                ephemeral_workspace=ephemeral,
                cleanup_manager=cleanup_manager if ephemeral and not portable_inert else None,
            )

            max_duration_seconds = min(
                self.config.max_wall_time_seconds,
                plan_model.limits.get("max_duration_seconds", self.config.max_wall_time_seconds),
            )
            if timeout_seconds is not None:
                max_duration_seconds = min(max_duration_seconds, timeout_seconds)
            plan_max_output_bytes = min(
                self.config.max_output_bytes,
                plan_model.limits.get("max_output_bytes", self.config.max_output_bytes),
            )
            if max_output_bytes is not None:
                plan_max_output_bytes = min(plan_max_output_bytes, max_output_bytes)
            max_output_bytes = plan_max_output_bytes
            captured_output_bytes = 0
            persisted_output_bytes = 0
            credential_scratch_cleanup_failed = False
            start_dt = datetime.now(UTC)

            clean_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(target_workspace),
                "TMPDIR": str(target_workspace),
            }

        except BaseException:
            try:
                self.last_cleanup_receipt = cleanup_manager.rollback()
            finally:
                try:
                    if redactor is not None:
                        redactor.clear_secrets()
                finally:
                    self.approval_control.release_receipt_provenance(receipt)
            raise

        try:
            # Check injected failure before starting the first process.
            if failure_injection and failure_injection.get("inject_at") == "before_process":
                status = "failed"
                status_reason = "injected failure before process start"
                overall_exit_code = 1

            # 6. Execute operations in sequence (if checks passed)
            if status == "success":
                for operation_index, (op, operation_egress_policy) in enumerate(
                    zip(plan_model.operations, operation_egress_policies, strict=True)
                ):
                    step_id = op["step_id"]
                    tool = op["tool"]
                    action = op["action"]
                    is_idempotent = bool(op.get("idempotent", False))
                    # Track declared cleanup in side-effect ledger
                    if "cleanup" in op and isinstance(op["cleanup"], Mapping):
                        clean_spec = op["cleanup"]
                        clean_target = clean_spec.get("target") or str(target_workspace / f"{step_id}.tmp")
                        resource_type = clean_spec.get("resource_type", "file")
                        cleanup_metadata = dict(clean_spec)
                        cleanup_metadata[PLAN_DECLARED_PROVENANCE_KEY] = PLAN_DECLARED_PROVENANCE_UNVERIFIED
                        ledger.record_effect(
                            step_id=step_id,
                            resource_type=resource_type,
                            target=clean_target,
                            cleanup_action=clean_spec.get("action", "delete"),
                            metadata=cleanup_metadata,
                        )

                    if failure_injection and failure_injection.get("inject_at") == "during_execution":
                        target_step = failure_injection.get("step_id")
                        if target_step in (None, step_id):
                            if not is_idempotent:
                                status = "uncertain"
                                status_reason = (
                                    f"interrupted during non-idempotent step '{step_id}'; automatic repeat disallowed"
                                )
                            else:
                                status = "failed"
                                status_reason = f"injected failure during execution at step '{step_id}'"
                            overall_exit_code = 1
                            break

                    # Check overall plan duration limit
                    elapsed_seconds = (datetime.now(UTC) - start_dt).total_seconds()
                    if elapsed_seconds >= max_duration_seconds:
                        status = "partial"
                        status_reason = (
                            f"operation exceeded action plan max_duration_seconds limit ({max_duration_seconds}s)"
                        )
                        overall_exit_code = 124
                        break

                    remaining_time = max_duration_seconds - elapsed_seconds
                    timeout = min(float(op.get("timeout_seconds", 60)), remaining_time)
                    step_started = utc_now()
                    step_deadline = monotonic() + timeout

                    # Tool whitelist boundary
                    if tool not in self.config.allowed_tools and tool != "inert":
                        status = "failed"
                        status_reason = (
                            f"tool '{tool}' is not in worker allowed tools: {sorted(self.config.allowed_tools)}"
                        )
                        overall_exit_code = 127
                        break

                    # Prepare isolated execution via adapter or simulated inert
                    stdout_bytes = b""
                    stderr_bytes = b""
                    timed_out = False
                    output_limit_exceeded = False
                    artifact_reservation = None
                    prepared_cleanup_failed = False
                    operation_cleanup_failed = False
                    adapter_dispatched = False
                    credential_scratch_effect = None
                    operation_workspace = target_workspace
                    operation_workspace_fd = workspace_fd
                    if (
                        self.credential_resolver is not None
                        and self.credential_resolver.has_grant_for_operation(plan_model, op, operation_index)
                        and tool != "inert"
                    ):
                        operation_workspace = Path(tempfile.gettempdir()).resolve(strict=True) / (
                            f"cops-credential-operation-{operation_index}-{uuid.uuid4().hex}"
                        )
                        credential_scratch_effect = ledger.record_effect(
                            step_id=f"{step_id}-credential-scratch",
                            resource_type="directory",
                            target=str(operation_workspace),
                            cleanup_action="delete",
                            metadata={"purpose": "credential_operation_scratch"},
                        )
                        operation_workspace_fd = create_directory_exclusive_no_symlinks(operation_workspace)
                        workspace_stack.callback(os.close, operation_workspace_fd)
                        ledger.record_created_identity(
                            credential_scratch_effect,
                            creation_fd=operation_workspace_fd,
                        )
                    operation_env = {**clean_env, "HOME": str(operation_workspace), "TMPDIR": str(operation_workspace)}
                    try:
                        remaining_capture = max(0, max_output_bytes - captured_output_bytes)
                        # Evidence storage is reserved before any operation can have
                        # side effects. A reservation failure therefore fails closed
                        # without probing or invoking the adapter executable.
                        artifact_reservation = evidence_recorder.reserve_step_output(step_id)
                        if tool == "inert":
                            # Simulated execution for testing
                            raw_output = f"Inert step {step_id} executed successfully: {action}".encode()
                            stdout_bytes = raw_output[:remaining_capture]
                            output_limit_exceeded = len(raw_output) > remaining_capture
                            exit_code = 0
                        else:
                            if tool not in self.adapter_registry.list_tools():
                                # Tool has no registered adapter - fail closed
                                status = "failed"
                                status_reason = f"tool '{tool}' has no registered execution adapter"
                                overall_exit_code = 127
                                break
                            adapter = self.adapter_registry.get_adapter(tool)
                            if adapter.version != op["tool_version"]:
                                status = "failed"
                                status_reason = (
                                    f"adapter logical version for '{tool}' does not match approved version "
                                    f"{op['tool_version']!r}"
                                )
                                overall_exit_code = 126
                                break
                            cmd = adapter.assemble_command(action, op.get("arguments"))

                            def run_bound_probe(
                                command: Any,
                                *,
                                _operation_workspace_fd: int = operation_workspace_fd,
                                **kwargs: Any,
                            ) -> Any:
                                return self.sandbox.run(
                                    command, expected_workspace_fd=_operation_workspace_fd, **kwargs
                                )

                            prepared = prepare_executable(
                                adapter,
                                workspace=operation_workspace,
                                expected_workspace_fd=operation_workspace_fd,
                                env=operation_env,
                                timeout_seconds=timeout,
                                deadline=step_deadline,
                                process_runner=run_bound_probe,
                                cleanup_manager=cleanup_manager,
                                credential_scratch_root=(
                                    operation_workspace if credential_scratch_effect is not None else None
                                ),
                            )
                            try:
                                credential_env = (
                                    self.credential_resolver.resolve_for_operation(
                                        plan=plan_model,
                                        authorization=receipt,
                                        worker_identity=self.config.worker_id,
                                        operation=op,
                                        operation_index=operation_index,
                                        deadline=step_deadline,
                                        redactor=redactor,
                                    )
                                    if self.credential_resolver is not None
                                    else {}
                                )

                                def run_prepared_adapter(
                                    *,
                                    _step_deadline: float = step_deadline,
                                    _prepared: Any = prepared,
                                    _cmd: tuple[str, ...] = tuple(cmd),
                                    _remaining_capture: int = remaining_capture,
                                    _operation_workspace: Path = operation_workspace,
                                    _operation_workspace_fd: int = operation_workspace_fd,
                                    _operation_env: dict[str, str] = operation_env,
                                    **extra_arguments: Any,
                                ) -> Any:
                                    nonlocal adapter_dispatched
                                    invocation_timeout = _step_deadline - monotonic()
                                    if invocation_timeout <= 0:
                                        return None
                                    adapter_dispatched = True
                                    return self.sandbox.run(
                                        [_prepared.invocation_path, *_cmd[1:]],
                                        cwd=_operation_workspace,
                                        env=_operation_env,
                                        timeout_seconds=invocation_timeout,
                                        max_output_bytes=_remaining_capture,
                                        pass_fds=_prepared.pass_fds,
                                        expected_workspace_fd=_operation_workspace_fd,
                                        **extra_arguments,
                                    )

                                if operation_egress_policy is None:
                                    proc = run_prepared_adapter(
                                        **({"operation_env": credential_env} if credential_env else {})
                                    )
                                else:
                                    if self.scope_guard is None or self._egress_identity_verifier is None:
                                        raise WorkerIsolationError("operation egress preflight state is unavailable")
                                    mediator = HTTPSExecutionMediator(
                                        scope_guard=self.scope_guard,
                                        identity_verifier=self._egress_identity_verifier,
                                        identity_allowlist=operation_egress_policy.identity_allowlist,
                                        approved_origin=(
                                            operation_egress_policy.host,
                                            operation_egress_policy.port,
                                        ),
                                    )
                                    with ExecutionEgressBroker(mediator).open_channel(
                                        deadline=step_deadline
                                    ) as channel:
                                        proc = run_prepared_adapter(
                                            operation_env={**channel.environment, **credential_env},
                                            capability_fds=channel.pass_fds,
                                        )
                                if proc is None:
                                    stdout_bytes = b""
                                    stderr_bytes = b""
                                    timed_out = True
                                    exit_code = 124
                                else:
                                    stdout_bytes = proc.stdout
                                    stderr_bytes = proc.stderr
                                    timed_out = proc.timed_out
                                    output_limit_exceeded = proc.output_limit_exceeded
                                    exit_code = proc.returncode
                            finally:
                                try:
                                    prepared.remove()
                                except Exception:
                                    # Cleanup must not erase the observed process
                                    # result or the non-idempotent dispatch state.
                                    prepared_cleanup_failed = True
                    except ExecutablePreparationTimeoutError as err:
                        redacted_err = redactor.redact_string(str(err))
                        status = "partial"
                        status_reason = (
                            f"step '{step_id}' timed out during adapter executable preparation: {redacted_err}"
                        )
                        overall_exit_code = 124
                        break
                    except (AdapterError, ExecutableVerificationError) as err:
                        redacted_err = redactor.redact_string(str(err))
                        status = "failed"
                        status_reason = f"adapter execution verification failed: {redacted_err}"
                        overall_exit_code = 126
                        break
                    except KeyboardInterrupt:
                        if not is_idempotent:
                            status = "uncertain"
                            status_reason = (
                                f"interrupted during non-idempotent step '{step_id}'; automatic repeat disallowed"
                            )
                        else:
                            status = "cancelled"
                            status_reason = "execution cancelled by operator via interrupt"
                        overall_exit_code = 130
                        break
                    except Exception:
                        status = "uncertain" if adapter_dispatched and not is_idempotent else "failed"
                        status_reason = f"adapter execution failed at step '{step_id}'"
                        if status == "uncertain":
                            status_reason += "; automatic repeat disallowed"
                        overall_exit_code = 1
                        break
                    finally:
                        if operation_workspace != target_workspace:
                            try:
                                assert credential_scratch_effect is not None
                                cleanup_manager.cleanup_effect(credential_scratch_effect)
                            except CleanupPersistenceError:
                                operation_cleanup_failed = True
                                credential_scratch_cleanup_failed = True
                                assert credential_scratch_effect is not None
                                credential_scratch_effect.status = "unknown"
                                status = "uncertain" if adapter_dispatched and not is_idempotent else "failed"
                                status_reason = (
                                    f"credential operation scratch cleanup audit persistence failed at step '{step_id}'"
                                )
                                if status == "uncertain":
                                    status_reason += "; automatic repeat disallowed"
                                overall_exit_code = 1
                            except CleanupError:
                                operation_cleanup_failed = True
                                credential_scratch_cleanup_failed = True
                                status = "uncertain" if adapter_dispatched and not is_idempotent else "failed"
                                status_reason = f"credential operation scratch cleanup failed at step '{step_id}'"
                                if status == "uncertain":
                                    status_reason += "; automatic repeat disallowed"
                                overall_exit_code = 1
                            except OSError:
                                operation_cleanup_failed = True
                                credential_scratch_cleanup_failed = True
                                status = "uncertain" if adapter_dispatched and not is_idempotent else "failed"
                                status_reason = f"credential operation scratch cleanup failed at step '{step_id}'"
                                if status == "uncertain":
                                    status_reason += "; automatic repeat disallowed"
                                overall_exit_code = 1

                    # A bounded prefix can end inside an arbitrarily long secret.
                    # Suppress all raw output on timeout or overflow before any
                    # redaction, digest, telemetry, or artifact persistence.
                    if timed_out or output_limit_exceeded:
                        stdout_bytes = b""
                        stderr_bytes = b""
                    if timed_out:
                        exit_code = 124
                    elif output_limit_exceeded:
                        exit_code = 125
                    elif exit_code < 0:
                        exit_code = 128 - exit_code
                    captured_output_bytes += len(stdout_bytes) + len(stderr_bytes)
                    step_finished = utc_now()
                    # Record and redact evidence
                    remaining_artifact = max(0, max_output_bytes - persisted_output_bytes)
                    try:
                        _, artifact = evidence_recorder.record_step_output(
                            step_id=step_id,
                            tool=tool,
                            action=action,
                            tool_version=op["tool_version"],
                            stdout=stdout_bytes,
                            stderr=stderr_bytes,
                            exit_code=exit_code,
                            started_at=step_started,
                            finished_at=step_finished,
                            max_output_bytes=remaining_artifact,
                            reservation=artifact_reservation,
                        )
                    except Exception:
                        status = "uncertain" if adapter_dispatched and not is_idempotent else "failed"
                        status_reason = f"evidence capture failed at step '{step_id}'"
                        if status == "uncertain":
                            status_reason += "; automatic repeat disallowed"
                        overall_exit_code = 1
                        break
                    persisted_output_bytes += artifact.size_bytes

                    if operation_cleanup_failed:
                        break

                    if prepared_cleanup_failed:
                        if adapter_dispatched and not is_idempotent:
                            status = "uncertain"
                            status_reason = (
                                f"verified executable cleanup failed after non-idempotent step '{step_id}'; "
                                "automatic repeat disallowed"
                            )
                        else:
                            status = "partial"
                            status_reason = f"verified executable cleanup failed at step '{step_id}'"
                        overall_exit_code = 1
                        break

                    if timed_out:
                        status = "uncertain" if adapter_dispatched and not is_idempotent else "partial"
                        status_reason = (
                            f"step '{step_id}' timed out after {timeout} seconds; "
                            "retained raw output was suppressed before redaction"
                        )
                        if status == "uncertain":
                            status_reason += "; automatic repeat disallowed"
                        overall_exit_code = 124
                        break

                    if output_limit_exceeded:
                        status = "uncertain" if adapter_dispatched and not is_idempotent else "partial"
                        status_reason = (
                            f"step '{step_id}' exceeded the raw max_output_bytes limit "
                            f"({max_output_bytes} bytes for the action plan); retained raw "
                            "output was suppressed before redaction"
                        )
                        if status == "uncertain":
                            status_reason += "; automatic repeat disallowed"
                        overall_exit_code = 125
                        break

                    if exit_code != 0:
                        status = "failed"
                        status_reason = f"step '{step_id}' exited with non-zero code {exit_code}"
                        overall_exit_code = exit_code
                        break

                    if artifact.truncated_bytes:
                        status = "partial"
                        status_reason = (
                            f"step '{step_id}' post-redaction evidence exceeded the remaining "
                            f"max_output_bytes limit and was truncated by "
                            f"{artifact.truncated_bytes} bytes"
                        )
                        overall_exit_code = 125
                        break

        except Exception:
            status = "failed"
            status_reason = "unexpected worker execution failure"
            overall_exit_code = 1
        finally:
            finished_at = utc_now()
            try:
                try:
                    evidence_recorder.discard_pending_reservations()
                finally:
                    # Cleanup is mandatory even when evidence finalization fails.
                    cleanup_receipt = cleanup_manager.rollback()
                    self.last_cleanup_receipt = cleanup_receipt
                cleanup_status = cleanup_receipt.status
                if credential_scratch_cleanup_failed:
                    cleanup_status = "failed"

                if cleanup_receipt.status in ("failed", "partial"):
                    unres_summary = [e["target"] for e in cleanup_receipt.unresolved_effects]
                    if status == "success":
                        status = "partial"
                        status_reason = f"cleanup {cleanup_receipt.status}: unresolved artifacts: {unres_summary}"
                    elif not status_reason:
                        status_reason = f"cleanup {cleanup_receipt.status}: unresolved artifacts: {unres_summary}"

            finally:
                try:
                    redactor.clear_secrets()
                finally:
                    self.approval_control.release_receipt_provenance(receipt)

        # 7. Build and return RunResult contract
        result_id = f"res-{uuid.uuid4().hex[:16]}"
        summary_text = (
            "All action plan operations completed successfully"
            if status == "success"
            else f"Execution finished with status '{status}'"
        )
        status_details: dict[str, Any] = {"summary": summary_text}
        if status != "success":
            status_details["reason"] = status_reason

        # Combine authorization proof, recorded step evidence hashes, and cleanup receipt hash
        evidence_hashes = [receipt.authorization_digest]
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
        return AuthorizedExecution(RunResult.from_dict(result_doc), receipt)
