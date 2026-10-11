"""Scenario laboratory harness runtime for COPS security operations."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cops.contracts.models import (
    ActionPlan,
    ExecutionAuthorization,
    LaboratoryEnvironment,
)
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import EvidenceError, timestamp, utc_now
from cops.execution.authorization import (
    AuthorizationError,
    AuthorizationTrustStore,
    verify_execution_authorization,
)
from cops.execution.scope_guard import ScopeDefinition, ScopeGuard, ScopeViolationError
from cops.execution.ssh_execution import (
    RemoteAuthorizedRun,
    SSHExecutionDispatcher,
    SSHExecutionError,
    validate_remote_authorized_run,
)
from cops.execution.ssh_transport import SSHRemoteEndpointInventory, SSHTransportError
from cops.execution.worker import WorkerCapabilityInventory

from .journal import LaboratoryCaseJournal
from .matrix import verify_platform_matrix, verify_tool_prerequisites
from .models import (
    CanaryVerificationError,
    IsolationVerificationError,
    LaboratoryCaseResult,
    LaboratoryGateError,
    LaboratoryObservation,
    PrerequisiteMismatchError,
    ResetError,
    TestedMatrix,
)
from .receipts import (
    LaboratoryCaseObservation,
    LaboratoryObservationTrustStore,
    LaboratoryResetReceipt,
    operation_timestamp,
    verify_worker_receipt,
)


class LaboratoryHarness:
    """Manages laboratory environments, isolation checks, reproducible resets, and case execution."""

    def __init__(
        self,
        tested_matrix: TestedMatrix | None = None,
        observation_provider: Callable[[LaboratoryEnvironment, str], LaboratoryObservation] | None = None,
        observation_trust_store: LaboratoryObservationTrustStore | None = None,
        case_journal: LaboratoryCaseJournal | None = None,
    ) -> None:
        self.matrix = tested_matrix or TestedMatrix()
        self.observation_provider = observation_provider
        self.observation_trust_store = observation_trust_store
        self.case_journal = case_journal
        self._pending_resets: dict[str, tuple[str, str, str, str]] = {}
        self._pending_cases: dict[str, tuple[RemoteAuthorizedRun, str, str, str, str, str, str, LaboratoryObservation]] = {}
        self._latest_environment_observations: dict[str, LaboratoryObservation] = {}
        self._last_reset_receipts: dict[str, tuple[LaboratoryResetReceipt, LaboratoryObservation]] = {}

    @staticmethod
    def _invalidate_verification(environment: LaboratoryEnvironment) -> None:
        environment.isolation["verification_status"] = "unverified"
        environment.isolation["verification_timestamp"] = None
        environment.canary["verified"] = False

    def _discard_pending_cases(self, environment_id: str, reason: str) -> None:
        for result_id, pending in tuple(self._pending_cases.items()):
            if pending[1] == environment_id:
                if self.case_journal is None:
                    raise LaboratoryGateError("an owner-only laboratory case journal is required")
                self.case_journal.fail(result_id, reason)
                del self._pending_cases[result_id]

    def expire_pending_cases(self) -> list[dict[str, Any]]:
        """Fail cases that did not receive a signed observation within two minutes."""
        expired: list[dict[str, Any]] = []
        deadline = datetime.now(UTC) - timedelta(minutes=2)
        for result_id, pending in tuple(self._pending_cases.items()):
            if timestamp(pending[6]) < deadline:
                if self.case_journal is None:
                    raise LaboratoryGateError("an owner-only laboratory case journal is required")
                expired.append(self.case_journal.fail(result_id, "operator case observation missing before deadline"))
                del self._pending_cases[result_id]
        return expired

    def recorded_cases(self) -> list[dict[str, Any]]:
        """Return journaled dispatch attempts and terminal case results."""
        self.expire_pending_cases()
        if self.case_journal is None:
            raise LaboratoryGateError("an owner-only laboratory case journal is required")
        return self.case_journal.records()

    def _fail_verification(self, environment: LaboratoryEnvironment, reason: str) -> None:
        self._invalidate_verification(environment)
        self._discard_pending_cases(environment.environment_id, f"environment verification failed: {reason}")
        self._latest_environment_observations.pop(environment.environment_id, None)
        self._last_reset_receipts.pop(environment.environment_id, None)
        environment.isolation["verification_status"] = "failed"
        environment.isolation["verification_notes"] = reason
        environment.canary["verified"] = False
        if environment.status != "failed":
            environment.transition_to("failed")

    def _observe_environment(
        self,
        environment: LaboratoryEnvironment,
        *,
        endpoint_inventory: SSHRemoteEndpointInventory,
        after: str | None = None,
    ) -> LaboratoryObservation:
        """Check owner-provided measurements; contract flags never count as measurements."""
        if not isinstance(endpoint_inventory, SSHRemoteEndpointInventory) or not endpoint_inventory.is_verified:
            raise IsolationVerificationError("A verified owner-provisioned SSH endpoint inventory is required.")
        try:
            endpoint_inventory.resolve(environment.owner)
        except SSHTransportError as err:
            raise IsolationVerificationError("Laboratory owner has no trusted worker endpoint.") from err
        if self.observation_provider is None:
            raise IsolationVerificationError("An operator-owned runtime observation provider is required.")
        nonce = secrets.token_hex(32)
        requested_at = utc_now()
        try:
            observation = self.observation_provider(environment, nonce)
        except Exception as err:
            raise IsolationVerificationError("Runtime observation provider failed.") from err
        if not isinstance(observation, LaboratoryObservation):
            raise IsolationVerificationError("Runtime observation provider returned no typed measurements.")
        try:
            verify_worker_receipt(
                observation,
                trust_store=self.observation_trust_store,
                worker_identity=environment.owner,
                after=requested_at,
            )
        except LaboratoryGateError as err:
            raise IsolationVerificationError("Runtime observation attestation failed.") from err
        if observation.request_nonce != nonce:
            raise IsolationVerificationError("Runtime observation does not match the challenge.")
        if observation.environment_id != environment.environment_id:
            raise IsolationVerificationError("Runtime observation identifies a different environment.")
        if observation.isolation_type != environment.isolation.get("isolation_type"):
            raise IsolationVerificationError("Observed isolation type does not match the environment.")
        if observation.network_isolated is not True or observation.egress_restricted is not True:
            raise IsolationVerificationError("Runtime isolation or egress observation failed.")
        try:
            observed_at = timestamp(observation.observed_at)
            reset_completed_at = timestamp(after) if after is not None else None
        except EvidenceError as err:
            raise IsolationVerificationError("Runtime observation timestamp is invalid.") from err
        now = datetime.now(UTC)
        if observed_at < now - timedelta(minutes=2) or observed_at > now + timedelta(seconds=5):
            raise IsolationVerificationError("Runtime observation is stale or future dated.")
        if reset_completed_at is not None and observed_at <= reset_completed_at:
            raise IsolationVerificationError("Runtime observation predates the reset.")
        token = environment.canary.get("canary_token")
        if not isinstance(token, str) or not token or not environment.canary.get("location"):
            raise CanaryVerificationError("Canary configuration requires a token and location.")
        expected_canary = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if not isinstance(observation.canary_digest, str) or not hmac.compare_digest(
            observation.canary_digest, expected_canary
        ):
            raise CanaryVerificationError("Observed canary does not match the configured canary.")
        baseline = environment.reset_configuration.get("expected_baseline_digest")
        if not isinstance(baseline, str) or len(baseline) != 64:
            raise IsolationVerificationError("An expected baseline digest is required.")
        if not isinstance(observation.baseline_digest, str) or not hmac.compare_digest(
            observation.baseline_digest, baseline
        ):
            raise IsolationVerificationError("Observed baseline does not match the expected clean baseline.")
        return observation

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
        endpoint_inventory: SSHRemoteEndpointInventory,
        required_tools: list[str] | tuple[str, ...] | None = None,
        mock_checks: bool = False,
    ) -> LaboratoryEnvironment:
        """Verify environment platform, tool prerequisites, isolation boundaries, and canary marker."""
        self._invalidate_verification(environment)
        self._discard_pending_cases(environment.environment_id, "environment reverification invalidated pending case")
        self._latest_environment_observations.pop(environment.environment_id, None)
        self._last_reset_receipts.pop(environment.environment_id, None)
        if mock_checks:
            self._fail_verification(environment, "Mock checks cannot verify a laboratory environment.")
            raise IsolationVerificationError("Mock checks cannot verify a laboratory environment.")

        try:
            verify_platform_matrix(environment.platform, self.matrix)
            verify_tool_prerequisites(environment.tool_matrix, required_tools=required_tools, matrix=self.matrix)
        except PrerequisiteMismatchError as err:
            self._fail_verification(environment, str(err))
            raise

        # 3. Isolation checks
        iso = environment.isolation
        if not iso.get("network_isolated"):
            self._fail_verification(environment, "Network isolation boundary is disabled or unconfigured.")
            raise IsolationVerificationError("Laboratory environment must have network isolation enabled.")

        if not iso.get("egress_restricted"):
            self._fail_verification(environment, "Egress restriction is disabled; potential data leak.")
            raise IsolationVerificationError("Laboratory environment must enforce strict egress restrictions.")

        iso_type = iso.get("isolation_type")
        expected_type = {"container": "container_unprivileged", "vm": "vm_hypervisor"}.get(
            environment.environment_type
        )
        if expected_type is None or iso_type != expected_type:
            self._fail_verification(environment, f"Unsupported environment/isolation pair: {environment.environment_type}/{iso_type}")
            raise IsolationVerificationError(f"Unsupported isolation type '{iso_type}'.")

        # 4. Canary data verification
        canary = environment.canary
        token = canary.get("canary_token")
        location = canary.get("location")
        if not token or not location:
            self._fail_verification(environment, "Canary configuration is incomplete.")
            raise CanaryVerificationError("Canary configuration must specify both 'canary_token' and 'location'.")

        try:
            observation = self._observe_environment(environment, endpoint_inventory=endpoint_inventory)
        except (IsolationVerificationError, CanaryVerificationError) as err:
            self._fail_verification(environment, str(err))
            raise

        environment.canary["verified"] = True
        environment.isolation["verification_status"] = "verified"
        environment.isolation["verification_timestamp"] = observation.observed_at
        environment.isolation["verification_notes"] = "Fresh runtime isolation, egress, canary, and baseline observations passed."
        self._latest_environment_observations[environment.environment_id] = observation

        if environment.status != "verified":
            environment.transition_to("verified")

        return environment

    def begin_reset(self, environment: LaboratoryEnvironment) -> str:
        """Issue a single-use challenge for an operator-owned worker reset."""
        reset_cfg = environment.reset_configuration
        if environment.status not in ("verified", "active", "failed"):
            raise ResetError("laboratory environment must be verified, active, or failed before reset")
        if reset_cfg.get("reproducible") is not True:
            raise ResetError("laboratory reset is not marked reproducible")
        strategy = reset_cfg.get("strategy")
        if strategy not in ("container_recreate", "snapshot_rollback", "script_revert"):
            raise ResetError("unsupported reset strategy")
        command = reset_cfg.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ResetError("a reset command is required")
        if self.observation_provider is None:
            raise ResetError("an operator-owned runtime observation provider is required")
        self._invalidate_verification(environment)
        self._discard_pending_cases(environment.environment_id, "environment reset invalidated pending case")
        self._latest_environment_observations.pop(environment.environment_id, None)
        self._last_reset_receipts.pop(environment.environment_id, None)
        self._pending_resets.pop(environment.environment_id, None)
        environment.transition_to("resetting")
        nonce = secrets.token_hex(32)
        self._pending_resets[environment.environment_id] = (
            nonce,
            utc_now(),
            strategy,
            hashlib.sha256(command.encode("utf-8")).hexdigest(),
        )
        return nonce

    def reproducible_reset(
        self,
        environment: LaboratoryEnvironment,
        *,
        reset_receipt: LaboratoryResetReceipt,
        endpoint_inventory: SSHRemoteEndpointInventory,
    ) -> LaboratoryEnvironment:
        """Verify a challenged worker reset and a fresh clean-baseline observation."""
        pending = self._pending_resets.get(environment.environment_id)
        if pending is None or environment.status != "resetting":
            raise ResetError("no pending worker reset challenge exists for this environment")
        self._pending_resets.pop(environment.environment_id)
        nonce, requested_at, strategy, command_digest = pending
        try:
            verify_worker_receipt(
                reset_receipt,
                trust_store=self.observation_trust_store,
                worker_identity=environment.owner,
                after=requested_at,
            )
            if (
                reset_receipt.environment_id != environment.environment_id
                or reset_receipt.strategy != strategy
                or reset_receipt.command_digest != command_digest
                or reset_receipt.request_nonce != nonce
            ):
                raise ResetError("worker reset receipt does not match the pending challenge")
            observation = self._observe_environment(
                environment, endpoint_inventory=endpoint_inventory, after=reset_receipt.completed_at
            )
        except (LaboratoryGateError, ResetError, IsolationVerificationError, CanaryVerificationError) as err:
            self._fail_verification(environment, "Worker reset or post-reset baseline verification failed.")
            raise ResetError("worker reset or post-reset baseline verification failed") from err
        environment.reset_configuration["last_reset_timestamp"] = observation.observed_at
        environment.canary["verified"] = True
        environment.isolation["verification_status"] = "verified"
        environment.isolation["verification_timestamp"] = observation.observed_at
        environment.isolation["verification_notes"] = "Attested worker reset and post-reset observations passed."
        self._latest_environment_observations[environment.environment_id] = observation
        self._last_reset_receipts[environment.environment_id] = (reset_receipt, observation)
        environment.transition_to("verified")
        return environment

    def execute_case(
        self,
        environment: LaboratoryEnvironment,
        action_plan: ActionPlan | dict[str, Any],
        authorization: ExecutionAuthorization | dict[str, Any],
        case_type: Literal["positive", "negative", "remediated"] = "positive",
        *,
        trust_store: AuthorizationTrustStore,
        engagement: Any,
        worker_inventory: WorkerCapabilityInventory,
        endpoint_inventory: SSHRemoteEndpointInventory,
        scope_guard: ScopeGuard,
    ) -> RemoteAuthorizedRun:
        """Dispatch one authorized plan to the pinned worker after laboratory gates."""
        if case_type not in ("positive", "negative", "remediated"):
            raise LaboratoryGateError("unsupported laboratory case type")
        if not isinstance(worker_inventory, WorkerCapabilityInventory) or not worker_inventory.is_verified:
            raise LaboratoryGateError("a verified owner-provisioned worker capability inventory is required")
        if not isinstance(endpoint_inventory, SSHRemoteEndpointInventory) or not endpoint_inventory.is_verified:
            raise LaboratoryGateError("a verified owner-provisioned SSH endpoint inventory is required")
        try:
            endpoint_inventory.resolve(environment.owner)
        except SSHTransportError as err:
            raise LaboratoryGateError("laboratory owner has no trusted worker endpoint") from err
        plan_model = ActionPlan.from_dict(action_plan) if isinstance(action_plan, dict) else action_plan
        if not isinstance(plan_model, ActionPlan):
            raise LaboratoryGateError("a typed action plan is required")
        if environment.status not in ("verified", "active"):
            raise LaboratoryGateError("laboratory environment must be verified or active before execution")
        if worker_inventory.worker_identity != environment.owner:
            raise LaboratoryGateError("worker capability inventory identity does not match the laboratory owner")

        required_tools = {operation["tool"] for operation in plan_model.operations}
        try:
            verify_tool_prerequisites(
                environment.tool_matrix, required_tools=sorted(required_tools), matrix=self.matrix
            )
        except Exception as err:
            raise LaboratoryGateError("approved tool prerequisite gate failed") from err
        for operation in plan_model.operations:
            if worker_inventory.tool_versions.get(operation["tool"]) != operation["tool_version"]:
                raise LaboratoryGateError("worker tool version does not match the approved plan")
        missing_capabilities = set(plan_model.platform_prerequisites) - set(
            worker_inventory.platform_capabilities
        )
        if missing_capabilities:
            raise LaboratoryGateError(
                f"worker inventory lacks approved platform prerequisites: {sorted(missing_capabilities)}"
            )
        if not isinstance(scope_guard, ScopeGuard):
            raise LaboratoryGateError("an explicit laboratory scope guard is required")
        if plan_model.limits.get("egress_allowed") is not False:
            raise LaboratoryGateError("laboratory action plans must prohibit egress")
        try:
            ScopeGuard(ScopeDefinition.from_engagement_scope(engagement.scope)).check_destination(
                plan_model.target
            )
            scope_guard.check_destination(plan_model.target)
        except (AttributeError, TypeError, ValueError, ScopeViolationError) as err:
            raise LaboratoryGateError("laboratory scope guard violation or invalid engagement scope") from err
        if environment.isolation.get("verification_status") != "verified":
            raise LaboratoryGateError("laboratory isolation has not been verified")
        try:
            pre_execution_observation = self._observe_environment(environment, endpoint_inventory=endpoint_inventory)
        except (IsolationVerificationError, CanaryVerificationError) as err:
            self._fail_verification(environment, "Fresh runtime verification failed before case execution.")
            raise LaboratoryGateError("fresh runtime verification failed before case execution") from err
        if isinstance(authorization, dict):
            auth_model = ExecutionAuthorization.from_dict(authorization)
        elif isinstance(authorization, ExecutionAuthorization):
            auth_model = authorization
        else:
            raise LaboratoryGateError("a signed execution authorization is required")
        try:
            auth_model = verify_execution_authorization(
                auth_model,
                plan_model,
                trust_store=trust_store,
                engagement=engagement,
                worker_identity=environment.owner,
            )
        except AuthorizationError as err:
            raise LaboratoryGateError("execution authorization gate failed") from err
        if self.case_journal is None:
            raise LaboratoryGateError("an owner-only laboratory case journal is required")
        attempt_id = secrets.token_hex(32)
        dispatch_request_id = str(uuid.uuid4())
        self.case_journal.begin(attempt_id, environment.environment_id, {
            "plan_id": plan_model.plan_id,
            "plan_digest": plan_model.plan_digest,
            "authorization_id": auth_model.authorization_id,
            "case_type": case_type,
            "dispatch_request_id": dispatch_request_id,
            "operator_pre_execution_observation": asdict(pre_execution_observation),
        })
        try:
            authorized_run = SSHExecutionDispatcher(endpoint_inventory).execute(
                approved_worker_identity=environment.owner,
                authorization_id=auth_model.authorization_id,
                action_plan=plan_model,
                request_id=dispatch_request_id,
            )
        except Exception as err:
            self.case_journal.mark_unknown(attempt_id, "trusted worker dispatch outcome unknown")
            raise LaboratoryGateError("trusted worker dispatch failed") from err
        failure_result = LaboratoryCaseResult(
            case_type=case_type,
            status="failed",
            environment_id=environment.environment_id,
            plan_id=plan_model.plan_id,
            run_result=authorized_run.result,
            canary_verified=False,
            evidence_records=list(authorized_run.result.evidence_records),
            cleanup_receipt=None,
            details={
                "operator_case_observation": None,
                "operator_pre_execution_observation": asdict(pre_execution_observation),
                "worker_cleanup_status": authorized_run.result.cleanup_status,
                "failure_reason": "operator case observation missing",
            },
        )
        self.case_journal.bind(attempt_id, authorized_run.result.result_id, failure_result.to_dict())
        self._pending_cases[authorized_run.result.result_id] = (
            authorized_run,
            environment.environment_id,
            auth_model.authorization_id,
            plan_model.plan_digest,
            case_type,
            secrets.token_hex(32),
            utc_now(),
            pre_execution_observation,
        )
        return authorized_run

    def case_observation_challenge(self, authorized_run: RemoteAuthorizedRun) -> str:
        """Return the fresh challenge to be sent to the independent operator adapter."""
        self.expire_pending_cases()
        if not isinstance(authorized_run, RemoteAuthorizedRun):
            raise LaboratoryGateError("a trusted remote authorized run is required")
        pending = self._pending_cases.get(authorized_run.result.result_id)
        if pending is None or pending[0] != authorized_run:
            raise LaboratoryGateError("laboratory result is not bound to a pending dispatch")
        return pending[5]

    def classify_case(
        self,
        environment: LaboratoryEnvironment,
        action_plan: ActionPlan,
        authorized_run: RemoteAuthorizedRun,
        authorization_id: str,
        case_type: Literal["positive", "negative", "remediated"],
        *,
        case_observation: LaboratoryCaseObservation,
        endpoint_inventory: SSHRemoteEndpointInventory,
    ) -> LaboratoryCaseResult:
        """Classify only a worker result and observation bound to this dispatch."""
        self.expire_pending_cases()
        if not isinstance(authorized_run, RemoteAuthorizedRun):
            raise LaboratoryGateError("a trusted remote authorized run is required")
        result = authorized_run.result
        pending = self._pending_cases.get(result.result_id)
        if pending is None or pending[:5] != (
            authorized_run,
            environment.environment_id,
            authorization_id,
            action_plan.plan_digest,
            case_type,
        ):
            raise LaboratoryGateError("laboratory result is not bound to a pending dispatch")
        nonce, requested_at, pre_execution_observation = pending[5:]
        try:
            validate_remote_authorized_run(
                authorized_run,
                approved_worker_identity=environment.owner,
                authorization_id=authorization_id,
                action_plan=action_plan,
            )
            verify_worker_receipt(
                case_observation,
                trust_store=self.observation_trust_store,
                worker_identity=environment.owner,
                after=requested_at,
            )
        except (SSHExecutionError, LaboratoryGateError) as err:
            raise LaboratoryGateError("worker result or case observation verification failed") from err
        if (
            case_observation.environment_id != environment.environment_id
            or case_observation.authorization_id != authorization_id
            or case_observation.plan_digest != action_plan.plan_digest
            or case_observation.result_id != result.result_id
            or case_observation.result_finished_at != result.finished_at
            or case_observation.request_nonce != nonce
        ):
            raise LaboratoryGateError("worker case observation does not match the authorized result")
        try:
            if timestamp(case_observation.observed_at) <= operation_timestamp(result.finished_at):
                raise LaboratoryGateError("worker case observation predates the authorized result")
        except EvidenceError as err:
            raise LaboratoryGateError("worker case observation timestamp is invalid") from err

        canary_found = case_observation.canary_token_detected
        blocked = case_observation.control_blocked
        cleaned = result.cleanup_status in ("completed", "not_required")
        if case_type == "positive" and result.status == "success" and result.exit_code == 0 and canary_found and not blocked and cleaned:
            case_status = "success"
        elif case_type == "remediated" and result.status == "success" and result.exit_code == 0 and not canary_found and blocked and cleaned:
            case_status = "remediated"
        elif case_type == "negative" and result.status == "failed" and type(result.exit_code) is int and result.exit_code != 0 and not canary_found and blocked and cleaned:
            case_status = "rejected"
        else:
            case_status = "failed"
        case_result = LaboratoryCaseResult(
            case_type=case_type,
            status=case_status,
            environment_id=environment.environment_id,
            plan_id=action_plan.plan_id,
            run_result=result,
            canary_verified=case_status == "success",
            evidence_records=list(result.evidence_records),
            cleanup_receipt=None,
            details={
                "operator_case_observation": asdict(case_observation),
                "operator_pre_execution_observation": asdict(pre_execution_observation),
                "operator_reset_receipt": (
                    asdict(self._last_reset_receipts[environment.environment_id][0])
                    if environment.environment_id in self._last_reset_receipts else None
                ),
                "operator_post_reset_observation": (
                    asdict(self._last_reset_receipts[environment.environment_id][1])
                    if environment.environment_id in self._last_reset_receipts else None
                ),
                "worker_cleanup_status": result.cleanup_status,
            },
        )
        if self.case_journal is None:
            raise LaboratoryGateError("an owner-only laboratory case journal is required")
        self.case_journal.finish(
            result.result_id, case_result.to_dict(),
            state="failed" if case_status == "failed" else "classified",
        )
        self._pending_cases.pop(result.result_id)
        return case_result
