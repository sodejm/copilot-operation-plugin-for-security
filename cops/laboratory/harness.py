"""Scenario laboratory harness runtime for COPS security operations."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
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

from .evidence import LaboratoryEvidenceStore
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
        evidence_dir: Path | str | None = None,
    ) -> None:
        self.matrix = tested_matrix or TestedMatrix()
        self.observation_provider = observation_provider
        self.observation_trust_store = observation_trust_store
        self.case_journal = case_journal
        self.evidence_store = LaboratoryEvidenceStore(evidence_dir) if evidence_dir is not None else None
        self._pending_resets: dict[str, tuple[str, str, str, str]] = {}
        self._pending_cases: dict[
            str,
            tuple[
                RemoteAuthorizedRun,
                str,
                str,
                str,
                str,
                str,
                str,
                LaboratoryObservation,
                list[dict[str, Any]],
                str,
            ],
        ] = {}
        self._latest_environment_observations: dict[str, LaboratoryObservation] = {}
        self._last_reset_receipts: dict[str, tuple[LaboratoryResetReceipt, LaboratoryObservation]] = {}

    @staticmethod
    def _invalidate_verification(environment: LaboratoryEnvironment) -> None:
        environment.isolation["verification_status"] = "unverified"
        environment.isolation["verification_provenance"] = None
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

    def _validate_environment_configuration(
        self,
        environment: LaboratoryEnvironment,
        required_tools: list[str] | tuple[str, ...] | None,
    ) -> None:
        verify_platform_matrix(environment.platform, self.matrix)
        verify_tool_prerequisites(environment.tool_matrix, required_tools=required_tools, matrix=self.matrix)
        isolation = environment.isolation
        if not isolation.get("network_isolated"):
            raise IsolationVerificationError("Laboratory environment must have network isolation enabled.")
        if not isolation.get("egress_restricted"):
            raise IsolationVerificationError("Laboratory environment must enforce strict egress restrictions.")
        expected_type = {"container": "container_unprivileged", "vm": "vm_hypervisor"}.get(
            environment.environment_type
        )
        if expected_type is None or isolation.get("isolation_type") != expected_type:
            raise IsolationVerificationError(f"Unsupported isolation type '{isolation.get('isolation_type')}'.")
        if not environment.canary.get("canary_token") or not environment.canary.get("location"):
            raise CanaryVerificationError("Canary configuration must specify both 'canary_token' and 'location'.")

    def verify_environment(
        self,
        environment: LaboratoryEnvironment,
        *,
        endpoint_inventory: SSHRemoteEndpointInventory | None = None,
        required_tools: list[str] | tuple[str, ...] | None = None,
        mock_checks: bool = False,
    ) -> LaboratoryEnvironment:
        """Verify environment platform, tool prerequisites, isolation boundaries, and canary marker."""
        self._invalidate_verification(environment)
        self._discard_pending_cases(environment.environment_id, "environment reverification invalidated pending case")
        self._latest_environment_observations.pop(environment.environment_id, None)
        self._last_reset_receipts.pop(environment.environment_id, None)
        try:
            self._validate_environment_configuration(environment, required_tools)
        except (PrerequisiteMismatchError, IsolationVerificationError, CanaryVerificationError) as err:
            self._fail_verification(environment, str(err))
            raise
        if mock_checks:
            environment.isolation["verification_provenance"] = "simulated"
            environment.isolation["verification_notes"] = (
                "Configuration checks passed in explicit mock mode; runtime isolation, egress, canary, "
                "and baseline were not observed."
            )
            return environment

        try:
            observation = self._observe_environment(environment, endpoint_inventory=endpoint_inventory)
        except (IsolationVerificationError, CanaryVerificationError) as err:
            self._fail_verification(environment, str(err))
            raise

        environment.canary["verified"] = True
        environment.isolation["verification_status"] = "verified"
        environment.isolation["verification_provenance"] = "observed"
        environment.isolation["verification_timestamp"] = observation.observed_at
        environment.isolation["verification_notes"] = (
            "Fresh runtime isolation, egress, canary, and baseline observations passed."
        )
        self._latest_environment_observations[environment.environment_id] = observation

        if environment.status != "verified":
            environment.transition_to("verified")

        return environment

    def simulate_reset(self, environment: LaboratoryEnvironment) -> LaboratoryEnvironment:
        """Validate reset configuration without claiming a reset or clean baseline occurred."""
        reset_cfg = environment.reset_configuration
        if reset_cfg.get("reproducible") is not True:
            raise ResetError("laboratory reset is not marked reproducible")
        if reset_cfg.get("strategy") not in ("container_recreate", "snapshot_rollback", "script_revert"):
            raise ResetError("unsupported reset strategy")
        command = reset_cfg.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ResetError("a reset command is required")
        self._invalidate_verification(environment)
        self._discard_pending_cases(environment.environment_id, "simulated reset invalidated pending case")
        self._latest_environment_observations.pop(environment.environment_id, None)
        self._last_reset_receipts.pop(environment.environment_id, None)
        environment.isolation["verification_provenance"] = "simulated"
        environment.isolation["verification_notes"] = (
            "Reset configuration passed in explicit mock mode; no reset or post-reset baseline was observed."
        )
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
        environment.isolation["verification_provenance"] = "observed"
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
        missing_capabilities = set(plan_model.platform_prerequisites) - set(worker_inventory.platform_capabilities)
        if missing_capabilities:
            raise LaboratoryGateError(
                f"worker inventory lacks approved platform prerequisites: {sorted(missing_capabilities)}"
            )
        if not isinstance(scope_guard, ScopeGuard):
            raise LaboratoryGateError("an explicit laboratory scope guard is required")
        if plan_model.limits.get("egress_allowed") is not False:
            raise LaboratoryGateError("laboratory action plans must prohibit egress")
        try:
            ScopeGuard(ScopeDefinition.from_engagement_scope(engagement.scope)).check_destination(plan_model.target)
            scope_guard.check_destination(plan_model.target)
        except (AttributeError, TypeError, ValueError, ScopeViolationError) as err:
            raise LaboratoryGateError("laboratory scope guard violation or invalid engagement scope") from err
        if environment.isolation.get("verification_status") != "verified":
            raise LaboratoryGateError("laboratory isolation has not been verified")
        if environment.isolation.get("verification_provenance") != "observed":
            raise LaboratoryGateError("laboratory verification lacks fresh observed provenance; reverify the environment")
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
        if self.evidence_store is None:
            raise LaboratoryGateError("an explicit owner-only laboratory evidence directory is required")
        if self.case_journal.authorization_attempted(auth_model.authorization_id):
            raise LaboratoryGateError("execution authorization has already been used for a dispatch attempt")
        durable_evidence = [
            self.evidence_store.write_json("pre-execution-observation", asdict(pre_execution_observation))
        ]
        attempt_id = secrets.token_hex(32)
        dispatch_request_id = str(uuid.uuid4())
        self.case_journal.begin(
            attempt_id,
            environment.environment_id,
            {
                "plan_id": plan_model.plan_id,
                "plan_digest": plan_model.plan_digest,
                "authorization_id": auth_model.authorization_id,
                "case_type": case_type,
                "dispatch_request_id": dispatch_request_id,
                "operator_pre_execution_observation": asdict(pre_execution_observation),
                "durable_evidence": durable_evidence,
            },
        )

        def mark_unknown_best_effort(
            *,
            reason: str,
            failure_code: str,
            failure_basis: str,
            cleanup_reference: dict[str, Any] | None = None,
        ) -> None:
            """Retain all available evidence and consume the authorization on uncertain outcomes."""
            try:
                failure_reference = self.evidence_store.write_json(
                    "dispatch-failure",
                    {
                        "schema_version": "cops.laboratory-dispatch-failure/v1",
                        "environment_id": environment.environment_id,
                        "authorization_id": auth_model.authorization_id,
                        "plan_digest": plan_model.plan_digest,
                        "dispatch_request_id": dispatch_request_id,
                        "failure_code": failure_code,
                    },
                )
                durable_evidence.append(failure_reference)
            except Exception:
                failure_reference = None
            try:
                unknown_cleanup = self.evidence_store.write_json(
                    "cleanup-receipt",
                    {
                        "schema_version": "cops.laboratory-cleanup-receipt/v1",
                        "environment_id": environment.environment_id,
                        "authorization_id": auth_model.authorization_id,
                        "plan_digest": plan_model.plan_digest,
                        "dispatch_request_id": dispatch_request_id,
                        "result_id": None,
                        "receipt_producer": "controller",
                        "expected_worker_identity": environment.owner,
                        "cleanup_status": "unknown",
                        "basis": failure_basis,
                        "worker_evidence_records": [],
                    },
                )
                durable_evidence.append(unknown_cleanup)
                cleanup_reference = unknown_cleanup
            except Exception:
                unknown_cleanup = None
            try:
                self.case_journal.mark_unknown(
                    attempt_id,
                    reason,
                    evidence_records=durable_evidence,
                    cleanup_receipt_digest=(cleanup_reference or {}).get("sha256"),
                )
            except Exception:
                return

        dispatch_returned = False
        try:
            authorized_run = SSHExecutionDispatcher(endpoint_inventory).execute(
                approved_worker_identity=environment.owner,
                authorization_id=auth_model.authorization_id,
                action_plan=plan_model,
                request_id=dispatch_request_id,
            )
            dispatch_returned = True
            validate_remote_authorized_run(
                authorized_run,
                approved_worker_identity=environment.owner,
                authorization_id=auth_model.authorization_id,
                action_plan=plan_model,
            )
        except Exception as err:
            failure_code = (
                "trusted_worker_result_invalid"
                if dispatch_returned
                else "trusted_worker_dispatch_outcome_unknown"
            )
            failure_basis = (
                "dispatch returned an invalid or mismatched worker result"
                if dispatch_returned
                else "dispatch raised before a trusted worker result was available"
            )
            journal_reason = (
                "trusted worker result invalid"
                if dispatch_returned
                else "trusted worker dispatch outcome unknown"
            )
            mark_unknown_best_effort(
                reason=journal_reason,
                failure_code=failure_code,
                failure_basis=failure_basis,
            )
            raise LaboratoryGateError(f"trusted worker dispatch failed: {failure_basis}") from err
        cleanup_evidence: dict[str, Any] | None = None
        try:
            run_evidence = self.evidence_store.write_json("run-result", authorized_run.result.to_dict())
            durable_evidence.append(run_evidence)
            cleanup_evidence = self.evidence_store.write_json(
                "cleanup-receipt",
                {
                    "schema_version": "cops.laboratory-cleanup-receipt/v1",
                    "environment_id": environment.environment_id,
                    "authorization_id": auth_model.authorization_id,
                    "plan_digest": plan_model.plan_digest,
                    "dispatch_request_id": dispatch_request_id,
                    "result_id": authorized_run.result.result_id,
                    "receipt_producer": "controller",
                    "reported_worker_identity": authorized_run.result.worker_identity,
                    "cleanup_status": authorized_run.result.cleanup_status,
                    "basis": "trusted worker result",
                    "worker_evidence_records": list(authorized_run.result.evidence_records),
                },
            )
            durable_evidence.append(cleanup_evidence)
            failure_result = LaboratoryCaseResult(
                case_type=case_type,
                status="failed",
                environment_id=environment.environment_id,
                plan_id=plan_model.plan_id,
                run_result=authorized_run.result,
                canary_verified=False,
                observed_case_type="indeterminate",
                evidence_records=list(authorized_run.result.evidence_records),
                cleanup_receipt=None,
                cleanup_receipt_digest=cleanup_evidence["sha256"],
                details={
                    "operator_case_observation": None,
                    "operator_pre_execution_observation": asdict(pre_execution_observation),
                    "worker_cleanup_status": authorized_run.result.cleanup_status,
                    "failure_reason": "operator case observation missing",
                    "durable_evidence": durable_evidence,
                },
            )
            self.case_journal.bind(attempt_id, authorized_run.result.result_id, failure_result.to_dict())
        except Exception as err:
            mark_unknown_best_effort(
                reason="trusted worker result persistence failed",
                failure_code="trusted_worker_result_persistence_failed",
                failure_basis="trusted worker result could not be durably recorded",
                cleanup_reference=cleanup_evidence,
            )
            raise LaboratoryGateError("trusted worker result persistence failed") from err
        self._pending_cases[authorized_run.result.result_id] = (
            authorized_run,
            environment.environment_id,
            auth_model.authorization_id,
            plan_model.plan_digest,
            case_type,
            secrets.token_hex(32),
            utc_now(),
            pre_execution_observation,
            durable_evidence,
            cleanup_evidence["sha256"],
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
        nonce, requested_at, pre_execution_observation, durable_evidence, cleanup_receipt_digest = pending[5:]
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
        if (
            result.status == "success"
            and result.exit_code == 0
            and canary_found
            and not blocked
            and cleaned
        ):
            observed_case_type = "positive"
        elif (
            result.status == "success"
            and result.exit_code == 0
            and not canary_found
            and blocked
            and cleaned
        ):
            observed_case_type = "remediated"
        elif (
            result.status == "failed"
            and type(result.exit_code) is int
            and result.exit_code != 0
            and not canary_found
            and blocked
            and cleaned
        ):
            observed_case_type = "negative"
        else:
            observed_case_type = "indeterminate"
        matching_status = {"positive": "success", "remediated": "remediated", "negative": "rejected"}
        case_status = matching_status[case_type] if observed_case_type == case_type else "failed"
        observation_evidence = self.evidence_store.write_json("case-observation", asdict(case_observation))
        durable_evidence = [*durable_evidence, observation_evidence]
        case_result = LaboratoryCaseResult(
            case_type=case_type,
            status=case_status,
            environment_id=environment.environment_id,
            plan_id=action_plan.plan_id,
            run_result=result,
            canary_verified=case_status == "success",
            observed_case_type=observed_case_type,
            evidence_records=list(result.evidence_records),
            cleanup_receipt=None,
            cleanup_receipt_digest=cleanup_receipt_digest,
            details={
                "operator_case_observation": asdict(case_observation),
                "operator_pre_execution_observation": asdict(pre_execution_observation),
                "operator_reset_receipt": (
                    asdict(self._last_reset_receipts[environment.environment_id][0])
                    if environment.environment_id in self._last_reset_receipts
                    else None
                ),
                "operator_post_reset_observation": (
                    asdict(self._last_reset_receipts[environment.environment_id][1])
                    if environment.environment_id in self._last_reset_receipts
                    else None
                ),
                "worker_cleanup_status": result.cleanup_status,
                "durable_evidence": durable_evidence,
            },
        )
        if self.case_journal is None:
            raise LaboratoryGateError("an owner-only laboratory case journal is required")
        self.case_journal.finish(
            result.result_id,
            case_result.to_dict(),
            state="failed" if case_status == "failed" else "classified",
        )
        self._pending_cases.pop(result.result_id)
        return case_result
