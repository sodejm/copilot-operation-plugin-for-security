"""Typed, approval-bound execution over the authenticated SSH transport."""

from __future__ import annotations

import math
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cops.contracts.models import ActionPlan, RunResult

from .control import ApprovalConsumptionReceipt
from .ssh_transport import (
    SSHRemoteDispatcher,
    SSHRemoteEndpointInventory,
    SSHTransportError,
    SSHTransportLimits,
)
from .supervisor_attestation import SupervisorAttestationError, verify_attested_authorized_run

SSH_EXECUTION_REQUEST_SCHEMA = "cops.remote-execution-request/v1"
SSH_AUTHORIZED_RUN_SCHEMA = "cops.remote-authorized-run/v1"

_RECEIPT_FIELDS = {
    "authorization_id",
    "authorization_digest",
    "action_plan_id",
    "plan_digest",
    "engagement_id",
    "worker_identity",
    "target",
}


class SSHExecutionError(SSHTransportError):
    """A remote execution message was invalid or not bound to its approval."""


@dataclass(frozen=True)
class RemoteAuthorizedRun:
    """A remote result accompanied by the authority's consumption receipt."""

    result: RunResult
    approval_receipt: ApprovalConsumptionReceipt

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SSH_AUTHORIZED_RUN_SCHEMA,
            "result": self.result.to_dict(),
            "approval_receipt": _receipt_to_dict(self.approval_receipt),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, object]) -> RemoteAuthorizedRun:
        if not isinstance(document, Mapping) or set(document) != {
            "schema_version",
            "result",
            "approval_receipt",
        }:
            raise SSHExecutionError("remote authorized run fields do not match the required schema")
        if document["schema_version"] != SSH_AUTHORIZED_RUN_SCHEMA:
            raise SSHExecutionError("unsupported remote authorized run schema version")
        result_document = document["result"]
        receipt_document = document["approval_receipt"]
        if not isinstance(result_document, dict) or not isinstance(receipt_document, Mapping):
            raise SSHExecutionError("remote authorized run payload is invalid")
        if set(receipt_document) != _RECEIPT_FIELDS:
            raise SSHExecutionError("remote approval receipt fields do not match the required schema")
        if any(
            not isinstance(receipt_document[field], str) or not receipt_document[field] for field in _RECEIPT_FIELDS
        ):
            raise SSHExecutionError("remote approval receipt contains an invalid field")
        try:
            result = RunResult.from_dict(result_document)
        except Exception as err:
            raise SSHExecutionError("remote run result is invalid") from err
        return cls(
            result=result,
            approval_receipt=ApprovalConsumptionReceipt(
                **{field: receipt_document[field] for field in _RECEIPT_FIELDS}
            ),
        )


class SSHExecutionDispatcher:
    """Dispatch an approved plan to the trusted endpoint for its worker identity."""

    def __init__(
        self,
        inventory: SSHRemoteEndpointInventory,
        *,
        limits: SSHTransportLimits | None = None,
        ssh_executable: Path = Path("/usr/bin/ssh"),
    ) -> None:
        self._inventory = inventory
        self._remote = SSHRemoteDispatcher(
            inventory,
            limits=limits,
            ssh_executable=ssh_executable,
        )

    def execute(
        self,
        *,
        approved_worker_identity: str,
        authorization_id: str,
        action_plan: ActionPlan,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 65_536,
        request_id: str | None = None,
    ) -> RemoteAuthorizedRun:
        if not isinstance(approved_worker_identity, str) or not approved_worker_identity:
            raise SSHExecutionError("approved worker identity must be non-empty")
        if not isinstance(authorization_id, str) or not authorization_id:
            raise SSHExecutionError("authorization_id must be non-empty")
        if not isinstance(action_plan, ActionPlan):
            raise SSHExecutionError("action_plan must be an ActionPlan")
        _validate_execution_limits(timeout_seconds, max_output_bytes)
        exchange_id = request_id or str(uuid.uuid4())
        try:
            uuid.UUID(exchange_id)
        except (AttributeError, TypeError, ValueError) as err:
            raise SSHExecutionError("request_id must be a UUID") from err

        endpoint = self._inventory.resolve(approved_worker_identity)
        if not endpoint.attestation_key_id or not endpoint.attestation_key:
            raise SSHExecutionError("trusted endpoint lacks supervisor response attestation configuration")
        exchange_nonce = secrets.token_urlsafe(32)
        action_plan_document = action_plan.to_dict()

        response = self._remote.request(
            approved_worker_identity,
            {
                "schema_version": SSH_EXECUTION_REQUEST_SCHEMA,
                "authorization_id": authorization_id,
                "action_plan": action_plan_document,
                "timeout_seconds": timeout_seconds,
                "max_output_bytes": max_output_bytes,
                "exchange_nonce": exchange_nonce,
            },
            request_id=exchange_id,
        )
        if response.worker_id != approved_worker_identity:
            raise SSHExecutionError("remote response worker identity mismatch")
        if not isinstance(response.payload, Mapping):
            raise SSHExecutionError("remote response payload is invalid")
        try:
            verified_run = verify_attested_authorized_run(
                response.payload,
                attestation_key_id=endpoint.attestation_key_id,
                attestation_key=endpoint.attestation_key,
                request_id=exchange_id,
                exchange_nonce=exchange_nonce,
                host=endpoint.host,
                worker_identity=approved_worker_identity,
                authorization_id=authorization_id,
                action_plan_document=action_plan_document,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        except SupervisorAttestationError as err:
            raise SSHExecutionError("remote supervisor response attestation is invalid") from err
        authorized_run = RemoteAuthorizedRun.from_dict(verified_run)
        validate_remote_authorized_run(
            authorized_run,
            approved_worker_identity=approved_worker_identity,
            authorization_id=authorization_id,
            action_plan=action_plan,
        )
        return authorized_run


def validate_remote_authorized_run(
    authorized_run: RemoteAuthorizedRun,
    *,
    approved_worker_identity: str,
    authorization_id: str,
    action_plan: ActionPlan,
) -> None:
    """Require exact agreement among the request, authority receipt, and result."""
    receipt = authorized_run.approval_receipt
    result = authorized_run.result
    expected_receipt = (
        receipt.authorization_id == authorization_id
        and receipt.action_plan_id == action_plan.plan_id
        and receipt.plan_digest == action_plan.plan_digest
        and receipt.engagement_id == action_plan.engagement_id
        and receipt.worker_identity == approved_worker_identity
        and receipt.target == action_plan.target
    )
    expected_result = (
        result.plan_id == action_plan.plan_id
        and result.engagement_id == action_plan.engagement_id
        and result.worker_identity == approved_worker_identity
    )
    if not expected_receipt or not expected_result:
        raise SSHExecutionError("remote execution result does not match the approved plan and worker")


def _validate_execution_limits(timeout_seconds: float, max_output_bytes: int) -> None:
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise SSHExecutionError("execution timeout must be positive")
    if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or max_output_bytes < 0:
        raise SSHExecutionError("max_output_bytes must be a non-negative integer")


def _receipt_to_dict(receipt: ApprovalConsumptionReceipt) -> dict[str, str]:
    return {field: getattr(receipt, field) for field in _RECEIPT_FIELDS}
