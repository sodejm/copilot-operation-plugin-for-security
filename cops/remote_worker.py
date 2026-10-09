"""Remote execution receiver for a persistent, authority-connected worker."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from cops.contracts.models import ActionPlan, RunResult
from cops.execution.control import ApprovalConsumptionReceipt
from cops.execution.ssh_execution import (
    SSH_EXECUTION_REQUEST_SCHEMA,
    RemoteAuthorizedRun,
    SSHExecutionError,
    _validate_execution_limits,
    validate_remote_authorized_run,
)
from cops.execution.ssh_transport import SSH_PROTOCOL
from cops.execution.supervisor_attestation import (
    SupervisorAttestationError,
    validate_exchange_nonce,
)


class AuthorizedRunLike(Protocol):
    result: RunResult
    approval_receipt: ApprovalConsumptionReceipt


class ReceiptExecutingWorker(Protocol):
    def execute_plan_with_receipt(
        self,
        action_plan: ActionPlan,
        *,
        authorization_id: str,
        workspace_dir: Path | str | None = None,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 65_536,
    ) -> AuthorizedRunLike: ...


@dataclass(frozen=True)
class SSHRemoteExecutionReceiver:
    """Serve SSH relays using one persistent worker and approval-control client."""

    expected_host: str
    expected_worker_identity: str
    worker: ReceiptExecutingWorker
    workspace_dir: Path | str | None = None
    max_request_bytes: int = 64 * 1024
    max_response_bytes: int = 1024 * 1024

    def serve_one(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        serve_one_remote_execution_request(
            expected_host=self.expected_host,
            expected_worker_identity=self.expected_worker_identity,
            worker=self.worker,
            input_stream=input_stream,
            output_stream=output_stream,
            workspace_dir=self.workspace_dir,
            max_request_bytes=self.max_request_bytes,
            max_response_bytes=self.max_response_bytes,
        )


def handle_remote_execution_request(
    document: dict[str, Any],
    *,
    expected_host: str,
    expected_worker_identity: str,
    worker: ReceiptExecutingWorker,
    workspace_dir: Path | str | None = None,
) -> dict[str, Any]:
    expected_fields = {"expected_host", "expected_worker_id", "payload", "protocol", "request_id"}
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise SSHExecutionError("remote execution envelope fields do not match the required schema")
    if document["protocol"] != SSH_PROTOCOL:
        raise SSHExecutionError("unsupported remote execution transport protocol")
    if document["expected_host"] != expected_host or document["expected_worker_id"] != expected_worker_identity:
        raise SSHExecutionError("remote execution endpoint identity mismatch")
    if not isinstance(document["request_id"], str) or not document["request_id"]:
        raise SSHExecutionError("remote execution request_id is invalid")
    payload = document["payload"]
    payload_fields = {
        "schema_version",
        "authorization_id",
        "action_plan",
        "timeout_seconds",
        "max_output_bytes",
        "exchange_nonce",
    }
    if not isinstance(payload, dict) or set(payload) != payload_fields:
        raise SSHExecutionError("remote execution request fields do not match the required schema")
    if payload["schema_version"] != SSH_EXECUTION_REQUEST_SCHEMA:
        raise SSHExecutionError("unsupported remote execution request schema version")
    try:
        validate_exchange_nonce(payload["exchange_nonce"])
    except SupervisorAttestationError as err:
        raise SSHExecutionError("remote execution exchange nonce is invalid") from err
    authorization_id = payload["authorization_id"]
    if not isinstance(authorization_id, str) or not authorization_id:
        raise SSHExecutionError("remote execution authorization_id is invalid")
    timeout_seconds = payload["timeout_seconds"]
    max_output_bytes = payload["max_output_bytes"]
    _validate_execution_limits(timeout_seconds, max_output_bytes)
    if not isinstance(payload["action_plan"], dict):
        raise SSHExecutionError("remote execution action plan is invalid")
    try:
        action_plan = ActionPlan.from_dict(payload["action_plan"])
    except Exception as err:
        raise SSHExecutionError("remote execution action plan is invalid") from err

    executed = worker.execute_plan_with_receipt(
        action_plan,
        authorization_id=authorization_id,
        workspace_dir=workspace_dir,
        timeout_seconds=float(timeout_seconds),
        max_output_bytes=max_output_bytes,
    )
    authorized_run = RemoteAuthorizedRun(
        result=executed.result,
        approval_receipt=executed.approval_receipt,
    )
    validate_remote_authorized_run(
        authorized_run,
        approved_worker_identity=expected_worker_identity,
        authorization_id=authorization_id,
        action_plan=action_plan,
    )
    return {
        "protocol": SSH_PROTOCOL,
        "request_id": document["request_id"],
        "host": expected_host,
        "worker_id": expected_worker_identity,
        "payload": authorized_run.to_dict(),
    }


def serve_one_remote_execution_request(
    *,
    expected_host: str,
    expected_worker_identity: str,
    worker: ReceiptExecutingWorker,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    workspace_dir: Path | str | None = None,
    max_request_bytes: int = 64 * 1024,
    max_response_bytes: int = 1024 * 1024,
) -> None:
    if max_request_bytes < 1 or max_response_bytes < 1:
        raise SSHExecutionError("remote execution byte limits must be positive")
    raw = input_stream.readline(max_request_bytes + 1)
    if len(raw) > max_request_bytes:
        raise SSHExecutionError("remote execution request exceeds the byte limit")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SSHExecutionError("remote execution requires one newline-delimited JSON document")
    try:
        document = json.loads(raw[:-1], object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise SSHExecutionError("remote execution request is not valid UTF-8 JSON") from err
    if not isinstance(document, dict):
        raise SSHExecutionError("remote execution request must be a JSON object")
    response = handle_remote_execution_request(
        document,
        expected_host=expected_host,
        expected_worker_identity=expected_worker_identity,
        worker=worker,
        workspace_dir=workspace_dir,
    )
    encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > max_response_bytes:
        raise SSHExecutionError("remote execution response exceeds the byte limit")
    output_stream.write(encoded)
    output_stream.flush()


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise SSHExecutionError("remote execution request contains a duplicate field")
        document[key] = value
    return document
