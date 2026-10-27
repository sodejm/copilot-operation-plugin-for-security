from __future__ import annotations

import io
import json
import stat
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops.contracts.models import ActionPlan, CleanupReceipt, RunResult
from cops.evidence.canonical import canonical, decode_json
from cops.execution.control import ApprovalConsumptionReceipt
from cops.execution.ssh_execution import (
    SSH_EXECUTION_REQUEST_SCHEMA,
    RemoteAuthorizedRun,
    SSHExecutionDispatcher,
    SSHExecutionError,
    validate_remote_authorized_run,
)
from cops.execution.ssh_transport import SSH_PROTOCOL, SSHRemoteEndpoint, SSHRemoteResponse
from cops.execution.supervisor_attestation import SupervisorResponseAttestor
from cops.remote_worker import (
    RemoteWorkerRelayConfig,
    _validate_supervisor_socket_metadata,
    handle_remote_execution_request,
    relay_remote_execution_request,
    serve_one_remote_execution_request,
)

FIXTURES = Path("cops/contracts/fixtures")
ATTESTATION_KEY_ID = "supervisor-key-01"
ATTESTATION_KEY = b"k" * 32
EXCHANGE_NONCE = "A" * 43


def _plan() -> ActionPlan:
    return ActionPlan.from_dict(json.loads((FIXTURES / "valid_action_plan.json").read_text(encoding="utf-8")))


def _result(plan: ActionPlan, worker_identity: str = "worker-lab-01") -> RunResult:
    document = json.loads((FIXTURES / "valid_run_result_success.json").read_text(encoding="utf-8"))
    document["plan_id"] = plan.plan_id
    document["engagement_id"] = plan.engagement_id
    document["worker_identity"] = worker_identity
    return RunResult.from_dict(document)


def _receipt(
    plan: ActionPlan,
    worker_identity: str = "worker-lab-01",
    authorization_id: str = "auth-01",
) -> ApprovalConsumptionReceipt:
    return ApprovalConsumptionReceipt(
        authorization_id=authorization_id,
        authorization_digest="a" * 64,
        action_plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity=worker_identity,
        target=plan.target,
    )


def _cleanup_receipt(plan: ActionPlan, result: RunResult) -> CleanupReceipt:
    return CleanupReceipt(
        schema_version="cops.cleanup-receipt/v1",
        receipt_id="cln-ssh-validation-01",
        plan_id=plan.plan_id,
        engagement_id=plan.engagement_id,
        worker_identity=result.worker_identity,
        status=result.cleanup_status,
        created_at=result.finished_at,
        completed_at="2026-10-02T10:05:31Z",
        cleaned_effects=[],
        unresolved_effects=[],
        evidence_hash="0" * 64,
    )


def test_remote_authorized_run_binds_cleanup_receipt_to_result_and_plan() -> None:
    plan = _plan()
    result = _result(plan)
    approval = _receipt(plan)
    cleanup = _cleanup_receipt(plan, result)
    run = RemoteAuthorizedRun(result=result, approval_receipt=approval, cleanup_receipt=cleanup)

    validate_remote_authorized_run(
        run,
        approved_worker_identity=result.worker_identity,
        authorization_id=approval.authorization_id,
        action_plan=plan,
    )

    invalid_receipts = (
        replace(cleanup, plan_id="plan-other"),
        replace(cleanup, engagement_id="eng-other"),
        replace(cleanup, worker_identity="worker-other"),
        replace(cleanup, status="failed"),
        replace(cleanup, completed_at="2026-10-02T10:05:29Z"),
        replace(cleanup, created_at="2026-10-02T10:05:32Z"),
    )
    for invalid in invalid_receipts:
        with pytest.raises(SSHExecutionError, match="cleanup receipt"):
            validate_remote_authorized_run(
                replace(run, cleanup_receipt=invalid),
                approved_worker_identity=result.worker_identity,
                authorization_id=approval.authorization_id,
                action_plan=plan,
            )


class _FakeWorker:
    def __init__(self, *, receipt_worker_identity: str = "worker-lab-01") -> None:
        self.calls: list[dict[str, object]] = []
        self.receipt_worker_identity = receipt_worker_identity

    def execute_plan_with_receipt(
        self,
        action_plan: ActionPlan,
        *,
        authorization_id: str,
        workspace_dir: Path | str | None = None,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 65_536,
    ) -> object:
        self.calls.append(
            {
                "action_plan": action_plan,
                "authorization_id": authorization_id,
                "workspace_dir": workspace_dir,
                "timeout_seconds": timeout_seconds,
                "max_output_bytes": max_output_bytes,
            }
        )
        return SimpleNamespace(
            result=_result(action_plan, self.receipt_worker_identity),
            approval_receipt=_receipt(
                action_plan,
                self.receipt_worker_identity,
                authorization_id,
            ),
            cleanup_receipt=None,
        )


def _envelope(plan: ActionPlan) -> dict[str, object]:
    return {
        "protocol": SSH_PROTOCOL,
        "request_id": str(uuid.uuid4()),
        "expected_host": "worker.example.test",
        "expected_worker_id": "worker-lab-01",
        "payload": {
            "schema_version": SSH_EXECUTION_REQUEST_SCHEMA,
            "authorization_id": "auth-01",
            "action_plan": plan.to_dict(),
            "timeout_seconds": 2.0,
            "max_output_bytes": 1024,
            "exchange_nonce": EXCHANGE_NONCE,
        },
    }


def test_relay_preserves_supervisor_attestation(monkeypatch) -> None:
    from cops import remote_worker

    request = _envelope(_plan())
    signed_payload = {
        "schema_version": "cops.attested-remote-authorized-run/v1",
        "authorized_run": {"opaque": "run"},
        "attestation": {"opaque": "signature"},
    }
    response = {
        "protocol": SSH_PROTOCOL,
        "request_id": request["request_id"],
        "host": "worker.example.test",
        "worker_id": "worker-lab-01",
        "payload": signed_payload,
    }
    raw = json.dumps(response).encode() + b"\n"

    class Socket:
        def __init__(self) -> None:
            self.sent = b""
            self.responses = [raw, b""]

        def settimeout(self, _seconds: float) -> None:
            pass

        def connect(self, _path: str) -> None:
            pass

        def sendall(self, data: bytes) -> None:
            self.sent += data

        def shutdown(self, _how: int) -> None:
            pass

        def recv(self, _count: int) -> bytes:
            return self.responses.pop(0)

        def close(self) -> None:
            pass

    fake_socket = Socket()
    monkeypatch.setattr(remote_worker.socket, "socket", lambda *_args: fake_socket)
    monkeypatch.setattr(remote_worker, "_verify_supervisor_socket", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(remote_worker, "_verify_supervisor_peer", lambda *_args, **_kwargs: None)
    config = RemoteWorkerRelayConfig(
        schema_version=remote_worker.REMOTE_WORKER_RELAY_CONFIG_SCHEMA,
        expected_host="worker.example.test",
        worker_identity="worker-lab-01",
        supervisor_socket_path=Path("/var/lib/cops-supervisor/relay.sock"),
        supervisor_uid=1001,
        supervisor_gid=1001,
        _file_verified=True,
    )

    assert relay_remote_execution_request(request, config=config) == response
    assert json.loads(fake_socket.sent) == request


def test_relay_accepts_provisioned_supervisor_socket_mode() -> None:
    from types import SimpleNamespace

    directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o2710, st_uid=1001, st_gid=1001)
    endpoint = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=1001, st_gid=1001)
    _validate_supervisor_socket_metadata(directory, endpoint, supervisor_uid=1001, supervisor_gid=1001)

    directory.st_mode = stat.S_IFDIR | 0o2770
    with pytest.raises(SSHExecutionError, match="directory permissions"):
        _validate_supervisor_socket_metadata(directory, endpoint, supervisor_uid=1001, supervisor_gid=1001)


def test_receiver_executes_once_and_derives_response_identity_locally() -> None:
    plan = _plan()
    worker = _FakeWorker()

    response = handle_remote_execution_request(
        _envelope(plan),
        expected_host="worker.example.test",
        expected_worker_identity="worker-lab-01",
        worker=worker,
        workspace_dir="workspace",
    )

    assert response["host"] == "worker.example.test"
    assert response["worker_id"] == "worker-lab-01"
    assert len(worker.calls) == 1
    assert worker.calls[0]["authorization_id"] == "auth-01"
    authorized_run = RemoteAuthorizedRun.from_dict(response["payload"])
    assert authorized_run.approval_receipt.worker_identity == "worker-lab-01"
    assert authorized_run.result.plan_id == plan.plan_id


def test_receiver_rejects_endpoint_identity_before_authority_consumption() -> None:
    worker = _FakeWorker()
    envelope = _envelope(_plan())
    envelope["expected_host"] = "substitute.example.test"

    with pytest.raises(SSHExecutionError, match="endpoint identity mismatch"):
        handle_remote_execution_request(
            envelope,
            expected_host="worker.example.test",
            expected_worker_identity="worker-lab-01",
            worker=worker,
        )

    assert worker.calls == []


def test_receiver_rejects_authority_receipt_for_different_worker() -> None:
    worker = _FakeWorker(receipt_worker_identity="substitute-worker")

    with pytest.raises(SSHExecutionError, match="does not match"):
        handle_remote_execution_request(
            _envelope(_plan()),
            expected_host="worker.example.test",
            expected_worker_identity="worker-lab-01",
            worker=worker,
        )

    assert len(worker.calls) == 1


def test_receiver_bounds_request_before_authority_consumption() -> None:
    worker = _FakeWorker()

    with pytest.raises(SSHExecutionError, match="request exceeds"):
        serve_one_remote_execution_request(
            expected_host="worker.example.test",
            expected_worker_identity="worker-lab-01",
            worker=worker,
            input_stream=io.BytesIO(b"x" * 65 + b"\n"),
            output_stream=io.BytesIO(),
            max_request_bytes=64,
        )

    assert worker.calls == []


def test_dispatcher_uses_only_approved_worker_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plan = _plan()
    calls: list[dict[str, object]] = []

    class _FakeRemoteDispatcher:
        def __init__(self, inventory: object, **kwargs: object) -> None:
            calls.append({"inventory": inventory, "options": kwargs})

        def request(
            self,
            worker_id: str,
            payload: dict[str, object],
            *,
            request_id: str,
        ) -> SSHRemoteResponse:
            calls.append({"worker_id": worker_id, "payload": payload, "request_id": request_id})
            run = RemoteAuthorizedRun(
                result=_result(plan, worker_id),
                approval_receipt=_receipt(
                    plan,
                    worker_identity=worker_id,
                    authorization_id=str(payload["authorization_id"]),
                ),
            )
            request_document = {
                "protocol": SSH_PROTOCOL,
                "request_id": request_id,
                "expected_host": "worker.example.test",
                "expected_worker_id": worker_id,
                "payload": payload,
            }
            response_document = {
                "protocol": SSH_PROTOCOL,
                "request_id": request_id,
                "host": "worker.example.test",
                "worker_id": worker_id,
                "payload": run.to_dict(),
            }
            wire = SupervisorResponseAttestor(ATTESTATION_KEY_ID, ATTESTATION_KEY).attest(
                canonical(request_document) + b"\n",
                canonical(response_document) + b"\n",
            )
            signed = decode_json(wire[:-1])
            assert isinstance(signed, dict)
            return SSHRemoteResponse(
                request_id=request_id,
                host="worker.example.test",
                worker_id=worker_id,
                payload=signed["payload"],
            )

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("worker.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n", encoding="ascii")
    known_hosts.chmod(0o600)
    endpoint = SSHRemoteEndpoint(
        host="worker.example.test",
        port=22,
        username="cops-worker",
        worker_id="worker-lab-01",
        known_hosts_path=known_hosts,
        remote_command=("python3", "-m", "cops.remote_worker"),
        attestation_key_id=ATTESTATION_KEY_ID,
        attestation_key=ATTESTATION_KEY,
    )

    class _FakeInventory:
        def resolve(self, worker_id: str) -> object:
            assert worker_id == "worker-lab-01"
            return endpoint

    monkeypatch.setattr(
        "cops.execution.ssh_execution.SSHRemoteDispatcher",
        _FakeRemoteDispatcher,
    )
    dispatcher = SSHExecutionDispatcher(_FakeInventory())  # type: ignore[arg-type]

    authorized_run = dispatcher.execute(
        approved_worker_identity="worker-lab-01",
        authorization_id="auth-01",
        action_plan=plan,
        request_id=str(uuid.uuid4()),
    )

    assert calls[1]["worker_id"] == "worker-lab-01"
    assert calls[1]["payload"]["authorization_id"] == "auth-01"  # type: ignore[index]
    assert authorized_run.approval_receipt.worker_identity == "worker-lab-01"
