"""Offline, test-only signed laboratory observations and remote result fixtures."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cops.contracts.models import ActionPlan, LaboratoryEnvironment, RunResult
from cops.evidence.canonical import canonical, digest, utc_now
from cops.execution.control import ApprovalConsumptionReceipt
from cops.execution.ssh_execution import RemoteAuthorizedRun
from cops.execution.ssh_transport import SSHRemoteEndpointInventory, SSH_ENDPOINT_INVENTORY_SCHEMA
from cops.laboratory.models import LaboratoryObservation
from cops.laboratory.receipts import LaboratoryCaseObservation, LaboratoryObservationTrustStore, LaboratoryResetReceipt

_TEST_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
_TEST_KEY_ID = "lab-observer-key-01"


def observation_trust_store(root: Path, worker_identity: str = "lab-operator") -> LaboratoryObservationTrustStore:
    """Load only the test signer's public key into the controller trust store."""
    root.mkdir(parents=True, exist_ok=True)
    path = root / "lab-observation-trust.json"
    path.write_text(json.dumps({
        "schema_version": "cops.laboratory-observation-trust-store/v1",
        "keys": [{
            "worker_identity": worker_identity,
            "key_id": _TEST_KEY_ID,
            "algorithm": "ed25519",
            "public_key_hex": _TEST_SIGNER.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex(),
        }],
    }), encoding="utf-8")
    path.chmod(0o600)
    return LaboratoryObservationTrustStore.from_file(path)


def endpoint_inventory(root: Path, worker_identity: str = "lab-operator") -> SSHRemoteEndpointInventory:
    """Load a protected, pinned SSH endpoint inventory with a test-only key."""
    root.mkdir(parents=True, exist_ok=True)
    known_hosts = root / "known_hosts"
    known_hosts.write_text("worker.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n", encoding="ascii")
    known_hosts.chmod(0o600)
    key = root / "supervisor-attestation.key"
    key.write_text("11" * 32, encoding="ascii")
    key.chmod(0o600)
    path = root / "ssh-endpoints.json"
    path.write_text(json.dumps({
        "schema_version": SSH_ENDPOINT_INVENTORY_SCHEMA,
        "workers": [{
            "host": "worker.example.test",
            "attestation_key_id": "supervisor-key-01",
            "attestation_key_path": str(key),
            "known_hosts_path": str(known_hosts),
            "port": 22,
            "remote_command": ["python3", "-m", "cops.remote_worker"],
            "username": "cops-worker",
            "worker_id": worker_identity,
        }],
    }), encoding="utf-8")
    path.chmod(0o600)
    return SSHRemoteEndpointInventory.from_file(path)


def sign_receipt(receipt, inventory: SSHRemoteEndpointInventory):
    """Produce a test-only operator signature independent of SSH dispatch."""
    inventory.resolve(receipt.worker_identity)
    return replace(receipt, signature=_TEST_SIGNER.sign(canonical(receipt.unsigned())).hex())


def environment_observation(
    environment: LaboratoryEnvironment,
    nonce: str,
    inventory: SSHRemoteEndpointInventory,
    **overrides,
) -> LaboratoryObservation:
    receipt = LaboratoryObservation(
        environment_id=environment.environment_id,
        worker_identity=environment.owner,
        request_nonce=nonce,
        isolation_type=environment.isolation["isolation_type"],
        network_isolated=True,
        egress_restricted=True,
        canary_digest=hashlib.sha256(environment.canary["canary_token"].encode()).hexdigest(),
        baseline_digest=environment.reset_configuration["expected_baseline_digest"],
        observed_at=utc_now(),
        key_id=_TEST_KEY_ID,
        signature="0" * 128,
    )
    return sign_receipt(replace(receipt, **overrides), inventory)


def reset_receipt(
    environment: LaboratoryEnvironment,
    nonce: str,
    inventory: SSHRemoteEndpointInventory,
    **overrides,
) -> LaboratoryResetReceipt:
    receipt = LaboratoryResetReceipt(
        environment_id=environment.environment_id,
        worker_identity=environment.owner,
        strategy=environment.reset_configuration["strategy"],
        command_digest=hashlib.sha256(environment.reset_configuration["command"].encode()).hexdigest(),
        request_nonce=nonce,
        completed_at=utc_now(),
        succeeded=True,
        key_id=_TEST_KEY_ID,
        signature="0" * 128,
    )
    return sign_receipt(replace(receipt, **overrides), inventory)


def remote_run(plan: ActionPlan, authorization_id: str, worker_identity: str, *, status: str = "success", exit_code: int = 0, cleanup_status: str = "completed") -> RemoteAuthorizedRun:
    started = datetime.now(UTC) - timedelta(seconds=2)
    finished = started + timedelta(seconds=1)
    result = RunResult(
        schema_version="cops.run-result/v1",
        result_id=str(uuid.uuid4()),
        plan_id=plan.plan_id,
        engagement_id=plan.engagement_id,
        status=status,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        status_details={},
        evidence_records=[],
        artifacts=[],
        cleanup_status=cleanup_status,
        worker_identity=worker_identity,
        exit_code=exit_code,
    )
    receipt = ApprovalConsumptionReceipt(
        authorization_id=authorization_id,
        authorization_digest=digest({"test_authorization_id": authorization_id}),
        action_plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity=worker_identity,
        target=plan.target,
    )
    return RemoteAuthorizedRun(result=result, approval_receipt=receipt)


def case_observation(
    environment: LaboratoryEnvironment,
    plan: ActionPlan,
    authorization_id: str,
    run: RemoteAuthorizedRun,
    inventory: SSHRemoteEndpointInventory,
    *,
    request_nonce: str,
    canary_token_detected: bool,
    control_blocked: bool,
    **overrides,
) -> LaboratoryCaseObservation:
    receipt = LaboratoryCaseObservation(
        environment_id=environment.environment_id,
        worker_identity=environment.owner,
        authorization_id=authorization_id,
        plan_digest=plan.plan_digest,
        result_id=run.result.result_id,
        result_finished_at=run.result.finished_at,
        request_nonce=request_nonce,
        observed_at=utc_now(),
        canary_token_detected=canary_token_detected,
        control_blocked=control_blocked,
        key_id=_TEST_KEY_ID,
        signature="0" * 128,
    )
    return sign_receipt(replace(receipt, **overrides), inventory)
