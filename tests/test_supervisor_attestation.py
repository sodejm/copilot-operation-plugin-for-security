"""Security tests for supervisor-authenticated remote execution responses."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from cops.evidence.canonical import canonical, decode_json
from cops.execution.supervisor_attestation import (
    SSH_PROTOCOL,
    SupervisorAttestationError,
    SupervisorResponseAttestor,
    load_attestation_key,
    verify_attested_authorized_run,
)

KEY_ID = "supervisor-key-01"
KEY = b"k" * 32
NONCE = "A" * 43


def _request(*, request_id: str = "request-01", nonce: str = NONCE) -> dict[str, object]:
    return {
        "protocol": SSH_PROTOCOL,
        "request_id": request_id,
        "expected_host": "worker.example.test",
        "expected_worker_id": "worker-lab-01",
        "payload": {
            "schema_version": "cops.remote-execution-request/v1",
            "authorization_id": "auth-01",
            "action_plan": {
                "plan_id": "plan-01",
                "plan_digest": "a" * 64,
                "engagement_id": "engagement-01",
                "target": "192.0.2.10",
            },
            "timeout_seconds": 30.0,
            "max_output_bytes": 65_536,
            "exchange_nonce": nonce,
        },
    }


def _authorized_run() -> dict[str, object]:
    return {
        "schema_version": "cops.remote-authorized-run/v1",
        "result": {"status": "succeeded", "exit_code": 0},
        "approval_receipt": {
            "authorization_id": "auth-01",
            "authorization_digest": "b" * 64,
            "worker_identity": "worker-lab-01",
        },
    }


def _signed_payload(
    *, request_id: str = "request-01", nonce: str = NONCE, key_id: str = KEY_ID, key: bytes = KEY
) -> dict[str, object]:
    request = _request(request_id=request_id, nonce=nonce)
    response = {
        "protocol": SSH_PROTOCOL,
        "request_id": request_id,
        "host": "worker.example.test",
        "worker_id": "worker-lab-01",
        "payload": _authorized_run(),
    }
    wire = SupervisorResponseAttestor(key_id, key).attest(canonical(request) + b"\n", canonical(response) + b"\n")
    document = decode_json(wire[:-1])
    assert isinstance(document, dict)
    payload = document["payload"]
    assert isinstance(payload, dict)
    return payload


def _verify(
    payload: dict[str, object],
    *,
    request_id: str = "request-01",
    nonce: str = NONCE,
    key_id: str = KEY_ID,
    key: bytes = KEY,
) -> object:
    request_payload = _request(request_id=request_id, nonce=nonce)["payload"]
    assert isinstance(request_payload, dict)
    action_plan = request_payload["action_plan"]
    assert isinstance(action_plan, dict)
    return verify_attested_authorized_run(
        payload,
        attestation_key_id=key_id,
        attestation_key=key,
        request_id=request_id,
        exchange_nonce=nonce,
        host="worker.example.test",
        worker_identity="worker-lab-01",
        authorization_id="auth-01",
        action_plan_document=action_plan,
        timeout_seconds=30.0,
        max_output_bytes=65_536,
    )


def test_valid_supervisor_attestation_returns_exact_authorized_run() -> None:
    payload = _signed_payload()

    assert _verify(payload) == payload["authorized_run"]


@pytest.mark.parametrize("field", ["result", "approval_receipt"])
def test_altered_authorized_run_is_rejected(field: str) -> None:
    payload = _signed_payload()
    altered = copy.deepcopy(payload)
    run = altered["authorized_run"]
    assert isinstance(run, dict)
    nested = run[field]
    assert isinstance(nested, dict)
    nested["tampered"] = True

    with pytest.raises(SupervisorAttestationError, match="binding mismatch"):
        _verify(altered)


def test_nonce_replay_and_cross_request_binding_are_rejected() -> None:
    payload = _signed_payload()

    with pytest.raises(SupervisorAttestationError, match="binding mismatch"):
        _verify(payload, nonce="B" * 43)
    with pytest.raises(SupervisorAttestationError, match="binding mismatch"):
        _verify(payload, request_id="request-02")


def test_missing_wrong_key_id_and_wrong_key_are_rejected() -> None:
    payload = _signed_payload()
    missing = copy.deepcopy(payload)
    attestation = missing["attestation"]
    assert isinstance(attestation, dict)
    del attestation["key_id"]

    with pytest.raises(SupervisorAttestationError, match="fields are invalid"):
        _verify(missing)
    with pytest.raises(SupervisorAttestationError, match="key ID mismatch"):
        _verify(payload, key_id="different-key")
    with pytest.raises(SupervisorAttestationError, match="verification failed"):
        _verify(payload, key=b"z" * 32)


def test_attestation_key_requires_owner_only_regular_file(tmp_path: Path) -> None:
    key_path = tmp_path / "attestation.key"
    key_path.write_text("11" * 32, encoding="ascii")
    key_path.chmod(0o600)

    assert load_attestation_key(key_path) == bytes.fromhex("11" * 32)

    key_path.chmod(0o640)
    with pytest.raises(SupervisorAttestationError, match="not protected"):
        load_attestation_key(key_path)


def test_attestation_key_rejects_symlink(tmp_path: Path) -> None:
    actual = tmp_path / "actual.key"
    actual.write_text("11" * 32, encoding="ascii")
    actual.chmod(0o600)
    link = tmp_path / "attestation.key"
    link.symlink_to(actual)

    with pytest.raises(SupervisorAttestationError, match="unavailable"):
        load_attestation_key(link)
