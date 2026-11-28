from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops.execution.ssh_transport import (
    SSH_ENDPOINT_INVENTORY_SCHEMA,
    SSHRemoteDispatcher,
    SSHRemoteEndpoint,
    SSHRemoteEndpointInventory,
    SSHTransportError,
)
from tests.ssh_transport_testkit import make_fake_ssh


def _inventory_document(known_hosts: Path, *, worker_id: str = "worker-lab-01") -> dict[str, object]:
    attestation_key = known_hosts.parent / "supervisor-attestation.key"
    attestation_key.write_text("11" * 32, encoding="ascii")
    attestation_key.chmod(0o600)
    return {
        "schema_version": SSH_ENDPOINT_INVENTORY_SCHEMA,
        "workers": [
            {
                "host": "worker.example.test",
                "attestation_key_id": "supervisor-key-01",
                "attestation_key_path": str(attestation_key),
                "known_hosts_path": str(known_hosts),
                "port": 22,
                "remote_command": ["python3", "-m", "cops.remote_worker"],
                "username": "cops-worker",
                "worker_id": worker_id,
            }
        ],
    }


def _write_inventory(path: Path, document: object, *, mode: int = 0o600) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(mode)


def _trusted_dispatcher(root: Path) -> tuple[SSHRemoteDispatcher, Path]:
    executable, marker = make_fake_ssh(root)
    known_hosts = root / "known_hosts"
    known_hosts.write_text("worker.example.test ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n", encoding="ascii")
    known_hosts.chmod(0o600)
    inventory_path = root / "ssh-endpoints.json"
    _write_inventory(inventory_path, _inventory_document(known_hosts))
    inventory = SSHRemoteEndpointInventory.from_file(inventory_path)
    return SSHRemoteDispatcher(inventory, ssh_executable=executable), marker


def test_dispatcher_resolves_endpoint_from_protected_inventory(tmp_path: Path) -> None:
    dispatcher, marker = _trusted_dispatcher(tmp_path)

    response = dispatcher.request(
        "worker-lab-01",
        {
            "host": "substitute.example.test",
            "known_hosts_path": "substitute",
            "remote_command": ["substitute"],
            "username": "substitute",
            "worker_id": "worker-substituted",
        },
        request_id="request-inventory",
    )

    assert marker.read_text(encoding="utf-8") == "invoked"
    assert response.host == "worker.example.test"
    assert response.worker_id == "worker-lab-01"
    assert response.payload["argv"][-2:] == ["worker.example.test", "python3 -m cops.remote_worker"]
    assert response.payload["request"]["payload"] == {
        "host": "substitute.example.test",
        "known_hosts_path": "substitute",
        "remote_command": ["substitute"],
        "username": "substitute",
        "worker_id": "worker-substituted",
    }


def test_dispatcher_rejects_missing_worker_before_launch(tmp_path: Path) -> None:
    dispatcher, marker = _trusted_dispatcher(tmp_path)

    with pytest.raises(SSHTransportError, match="not present in the trusted inventory"):
        dispatcher.request("worker-missing", {}, request_id="request-missing")

    assert not marker.exists()


def test_dispatcher_rejects_directly_constructed_inventory_before_launch(tmp_path: Path) -> None:
    executable, marker = make_fake_ssh(tmp_path)
    endpoint = SSHRemoteEndpoint(
        host="worker.example.test",
        port=22,
        username="cops-worker",
        worker_id="worker-lab-01",
        known_hosts_path=tmp_path / "known_hosts",
        remote_command=("python3", "-m", "cops.remote_worker"),
    )
    inventory = SSHRemoteEndpointInventory(
        schema_version=SSH_ENDPOINT_INVENTORY_SCHEMA,
        endpoints={"worker-lab-01": endpoint},
    )

    with pytest.raises(SSHTransportError, match="verified owner-provisioned"):
        SSHRemoteDispatcher(inventory, ssh_executable=executable)

    assert not marker.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate-worker", "duplicate worker identity"),
        ("relative-pin", "invalid worker endpoint"),
        ("unknown-field", "fields do not match"),
    ],
)
def test_inventory_rejects_ambiguous_endpoint_configuration(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    document = _inventory_document(known_hosts)
    workers = document["workers"]
    assert isinstance(workers, list)
    entry = workers[0]
    assert isinstance(entry, dict)
    if mutation == "duplicate-worker":
        workers.append(dict(entry))
    elif mutation == "relative-pin":
        entry["known_hosts_path"] = "known_hosts"
    else:
        entry["unexpected"] = True
    inventory_path = tmp_path / "ssh-endpoints.json"
    _write_inventory(inventory_path, document)

    with pytest.raises(SSHTransportError, match=message):
        SSHRemoteEndpointInventory.from_file(inventory_path)


def test_inventory_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    inventory_path = tmp_path / "ssh-endpoints.json"
    inventory_path.write_text(
        '{"schema_version":"cops.ssh-remote-endpoint-inventory/v1",'
        '"schema_version":"cops.ssh-remote-endpoint-inventory/v1","workers":[]}',
        encoding="utf-8",
    )
    inventory_path.chmod(0o600)

    with pytest.raises(SSHTransportError, match="not valid JSON"):
        SSHRemoteEndpointInventory.from_file(inventory_path)


def test_inventory_rejects_group_readable_file(tmp_path: Path) -> None:
    inventory_path = tmp_path / "ssh-endpoints.json"
    _write_inventory(inventory_path, _inventory_document(tmp_path / "known_hosts"), mode=0o640)

    with pytest.raises(SSHTransportError, match="owner-only regular file"):
        SSHRemoteEndpointInventory.from_file(inventory_path)


def test_inventory_rejects_symlinked_file(tmp_path: Path) -> None:
    actual_inventory = tmp_path / "actual-ssh-endpoints.json"
    _write_inventory(actual_inventory, _inventory_document(tmp_path / "known_hosts"))
    inventory_path = tmp_path / "ssh-endpoints.json"
    inventory_path.symlink_to(actual_inventory)

    with pytest.raises(SSHTransportError, match="cannot be opened securely"):
        SSHRemoteEndpointInventory.from_file(inventory_path)
