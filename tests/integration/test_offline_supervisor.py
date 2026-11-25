"""Real sandbox execution through the supervisor connection with test approval."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from cops.evidence.canonical import digest, utc_now
from cops.execution.filesystem import open_directory_no_symlinks
from cops.execution.sandbox import LinuxBubblewrapSandbox
from cops.execution.ssh_execution import RemoteAuthorizedRun, validate_remote_authorized_run
from cops.execution.supervisor_attestation import SupervisorResponseAttestor, verify_attested_authorized_run
from cops.remote_worker import SSH_EXECUTION_REQUEST_SCHEMA, SSH_PROTOCOL
from cops.worker_supervisor import serve_connection
from tests.auth_testkit import worker_inventory_for_plan
from tests.test_offline_research import WORKER_ID, _plan, _profile
from tests.test_worker_supervisor import _test_receiver

pytestmark = [
    pytest.mark.linux_bubblewrap,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires real Linux bubblewrap isolation"),
]


def test_offline_receiver_executes_pinned_corpus_and_cleans_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("LC_ALL", "C")
    cat = shutil.which("cat")
    if cat is None:
        pytest.skip("requires GNU coreutils cat 9.4 on /usr/bin:/bin")
    version = subprocess.run([cat, "--version"], capture_output=True, check=False, text=True, timeout=5)
    if version.returncode or version.stdout.splitlines()[:1] != ["cat (GNU coreutils) 9.4"]:
        pytest.skip("requires GNU coreutils cat 9.4 on /usr/bin:/bin")

    source = tmp_path / "source.txt"
    content = b"synthetic offline supervisor corpus\npassword=synthetic-fixture-value\n"
    redacted_content = b"synthetic offline supervisor corpus\npassword=[REDACTED:CREDENTIAL]\n"
    source.write_bytes(content)
    observation_workspace = tmp_path / "observation"
    observation_workspace.mkdir(mode=0o700)
    descriptor = open_directory_no_symlinks(observation_workspace)
    try:
        observation = LinuxBubblewrapSandbox().observe_offline_isolation(
            cwd=observation_workspace, expected_workspace_fd=descriptor
        )
    finally:
        os.close(descriptor)
    profile = _profile(source)
    profile["isolation_attestation"] = {"digest": observation["digest"], "observed_at": utc_now()}
    profile["cat_executable_sha256"] = hashlib.sha256(Path(cat).read_bytes()).hexdigest()
    operation = {
        "step_id": "step-1", "tool": "cat", "tool_version": "coreutils-9.4",
        "action": "read_local_corpus", "arguments": {"filename": "corpus-sample"}, "timeout_seconds": 10,
    }
    plan = _plan(profile, operations=[operation])
    inventory = worker_inventory_for_plan(plan, worker_identity=WORKER_ID)
    profile["worker_inventory_sha256"] = digest(inventory.to_dict())
    plan = _plan(profile, operations=[operation])
    context = _test_receiver(tmp_path, monkeypatch, plan=plan, inventory=inventory)
    request = {
        "protocol": SSH_PROTOCOL, "request_id": "offline-supervisor-test",
        "expected_host": context.config.expected_host, "expected_worker_id": WORKER_ID,
        "payload": {
            "schema_version": SSH_EXECUTION_REQUEST_SCHEMA,
            "authorization_id": context.authorization.authorization_id,
            "action_plan": plan.to_dict(), "timeout_seconds": 30, "max_output_bytes": 4096,
            "exchange_nonce": "a" * 43,
        },
    }
    config = replace(context.config, relay_uid=os.geteuid(), relay_gid=os.getegid())
    key = b"k" * 32
    attestor = SupervisorResponseAttestor(config.attestation_key_id, key)
    server, client = socket.socketpair()
    with server, client:
        client.sendall(json.dumps(request).encode() + b"\n")
        client.shutdown(socket.SHUT_WR)
        serve_connection(server, config, context.receiver, attestor)
        with client.makefile("rb") as stream:
            response = json.loads(stream.readline())
    assert response["request_id"] == request["request_id"]
    verified = verify_attested_authorized_run(
        response["payload"],
        attestation_key_id=config.attestation_key_id,
        attestation_key=key,
        request_id=request["request_id"],
        exchange_nonce=request["payload"]["exchange_nonce"],
        host=config.expected_host,
        worker_identity=WORKER_ID,
        authorization_id=context.authorization.authorization_id,
        action_plan_document=plan.to_dict(),
        timeout_seconds=30,
        max_output_bytes=4096,
    )
    run = RemoteAuthorizedRun.from_dict(verified)
    validate_remote_authorized_run(
        run, approved_worker_identity=WORKER_ID,
        authorization_id=context.authorization.authorization_id, action_plan=plan,
    )
    result = run.result.to_dict()
    assert result["status"] == "success"
    assert result["cleanup_status"] == "completed"
    assert run.cleanup_receipt is not None
    assert not run.cleanup_receipt.unresolved_effects
    workspace = next(
        Path(effect["target"]) for effect in run.cleanup_receipt.cleaned_effects
        if effect["resource_type"] == "directory" and Path(effect["target"]).name.startswith("cops-worker-")
    )
    assert not workspace.exists()
    assert run.redacted_artifacts is not None
    paths = {item["path"] for item in result["artifacts"]}
    (output,) = (path for path in paths if path.endswith("_output.txt"))
    (envelope_path,) = (path for path in paths if path.endswith("_evidence.json"))
    assert run.redacted_artifacts[output] == redacted_content
    envelope = json.loads(run.redacted_artifacts[envelope_path])
    assert digest(envelope) in result["evidence_records"]
    assert envelope["payload"]["provenance"]["plan_digest"] == plan.plan_digest
    output_sha256 = hashlib.sha256(redacted_content).hexdigest()
    assert envelope["payload"]["result"]["artifact_sha256"] == output_sha256
    assert envelope["payload"]["streams"]["stdout"] == {
        "sha256": output_sha256, "size_bytes": len(redacted_content),
    }
    assert b"synthetic-fixture-value" not in run.redacted_artifacts[envelope_path]
    assert context.store.get_authorization(context.authorization.authorization_id).status == "consumed"
    assert len(context.control.consume_calls) == 1
    assert run.approval_receipt.plan_digest == plan.plan_digest
    evidence = result["offline_research"]
    assert evidence["corpora"] == [{"name": "sample", "sha256": hashlib.sha256(content).hexdigest()}]
    assert evidence["approved_isolation_attestation"] == observation["digest"]
    assert evidence["isolation_invocations"]
    assert all(item["matches_approved"] for item in evidence["isolation_invocations"])
