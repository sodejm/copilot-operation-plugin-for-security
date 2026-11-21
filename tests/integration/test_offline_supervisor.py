"""Real sandbox execution through the built receiver, with in-process test approval.

This is not an installed SSH or cross-administrator observer acceptance test.
"""

import hashlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

from cops.evidence.canonical import digest, utc_now
from cops.execution.filesystem import open_directory_no_symlinks
from cops.execution.sandbox import LinuxBubblewrapSandbox
from cops.remote_worker import SSH_EXECUTION_REQUEST_SCHEMA, SSH_PROTOCOL
from tests.auth_testkit import worker_inventory_for_plan
from tests.test_offline_research import WORKER_ID, _plan, _profile
from tests.test_worker_supervisor import _test_receiver

pytestmark = [
    pytest.mark.linux_bubblewrap,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires real Linux bubblewrap isolation"),
]


def test_offline_receiver_executes_pinned_corpus_and_cleans_workspace(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    content = b"synthetic offline supervisor corpus\n"
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
    profile["cat_executable_sha256"] = hashlib.sha256(Path("/usr/bin/cat").read_bytes()).hexdigest()
    operation = {
        "step_id": "step-1", "tool": "cat", "tool_version": "coreutils-9.4",
        "action": "read_local_corpus", "arguments": {"filename": "corpus-sample"}, "timeout_seconds": 10,
    }
    plan = _plan(profile, operations=[operation])
    inventory = worker_inventory_for_plan(plan, worker_identity=WORKER_ID)
    profile["worker_inventory_sha256"] = digest(inventory.to_dict())
    plan = _plan(profile, operations=[operation])
    context = _test_receiver(tmp_path, monkeypatch, plan=plan, inventory=inventory)
    worker = context.receiver.worker
    run = LinuxBubblewrapSandbox.run
    observed_outputs = []
    workspaces = set()

    def record_execution(sandbox, *args, **kwargs):
        workspaces.add(kwargs["cwd"])
        result = run(sandbox, *args, **kwargs)
        observed_outputs.append(result.stdout)
        return result

    monkeypatch.setattr(LinuxBubblewrapSandbox, "run", record_execution)
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
    output = io.BytesIO()
    context.receiver.serve_one(io.BytesIO(json.dumps(request).encode() + b"\n"), output)
    response = json.loads(output.getvalue())
    result = response["payload"]["result"]
    assert response["request_id"] == request["request_id"]
    assert result["status"] == "success"
    assert result["cleanup_status"] == "completed"
    assert content in observed_outputs
    assert workspaces and all(not workspace.exists() for workspace in workspaces)
    assert context.store.get_authorization(context.authorization.authorization_id).status == "consumed"
    assert len(context.control.consume_calls) == 1
    assert response["payload"]["approval_receipt"]["plan_digest"] == plan.plan_digest
    evidence = result["offline_research"]
    assert evidence["corpora"] == [{"name": "sample", "sha256": hashlib.sha256(content).hexdigest()}]
    assert evidence["approved_isolation_attestation"] == observation["digest"]
    assert evidence["isolation_invocations"]
    assert all(item["matches_approved"] for item in evidence["isolation_invocations"])
    assert worker.last_cleanup_receipt.unresolved_effects == []
