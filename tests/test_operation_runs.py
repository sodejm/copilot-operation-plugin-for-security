from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from cops.operations.contracts import OperationError
from cops.operations.runs import RunStore
from cops.operations.service import OperationService

pytestmark = pytest.mark.skipif(os.name != "posix", reason="private durable state requires POSIX")


def request(task="sample"):
    return {
        "schema_version": "cops.operation-request/v1",
        "operation_id": "cops.work.request",
        "arguments": {"task": task},
    }


def call(service, operation, arguments):
    return service.invoke(
        {"schema_version": "cops.operation-request/v1", "operation_id": operation, "arguments": arguments}
    )


def test_idempotent_acceptance_and_restart(tmp_path):
    store = RunStore(tmp_path / "private")
    service = OperationService(run_store=store)
    accepted = call(service, "cops.run.create", {"request": request(), "idempotency_key": "same"})
    run_id = accepted["result"]["run_id"]
    assert accepted["result"]["state"] == "queued"
    assert call(service, "cops.run.create", {"request": request(), "idempotency_key": "same"}) == accepted
    correlated = dict(request(), request_id="new-transport-correlation")
    assert call(service, "cops.run.create", {"request": correlated, "idempotency_key": "same"}) == accepted
    conflict = call(service, "cops.run.create", {"request": request("changed"), "idempotency_key": "same"})
    assert conflict["error"]["code"] == "idempotency_conflict"
    resumed = call(service, "cops.run.resume", {"run_id": run_id})
    assert resumed["result"]["state"] == "succeeded"
    reopened = OperationService(run_store=RunStore(tmp_path / "private"))
    assert call(reopened, "cops.run.resume", {"run_id": run_id})["result"] == resumed["result"]


def test_concurrent_claim_and_cancellation(tmp_path, monkeypatch):
    entered, release = Event(), Event()
    service = OperationService(run_store=RunStore(tmp_path / "private"))
    run_id = call(service, "cops.run.create", {"request": request()})["result"]["run_id"]
    original = service._dispatch

    def blocked(*args):
        entered.set()
        assert release.wait(10)
        return original(*args)

    monkeypatch.setattr(service, "_dispatch", blocked)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(call, service, "cops.run.resume", {"run_id": run_id})
        assert entered.wait(10)
        other = OperationService(run_store=RunStore(tmp_path / "private"))
        competing = call(other, "cops.run.resume", {"run_id": run_id})
        assert competing["error"]["code"] == "run_busy"
        cancelled = call(service, "cops.run.cancel", {"run_id": run_id})
        assert cancelled["result"]["cancellation_requested"] is True
        release.set()
        result = future.result(timeout=10)
    assert result["result"]["state"] == "cancelled"
    assert result["result"]["operation_result"] is None
    assert result["result"]["evidence_refs"] == []


def test_pure_crash_recovery_uses_fenced_attempt(tmp_path):
    clock = [100.0]
    store = RunStore(tmp_path / "private", clock=lambda: clock[0], lease_seconds=10)
    service = OperationService(run_store=store)
    run_id = call(service, "cops.run.create", {"request": request()})["result"]["run_id"]
    claimed = store.claim(run_id)
    with pytest.raises(OperationError, match="run_busy"):
        store.recover(run_id)
    clock[0] = 111
    assert store.recover(run_id)["state"] == "queued"
    with pytest.raises(OperationError, match="stale_attempt"):
        store.finish(run_id, claimed["lease_token"], "succeeded", {"old": True})
    assert call(service, "cops.run.resume", {"run_id": run_id})["result"]["state"] == "succeeded"


@pytest.mark.parametrize("entry", ["recover", "resume", "claim"])
def test_cancelled_pure_lease_expiry_never_redispatches(tmp_path, monkeypatch, entry):
    clock = [100.0]
    store = RunStore(tmp_path / "private", clock=lambda: clock[0], lease_seconds=10)
    service = OperationService(run_store=store)
    run_id = call(service, "cops.run.create", {"request": request()})["result"]["run_id"]
    attempt = store.claim(run_id)
    assert store.cancel(run_id)["state"] == "running"
    clock[0] = 111
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("cancelled expired work called its handler")

    monkeypatch.setattr(service, "_dispatch", forbidden)
    if entry == "claim":
        with pytest.raises(OperationError, match="run_terminal"):
            store.claim(run_id)
    else:
        assert call(service, "cops.run." + entry, {"run_id": run_id})["result"]["state"] == "cancelled"
    reopened = RunStore(tmp_path / "private", clock=lambda: clock[0])
    record = reopened.get(run_id)
    assert record["state"] == "cancelled"
    assert record["cancellation_requested"] is True
    assert record["attempt"] == 1
    assert record["lease_token"] is record["lease_until"] is record["lease_expires_at"] is None
    assert record["operation_result"] is None
    assert record["evidence_refs"] == record["recovery_actions"] == []
    assert call(service, "cops.run.resume", {"run_id": run_id})["result"]["state"] == "cancelled"
    assert calls == []
    late = store.finish(run_id, attempt["lease_token"], "succeeded", {"late": True})
    assert late == record


def test_queued_cancel_and_unconfigured_storage(tmp_path):
    service = OperationService(run_store=RunStore(tmp_path / "private"))
    run_id = call(service, "cops.run.create", {"request": request()})["result"]["run_id"]
    assert call(service, "cops.run.cancel", {"run_id": run_id})["result"]["state"] == "cancelled"
    assert call(service, "cops.run.resume", {"run_id": run_id})["result"]["state"] == "cancelled"
    assert call(OperationService(), "cops.run.status", {"run_id": run_id})["error"]["code"] == "runtime_not_configured"
    nested = {
        "request": {
            "schema_version": "cops.operation-request/v1",
            "operation_id": "cops.run.resume",
            "arguments": {"run_id": run_id},
        }
    }
    assert call(service, "cops.run.create", nested)["status"] == "failed"


def test_private_state_and_symlink_rejection(tmp_path):
    store = RunStore(tmp_path / "private")
    assert store.path.stat().st_mode & 0o077 == 0
    assert store.path.parent.stat().st_mode & 0o077 == 0
    link = tmp_path / "redirect"
    link.symlink_to(store.path.parent, target_is_directory=True)
    with pytest.raises(OperationError, match="unsafe_state"):
        RunStore(link)


def test_actual_process_loss_and_restart(tmp_path):
    root = Path(__file__).resolve().parents[1]
    clock = [100.0]
    store = RunStore(tmp_path / "private", clock=lambda: clock[0], lease_seconds=10)
    service = OperationService(run_store=store)
    run_id = call(service, "cops.run.create", {"request": request()})["result"]["run_id"]
    code = (
        "import os,sys; from pathlib import Path; from cops.operations.runs import RunStore; "
        "s=RunStore(Path(sys.argv[1]),clock=lambda:100.0,lease_seconds=10); "
        "s.claim(sys.argv[2]); os._exit(17)"
    )
    process = subprocess.run(
        [sys.executable, "-B", "-c", code, str(store.path.parent), run_id], cwd=root, capture_output=True, timeout=15
    )
    assert process.returncode == 17
    assert store.get(run_id)["state"] == "running"
    clock[0] = 111
    assert store.recover(run_id)["state"] == "queued"
    assert call(service, "cops.run.resume", {"run_id": run_id})["result"]["attempt"] == 2


def test_cli_restart_uses_installation_owned_configuration(tmp_path):
    root = Path(__file__).resolve().parents[1]
    config = tmp_path / "runtime.json"
    state = tmp_path / "private"
    config.write_text(json.dumps({"schema_version": "cops.operation-runtime/v1", "state_directory": str(state)}))
    config.chmod(0o600)
    environment = dict(os.environ, COPS_RUNTIME_CONFIG=str(config))

    def cli(operation, arguments):
        document = {"schema_version": "cops.operation-request/v1", "operation_id": operation, "arguments": arguments}
        process = subprocess.run(
            [sys.executable, "-B", "-m", "cops", "tools", "invoke"],
            cwd=root,
            env=environment,
            input=json.dumps(document),
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert process.returncode == 0, process.stderr + process.stdout
        return json.loads(process.stdout)

    created = cli("cops.run.create", {"request": request()})
    run_id = created["result"]["run_id"]
    assert cli("cops.run.resume", {"run_id": run_id})["result"]["state"] == "succeeded"
    assert cli("cops.run.status", {"run_id": run_id})["result"]["attempt"] == 1
    config.chmod(0o644)
    blocked = OperationService(runtime_config=config).invoke(
        {
            "schema_version": "cops.operation-request/v1",
            "operation_id": "cops.run.status",
            "arguments": {"run_id": run_id},
        }
    )
    assert blocked["error"]["code"] == "unsafe_runtime_configuration"


def test_capacity_rejects_before_acceptance(tmp_path):
    store = RunStore(tmp_path / "private", max_records=1)
    service = OperationService(run_store=store)
    assert call(service, "cops.run.create", {"request": request()})["status"] == "succeeded"
    exhausted = call(service, "cops.run.create", {"request": request("another")})
    assert exhausted["error"]["code"] == "state_capacity_exhausted"


def test_sqlite_sidecar_redirect_is_rejected_without_touching_target(tmp_path):
    store = RunStore(tmp_path / "private")
    target = tmp_path / "unrelated"
    target.write_bytes(b"preserve this unrelated file")
    sidecar = Path(str(store.path) + "-journal")
    sidecar.symlink_to(target)
    with pytest.raises(OperationError, match="unsafe_state"):
        store.get("not-a-run")
    assert target.read_bytes() == b"preserve this unrelated file"


def test_competing_idempotent_acceptance_and_capacity_recovery(tmp_path):
    store = RunStore(tmp_path / "private", max_records=1)
    services = [
        OperationService(run_store=store),
        OperationService(run_store=RunStore(tmp_path / "private", max_records=1)),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda service: call(
                    service,
                    "cops.run.create",
                    {
                        "request": request(),
                        "idempotency_key": "same",
                    },
                ),
                services,
            )
        )
    assert results[0] == results[1]
    assert call(services[0], "cops.run.create", {"request": request(), "idempotency_key": "same"}) == results[0]
    assert (
        call(services[0], "cops.run.create", {"request": request("other")})["error"]["code"]
        == "state_capacity_exhausted"
    )


def test_legacy_worker_run_cannot_be_read_or_advanced(tmp_path):
    import hashlib
    import sqlite3

    from cops.operations.contracts import encode

    store = RunStore(tmp_path / "private")
    service = OperationService(run_store=store)
    args = {"request": request(), "idempotency_key": "legacy"}
    run_id = call(service, "cops.run.create", args)["result"]["run_id"]
    record = store.get(run_id)
    record.update(
        controlled=True,
        kind="controlled",
        state="approval_required",
        authorization_id="legacy-approval",
        plan_ref="legacy-plan",
    )
    raw = encode(record)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE runs SET document=?, checksum=? WHERE run_id=?", (raw, hashlib.sha256(raw).hexdigest(), run_id)
        )
    before = store.path.read_bytes()
    for action in ("status", "resume", "recover", "cancel"):
        result = call(service, f"cops.run.{action}", {"run_id": run_id})
        assert result["status"] == "blocked"
        assert result["error"]["code"] == "offline_run_required"
    assert call(service, "cops.run.create", args)["error"]["code"] == "offline_run_required"
    assert store.path.read_bytes() == before


def test_configuration_rejects_legacy_dispatch_settings_before_creating_state(tmp_path):
    config = tmp_path / "runtime.json"
    state = tmp_path / "private"
    config.write_text(
        json.dumps({"schema_version": "cops.operation-runtime/v1", "state_directory": str(state), "controlled": {}})
    )
    config.chmod(0o600)
    result = call(OperationService(runtime_config=config), "cops.run.create", {"request": request()})
    assert result["error"]["code"] == "invalid_runtime_configuration"
    assert not state.exists()


def test_durable_acceptance_rejects_non_offline_and_nested_lifecycle_requests(tmp_path):
    store = RunStore(tmp_path / "private")
    service = OperationService(run_store=store)
    before = store.path.read_bytes()
    for operation, arguments in (
        ("cops.controlled.submit", {}),
        ("cops.assess.unregistered", {}),
        ("cops.run.status", {"run_id": "unused"}),
    ):
        nested = dict(request(), operation_id=operation, arguments=arguments)
        result = call(service, "cops.run.create", {"request": nested})
        assert result["error"]["code"] == "invalid_input_or_runtime"
    assert (
        call(service, "cops.run.resume", {"run_id": "unused", "authorization_id": "legacy-approval"})["error"]["code"]
        == "invalid_input_or_runtime"
    )
    assert store.path.read_bytes() == before


def test_accepted_binding_and_schema_are_revalidated_before_dispatch(tmp_path, monkeypatch):
    from cops._schema_validation import validate
    from cops.operations.runs import RUN_SCHEMA

    store = RunStore(tmp_path / "private")
    service = OperationService(run_store=store)
    run_id = call(service, "cops.run.create", {"request": request()})["result"]["run_id"]
    validate(store.get(run_id), RUN_SCHEMA)
    monkeypatch.setattr(service, "operation_binding", lambda identifier: "a" * 64)
    assert call(service, "cops.run.resume", {"run_id": run_id})["error"]["code"] == "run_binding_changed"
    assert store.get(run_id)["attempt"] == 0
