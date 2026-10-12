"""Regressions for approved source execution, bounded inputs, and honest outcomes."""

from __future__ import annotations

import io
import json
import os
import signal
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops.execution import store as store_module
from cops.execution.authorization import create_execution_authorization
from cops.execution.store import ApprovalStoreConflictError
from tests.auth_testkit import (
    authorization_secret_environment,
    make_test_authorization_context,
    write_test_authorization_trust_store,
)
from tests.test_auth_assessment_approval import PLUGIN_ROOT, authorized_batch, forbid_processes
from foundryharness import auth_approval, auth_laboratory, cli, laboratory


def cli_context(tmp_path: Path, data: dict | None = None):
    case_path = tmp_path / "case.json"
    if data is None:
        data = json.loads((PLUGIN_ROOT / "auth_cases/delegated-control.json").read_text())
    case_path.write_text(json.dumps(data))
    cases = auth_laboratory.load_auth_cases(case_path)
    _, context = authorized_batch(tmp_path, cases)
    paths = {}
    for name in ("plan", "engagement", "authorization"):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(context[name].to_dict()))
    paths["trust-store"] = write_test_authorization_trust_store(tmp_path / "trust.json")
    arguments = ["auth-lab", "--cases", str(case_path)]
    for name, path in paths.items():
        arguments.extend((f"--{name}", str(path)))
    arguments.extend((
        "--worker-identity", "fixture-worker", "--approval-store",
        str(context["approval_store"].db_path), "--json",
    ))
    return arguments, paths, context


def set_test_secrets(monkeypatch):
    for name, value in authorization_secret_environment().items():
        monkeypatch.setenv(name, value)


def test_execution_uses_captured_approved_bytes_after_source_changes(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for name in auth_approval.SOURCE_FILES:
        (source / name).write_bytes((PLUGIN_ROOT / "foundryharness" / name).read_bytes())
    monkeypatch.setattr(auth_approval, "__file__", str(source / "auth_approval.py"))
    cases, context = authorized_batch(tmp_path)
    marker = tmp_path / "unapproved-source-executed"
    verify = auth_approval.verify_execution_authorization
    original_process = auth_approval._JsonLineProcess
    launched_sources = []

    def change_source_after_verification(*args, **kwargs):
        result = verify(*args, **kwargs)
        (source / "auth_fixture_server.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('changed')\n"
        )
        return result

    def track_process(*args, **kwargs):
        launched_sources.append(kwargs["source_root"])
        return original_process(*args, **kwargs)

    monkeypatch.setattr(auth_approval, "verify_execution_authorization", change_source_after_verification)
    monkeypatch.setattr(auth_approval, "_JsonLineProcess", track_process)
    report = auth_approval.run_auth_cases(cases, **context)
    assert report["security_pass"] is True
    assert not marker.exists()
    assert len(launched_sources) == 2
    assert all(path != source and not path.exists() for path in launched_sources)


@pytest.mark.parametrize("interrupt_at", ["first_spawn", "second_spawn", "cleanup"])
def test_sigint_during_startup_or_cleanup_observes_exits_and_removal(tmp_path, monkeypatch, interrupt_at):
    cases, context = authorized_batch(tmp_path)
    original_process = auth_approval._JsonLineProcess
    launched = []
    interrupted = [False]

    def tracked_process(*args, **kwargs):
        child = original_process(*args, **kwargs)
        launched.append((child, Path(args[1]), kwargs["source_root"]))
        target_count = 1 if interrupt_at == "first_spawn" else 2
        if interrupt_at != "cleanup" and len(launched) == target_count:
            os.kill(os.getpid(), signal.SIGINT)
        if interrupt_at == "cleanup":
            close = child.close

            def interrupted_close():
                if not interrupted[0]:
                    interrupted[0] = True
                    raise KeyboardInterrupt
                return close()

            child.close = interrupted_close
        return child

    monkeypatch.setattr(auth_approval, "_JsonLineProcess", tracked_process)
    report = auth_approval.run_auth_cases(cases, **context)
    assert report["cancelled"] is True
    assert report["security_pass"] is False
    assert report["all_expectations_met"] is False
    assert report["pending_case_ids"] == [cases[0].case_id]
    assert report["results"][0]["cleanup"] == {
        "process_exit_observed": True, "private_directory_removed": True,
    }
    assert launched and all(
        child.process.poll() is not None and not directory.exists() and not source.exists()
        for child, directory, source in launched
    )


@pytest.mark.parametrize("output_kind", ["existing", "symlink"])
def test_cli_cannot_write_an_unapproved_report_destination(tmp_path, monkeypatch, output_kind):
    arguments, _, context = cli_context(tmp_path)
    destination = tmp_path / "destination.json"
    destination.write_text("original report")
    output = destination
    if output_kind == "symlink":
        output = tmp_path / "report-link.json"
        output.symlink_to(destination)
    forbid_processes(monkeypatch)
    with pytest.raises(SystemExit) as error:
        cli.main(arguments + ["--output", str(output)])
    assert error.value.code == 2
    assert destination.read_text() == "original report"
    assert context["approval_store"].get_authorization(context["authorization"].authorization_id).status == "approved"


@pytest.mark.parametrize("mode", ["hung_server", "unsupported", "missing_context"])
def test_cli_returns_failure_for_incomplete_or_inconclusive_security_evidence(tmp_path, monkeypatch, capsys, mode):
    data = json.loads((PLUGIN_ROOT / "auth_cases/delegated-control.json").read_text())
    if mode == "unsupported":
        data.update(surface="unsupported_provider_surface", expected_outcome="unsupported")
    elif mode == "missing_context":
        data = json.loads((PLUGIN_ROOT / "auth_cases/peer-omit-tenant.json").read_text())
    else:
        data["attempts"][0]["fault_mode"] = mode
    arguments, _, _ = cli_context(tmp_path, data)
    set_test_secrets(monkeypatch)
    assert cli.main(arguments) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["security_pass"] is False
    result = report["results"][0]
    assert result["outcome"] in ("unsupported", "inconclusive")
    if mode == "missing_context":
        assert result["evidence_complete"] is True
        assert result["expectation_met"] is True
    else:
        assert result["evidence_complete"] is False
        assert result["expectation_met"] is False


@pytest.mark.parametrize("input_name", ["plan", "engagement", "authorization", "trust-store"])
@pytest.mark.parametrize("bad_input", ["duplicate", "deep", "nonfinite", "invalid_utf8", "oversized", "symlink"])
def test_cli_rejects_malformed_inputs_before_consumption_or_launch(
    tmp_path, monkeypatch, capsys, input_name, bad_input,
):
    arguments, paths, context = cli_context(tmp_path)
    path = paths[input_name]
    if bad_input == "symlink":
        original = tmp_path / "original.json"
        original.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(original)
    else:
        payload = {
            "duplicate": b'{"schema_version":"first","schema_version":"second"}',
            "deep": b'{"nested":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
            "nonfinite": b'{"value":NaN}',
            "invalid_utf8": b'{"value":"\xff"}',
            "oversized": b" " * (1048576 + 1),
        }[bad_input]
        path.write_bytes(payload)
    set_test_secrets(monkeypatch)
    forbid_processes(monkeypatch)
    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert "Traceback" not in captured.err
    assert str(tmp_path) not in captured.err
    assert context["approval_store"].get_authorization(context["authorization"].authorization_id).status == "approved"


def test_near_expiry_receipt_is_not_consumed_and_launches_nothing(tmp_path, monkeypatch):
    cases, context = authorized_batch(tmp_path)
    signer, trust, engagement = make_test_authorization_context(context["plan"])
    now = datetime.now(timezone.utc)
    receipt = create_execution_authorization(
        context["plan"], signer=signer, engagement=engagement, worker_identity="fixture-worker",
        issued_at=now.isoformat().replace("+00:00", "Z"),
        authorized_until_utc=(now + timedelta(seconds=8)).isoformat().replace("+00:00", "Z"),
    )
    context.update(authorization=receipt, trust_store=trust, engagement=engagement)
    context["approval_store"].store_authorization(receipt)
    forbid_processes(monkeypatch)
    with pytest.raises(ApprovalStoreConflictError, match="insufficient time"):
        auth_approval.run_auth_cases(cases, **context)
    assert context["approval_store"].get_authorization(receipt.authorization_id).status == "approved"


def test_consumption_clock_is_observed_after_acquiring_write_lock(tmp_path, monkeypatch):
    _, context = authorized_batch(tmp_path)
    store = context["approval_store"]
    connection = store._get_connection
    locked = [False]
    receipt = context["authorization"]

    @contextmanager
    def observed_connection():
        with connection() as conn:
            class Proxy:
                def execute(self, statement, *args):
                    result = conn.execute(statement, *args)
                    if statement == "BEGIN IMMEDIATE":
                        locked[0] = True
                    return result
            yield Proxy()

    def clock_after_lock():
        assert locked[0], "authorization clock sampled before lock acquisition"
        return receipt.authorized_until_utc

    monkeypatch.setattr(store, "_get_connection", observed_connection)
    monkeypatch.setattr(store_module, "utc_now", clock_after_lock)
    with pytest.raises(ApprovalStoreConflictError, match="expired"):
        store.atomically_consume(
            receipt.authorization_id, expected_authorization=receipt, worker_identity="fixture-worker",
        )
    assert store.get_authorization(receipt.authorization_id).status == "expired"


@pytest.mark.parametrize("over_by", [0, 1])
def test_response_reads_respect_exact_remaining_byte_budget(tmp_path, monkeypatch, over_by):
    _, context = authorized_batch(tmp_path)
    budget = auth_approval._BatchBudget(context["plan"], context["authorization"].authorized_until_utc)
    raw = b'{"ok":true}\n'
    budget.output_limit = len(raw) - over_by
    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(raw))
    monkeypatch.setattr(laboratory.subprocess, "Popen", lambda *_args, **_kwargs: process)
    child = laboratory._JsonLineProcess(
        "auth_peer_fixture.py", str(tmp_path), admission_check=budget.admit,
        account_response=budget.account_response, response_bytes_remaining=budget.remaining_bytes,
    )
    if over_by:
        with pytest.raises(auth_approval._BatchBudgetStop, match="output_budget_exhausted"):
            child.exchange({"request": "test"})
    else:
        assert child.exchange({"request": "test"}) == {"ok": True}
    assert process.stdout.tell() == budget.output_limit
    assert budget.output_bytes == budget.output_limit
    with pytest.raises(auth_approval._BatchBudgetStop, match="output_budget_exhausted"):
        budget.admit()


@pytest.mark.parametrize("over_by", [0, 1])
def test_ledger_reads_respect_exact_remaining_byte_budget(tmp_path, over_by):
    _, context = authorized_batch(tmp_path)
    budget = auth_approval._BatchBudget(context["plan"], context["authorization"].authorized_until_utc)
    event = {field: "test" for field in auth_approval.LEDGER_FIELDS}
    event.update(
        schema_version="cops.agent-mcp-auth-ledger-event/v1", server_identity=auth_approval.SERVER_IDENTITY,
        test_identity=auth_approval.TEST_IDENTITY, kind="canary_write", operation="write", redacted=True,
    )
    raw = (json.dumps(event) + "\n").encode()
    ledger = tmp_path / "effects.jsonl"
    ledger.write_bytes(raw)
    budget.output_limit = len(raw) - over_by
    if over_by:
        with pytest.raises(auth_approval._BatchBudgetStop, match="output_budget_exhausted"):
            auth_approval._read_effects(ledger, budget)
        assert budget.output_bytes == 0  # Rejected from size metadata before reading.
    else:
        assert auth_approval._read_effects(ledger, budget) == [event]
        assert budget.output_bytes == len(raw)


@pytest.mark.parametrize("case_id", [
    "delegated-control-fabrikam", "cross-tenant-reverse", "peer-mutate-tenant",
    "peer-omit-tenant", "peer-mutate-operation", "peer-substitute-receipt",
])
def test_coverage_gate_rejects_same_count_with_missing_required_behavior(case_id):
    cases = auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases")
    auth_laboratory.validate_default_auth_coverage(cases)
    changed = []
    for case in cases:
        data = case.to_dict()
        if case.case_id == case_id:
            data["attempts"][0]["peer_action"] = "trusted_forward"
            data["attempts"][0]["tenant"] = "tenant-contoso-01"
            data["grant"] = "delegated-write"
        changed.append(auth_laboratory.AuthCase.from_dict(data))
    assert len(changed) == len(cases)
    with pytest.raises(auth_laboratory.LabError, match="coverage"):
        auth_laboratory.validate_default_auth_coverage(changed)
