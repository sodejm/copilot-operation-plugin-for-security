"""Approval must bind the whole authorization laboratory before any process starts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

from cops.contracts import ActionPlan
from cops.execution.authorization import create_execution_authorization
from cops.execution.store import ApprovalStore, ApprovalStoreConflictError
from cops.laboratory import agent_mcp
from tests.auth_testkit import (
    authorization_secret_environment,
    make_test_authorization_context,
    write_test_authorization_trust_store,
)

PLUGIN_ROOT = Path(__file__).resolve().parents[1] / "plugins/offensive-security/foundry-agent-harness"
sys.path.insert(0, str(PLUGIN_ROOT))

from foundryharness import auth_approval, auth_bootstrap, auth_fixture_server, auth_laboratory  # noqa: E402


def authorized_batch(tmp_path: Path, cases=None):
    if cases is None:
        cases = auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases/delegated-control.json")
    plan = auth_approval.build_auth_plan(
        cases,
        plan_id="plan-auth-approval-test",
        engagement_id="eng-auth-approval-test",
        created_at="2026-10-12T00:00:00Z",
    )
    signer, trust_store, engagement = make_test_authorization_context(plan)
    authorization = create_execution_authorization(
        plan, signer=signer, engagement=engagement, worker_identity="fixture-worker",
    )
    store = ApprovalStore(tmp_path / "approval" / "authorization.sqlite3")
    store.store_authorization(authorization)
    return cases, {
        "plan": plan,
        "authorization": authorization,
        "engagement": engagement,
        "trust_store": trust_store,
        "worker_identity": "fixture-worker",
        "approval_store": store,
    }


def patch_executor(monkeypatch: pytest.MonkeyPatch, configure):
    """Instrument the freshly imported, approved execution namespace."""
    loader = auth_bootstrap._load_executor

    def load(source_root):
        executor = loader(source_root)
        configure(executor)
        return executor

    monkeypatch.setattr(auth_bootstrap, "_load_executor", load)


def forbid_processes(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("fixture launched before authorization passed")

    monkeypatch.setattr(auth_approval, "_JsonLineProcess", forbidden)
    monkeypatch.setattr(auth_bootstrap, "_load_executor", forbidden)


def test_trusted_planner_matches_runtime_case_and_tool_contracts():
    cases = auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases")
    rows = agent_mcp.load_case_inputs(PLUGIN_ROOT / "auth_cases")
    assert rows == tuple(case.to_dict() for case in cases)
    plan = agent_mcp.build_auth_plan(
        rows, plan_id="plan-contract-parity", engagement_id="eng-contract-parity",
        created_at="2026-10-12T00:00:00Z", source_root=PLUGIN_ROOT / "foundryharness",
    )
    manifest = plan.approved_snapshot()["operations"][0]["arguments"]
    adapter = manifest["adapter"]
    assert adapter["protocol_version"] == auth_fixture_server.PROTOCOL_VERSION
    assert adapter["server_info"] == auth_fixture_server.SERVER_INFO
    assert adapter["tools"] == list(auth_fixture_server.TOOLS)
    assert adapter["tool_input_schemas"] == auth_fixture_server.TOOL_INPUT_SCHEMAS
    assert adapter["tool_permissions"] == list(auth_fixture_server.TOOL_PERMISSIONS)
    assert adapter["peer_actions"] == list(auth_fixture_server.PEER_ACTIONS)
    assert manifest["fault_modes"]["supported"] == list(auth_fixture_server.FAULT_MODES)


@pytest.mark.parametrize("mutation", ["tool_schema", "permission", "peer", "cleanup", "budget"])
def test_signed_but_changed_execution_contract_is_rejected_before_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
):
    cases, context = authorized_batch(tmp_path)
    snapshot = context["plan"].approved_snapshot()
    manifest = snapshot["operations"][0]["arguments"]
    if mutation == "tool_schema":
        manifest["adapter"]["tool_input_schemas"]["canary/write"]["additionalProperties"] = True
    elif mutation == "permission":
        manifest["adapter"]["tool_permissions"][1]["granted_scopes"] = ["canary:admin"]
    elif mutation == "peer":
        manifest["adapter"]["peer_actions"] = ["trusted_forward"]
    elif mutation == "cleanup":
        manifest["cleanup"]["verify_process_exit"] = False
    else:
        snapshot["limits"]["max_output_bytes"] *= 2
    snapshot.pop("schema_version")
    plan = ActionPlan.create(**snapshot)
    signer, trust_store, engagement = make_test_authorization_context(plan)
    authorization = create_execution_authorization(
        plan, signer=signer, engagement=engagement, worker_identity="fixture-worker",
    )
    context["approval_store"].store_authorization(authorization)
    context.update(plan=plan, authorization=authorization, engagement=engagement, trust_store=trust_store)
    forbid_processes(monkeypatch)
    with pytest.raises(ValueError, match="fixed authorization batch"):
        auth_approval.run_auth_cases(cases, **context)
    assert context["approval_store"].get_authorization(authorization.authorization_id).status == "approved"


def test_missing_signed_approval_cannot_launch_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cases, context = authorized_batch(tmp_path)
    context["authorization"] = None
    forbid_processes(monkeypatch)
    with pytest.raises((TypeError, ValueError, RuntimeError)):
        auth_approval.run_auth_cases(cases, **context)


@pytest.mark.parametrize("field,value", [("tick", 2), ("depth", 2), ("operation", "read")])
def test_case_mutation_invalidates_signed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object,
):
    cases, context = authorized_batch(tmp_path)
    data = json.loads((PLUGIN_ROOT / "auth_cases/delegated-control.json").read_text())
    data["attempts"][0][field] = value
    changed_cases = [auth_laboratory.AuthCase.from_dict(data)]
    forbid_processes(monkeypatch)
    with pytest.raises((TypeError, ValueError, RuntimeError)):
        auth_approval.run_auth_cases(changed_cases, **context)


def test_consumed_approval_cannot_launch_another_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cases, context = authorized_batch(tmp_path)
    report = auth_approval.run_auth_cases(cases, **context)
    assert report["all_expectations_met"] is True
    forbid_processes(monkeypatch)
    with pytest.raises((TypeError, ValueError, RuntimeError)):
        auth_approval.run_auth_cases(cases, **context)


def test_wrong_worker_cannot_launch_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cases, context = authorized_batch(tmp_path)
    context["worker_identity"] = "different-worker"
    forbid_processes(monkeypatch)
    with pytest.raises((TypeError, ValueError, RuntimeError)):
        auth_approval.run_auth_cases(cases, **context)


def test_competing_receipt_consumers_launch_only_one_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cases, context = authorized_batch(tmp_path)
    barrier = Barrier(2)
    lock = Lock()
    launches = []
    process = auth_approval._JsonLineProcess

    def tracked_process(*args, **kwargs):
        with lock:
            launches.append(args)
        return process(*args, **kwargs)

    def attempt():
        barrier.wait(timeout=5)
        try:
            return auth_approval.run_auth_cases(cases, **context)
        except ApprovalStoreConflictError as error:
            return error

    patch_executor(monkeypatch, lambda executor: setattr(executor, "_JsonLineProcess", tracked_process))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    reports = [result for result in results if isinstance(result, dict)]
    assert len(reports) == 1
    assert reports[0]["all_expectations_met"] is True
    assert sum(isinstance(result, ApprovalStoreConflictError) for result in results) == 1
    assert len(launches) == 2  # One target service and one peer for the winning batch.


def test_output_budget_counts_responses_and_new_bytes_across_ledgers(tmp_path: Path):
    _, context = authorized_batch(tmp_path)
    budget = auth_approval._BatchBudget(context["plan"], context["authorization"].authorized_until_utc)
    budget.output_limit = 10
    budget.account_response(b"abc")
    budget.account_ledger(tmp_path / "first", b"1234")
    budget.account_ledger(tmp_path / "first", b"1234")
    assert budget.output_bytes == 7
    with pytest.raises(auth_approval._BatchBudgetStop, match="output_budget_exhausted"):
        budget.account_ledger(tmp_path / "second", b"5678")
    assert budget.report()["observed_output_bytes"] == 7
    assert budget.report()["accounting_scope"] == "received_response_bytes_and_new_ledger_bytes"


def test_effect_ledger_cannot_rewrite_observed_history(tmp_path: Path):
    _, context = authorized_batch(tmp_path)
    budget = auth_approval._BatchBudget(context["plan"], context["authorization"].authorized_until_utc)
    ledger = tmp_path / "effects"
    budget.account_ledger(ledger, b"first\n")
    with pytest.raises(auth_laboratory.LabError, match="changed previously observed bytes"):
        budget.account_ledger(ledger, b"other\n")
    assert budget.output_bytes == len(b"first\n")


def test_duration_budget_reserves_cleanup_and_stops_next_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cases = auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases/delegated-control.json")
    cases += auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases/wrong-audience.json")
    cases, context = authorized_batch(tmp_path, cases)
    clock = [0.0]
    def configure(executor):
        executor.time = SimpleNamespace(monotonic=lambda: clock[0])
        original = executor._run_auth_case

        def complete_first_case(*args, **kwargs):
            result = original(*args, **kwargs)
            clock[0] = 112.0
            return result

        executor._run_auth_case = complete_first_case

    patch_executor(monkeypatch, configure)
    report = auth_approval.run_auth_cases(cases, **context)
    assert report["results"][0]["expectation_met"] is True
    assert report["completed_case_count"] == 1
    assert report["pending_case_ids"] == [cases[1].case_id]
    assert report["budget"]["stop_reason"] == "duration_budget_exhausted"
    assert report["budget"]["cleanup_reserve_seconds"] == 8
    assert report["next_action"] == "approve_a_new_plan_for_pending_cases"
    assert report["all_expectations_met"] is False


def test_expiry_stops_admission_even_with_duration_remaining(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _, context = authorized_batch(tmp_path)
    until = context["authorization"].authorized_until_utc
    budget = auth_approval._BatchBudget(context["plan"], until)
    monkeypatch.setattr(auth_approval, "utc_now", lambda: until)
    with pytest.raises(auth_approval._BatchBudgetStop, match="authorization_expired"):
        budget.admit()


def test_cli_runs_one_signed_batch_and_rejects_receipt_reuse(tmp_path: Path):
    cases_path = tmp_path / "cases"
    cases_path.mkdir()
    for name in ("delegated-control", "wrong-audience"):
        (cases_path / f"{name}.json").write_bytes((PLUGIN_ROOT / f"auth_cases/{name}.json").read_bytes())
    cli = [sys.executable, str(PLUGIN_ROOT / "foundryharness/cli.py")]
    plan_path = tmp_path / "plan.json"
    compiled = subprocess.run(
        cli + [
            "auth-plan", "--cases", str(cases_path), "--plan-id", "plan-cli-auth-test",
            "--engagement-id", "eng-cli-auth-test", "--created-at", "2026-10-12T00:00:00Z",
            "--output", str(plan_path),
        ],
        capture_output=True, text=True, timeout=15,
    )
    assert compiled.returncode == 0, compiled.stderr
    plan = ActionPlan.from_dict(json.loads(plan_path.read_text()))
    signer, _, engagement = make_test_authorization_context(plan)
    authorization = create_execution_authorization(
        plan, signer=signer, engagement=engagement, worker_identity="fixture-worker",
    )
    engagement_path = tmp_path / "engagement.json"
    authorization_path = tmp_path / "authorization.json"
    engagement_path.write_text(json.dumps(engagement.to_dict()))
    authorization_path.write_text(json.dumps(authorization.to_dict()))
    store_path = tmp_path / "approval" / "authorization.sqlite3"
    ApprovalStore(store_path).store_authorization(authorization)
    trust_path = write_test_authorization_trust_store(tmp_path / "trust.json")
    arguments = cli + [
        "auth-lab", "--cases", str(cases_path), "--plan", str(plan_path),
        "--engagement", str(engagement_path), "--authorization", str(authorization_path),
        "--trust-store", str(trust_path), "--worker-identity", "fixture-worker",
        "--approval-store", str(store_path), "--json",
    ]
    environment = {**os.environ, **authorization_secret_environment()}
    completed = subprocess.run(arguments, capture_output=True, text=True, env=environment, timeout=30)
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["all_expectations_met"] is True
    assert report["security_pass"] is True
    assert report["source_snapshot"] == {
        "verified": True, "private_directory_removed": True, "reason": None,
    }
    assert report["assessment_authorization"]["consumed_once_for_batch"] is True
    assert report["completed_case_count"] == 2
    outcomes = {result["case_id"]: result for result in report["results"]}
    assert len(outcomes["delegated-control"]["observed_effects"]) == 1
    assert outcomes["wrong-audience"]["observed_effects"] == []
    rejected = subprocess.run(arguments, capture_output=True, text=True, env=environment, timeout=15)
    assert rejected.returncode == 2
    assert "consumed" in rejected.stderr
    assert "Traceback" not in rejected.stderr
    assert not (tmp_path / "report.json").exists()
