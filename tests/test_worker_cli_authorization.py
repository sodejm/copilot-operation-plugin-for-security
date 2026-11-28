"""CLI regressions for remote execution through independent authority."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import cops.execution as execution
from cops.cli import main
from cops.contracts import ActionPlan, RunResult


def _plan() -> ActionPlan:
    return ActionPlan.create(
        plan_id="plan-cli-001",
        engagement_id="eng-cli-001",
        scenario_id="COPS-E03.03-S01",
        specialist_id="cops-pentest-specialist",
        target="10.200.0.10",
        operations=[
            {
                "step_id": "step-01",
                "tool": "inert",
                "tool_version": "1.0.0",
                "action": "probe",
                "arguments": {},
                "timeout_seconds": 5,
            }
        ],
        limits={"max_duration_seconds": 10, "max_output_bytes": 4096, "egress_allowed": False},
        credential_references=[],
        platform_prerequisites=["linux"],
        created_at="2026-01-01T00:00:00Z",
        status="approved",
    )


def _result(plan: ActionPlan, *, status: str = "success") -> RunResult:
    return RunResult(
        schema_version="cops.run-result/v1",
        result_id="result-cli-001",
        plan_id=plan.plan_id,
        engagement_id=plan.engagement_id,
        status=status,
        started_at="2026-01-01T00:00:01Z",
        finished_at="2026-01-01T00:00:02Z",
        status_details={},
        evidence_records=[],
        artifacts=[],
        cleanup_status="not_required",
        worker_identity="cli-worker",
        exit_code=0 if status == "success" else 1,
    )


def test_worker_cli_dispatches_to_trusted_remote_endpoint(tmp_path, monkeypatch, capsys):
    plan = _plan()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    inventory_file = tmp_path / "ssh-endpoints.json"
    inventory_file.write_text("{}", encoding="utf-8")
    loaded_inventory = object()
    calls: dict[str, object] = {}

    class FakeInventory:
        @classmethod
        def from_file(cls, path):
            calls["inventory_path"] = path
            return loaded_inventory

    class FakeDispatcher:
        def __init__(self, inventory):
            calls["inventory"] = inventory

        def execute(self, **kwargs):
            calls["execute"] = kwargs
            return SimpleNamespace(result=_result(plan), approval_receipt=object())

    monkeypatch.setattr(execution, "SSHRemoteEndpointInventory", FakeInventory)
    monkeypatch.setattr(execution, "SSHExecutionDispatcher", FakeDispatcher)

    assert (
        main(
            [
                "worker",
                "execute",
                str(plan_file),
                "--authorization",
                "auth-cli-00000001",
                "--worker-id",
                "cli-worker",
                "--ssh-endpoint-inventory",
                str(inventory_file),
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "success"
    assert calls["inventory_path"] == inventory_file
    assert calls["inventory"] is loaded_inventory
    execute_call = calls["execute"]
    assert isinstance(execute_call, dict)
    assert execute_call["action_plan"].to_dict() == plan.to_dict()
    assert {key: value for key, value in execute_call.items() if key != "action_plan"} == {
        "approved_worker_identity": "cli-worker",
        "authorization_id": "auth-cli-00000001",
        "timeout_seconds": 10.0,
        "max_output_bytes": 4096,
    }


def test_worker_cli_keeps_authorization_id_opaque(tmp_path, monkeypatch, capsys):
    plan = _plan()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    inventory_file = tmp_path / "ssh-endpoints.json"
    inventory_file.write_text("{}", encoding="utf-8")
    authorization_id = tmp_path / "looks-like-a-receipt.json"
    authorization_id.write_text("not JSON", encoding="utf-8")
    calls: dict[str, object] = {}

    class FakeInventory:
        @classmethod
        def from_file(cls, path):
            return object()

    class FakeDispatcher:
        def __init__(self, inventory):
            pass

        def execute(self, **kwargs):
            calls.update(kwargs)
            return SimpleNamespace(result=_result(plan), approval_receipt=object())

    monkeypatch.setattr(execution, "SSHRemoteEndpointInventory", FakeInventory)
    monkeypatch.setattr(execution, "SSHExecutionDispatcher", FakeDispatcher)

    assert (
        main(
            [
                "worker",
                "execute",
                str(plan_file),
                "--authorization",
                str(authorization_id),
                "--worker-id",
                "cli-worker",
                "--ssh-endpoint-inventory",
                str(inventory_file),
            ]
        )
        == 0
    )
    assert calls["authorization_id"] == str(authorization_id)
    assert "Execution complete" in capsys.readouterr().out


@pytest.mark.parametrize(
    "required_input",
    ["--worker-id", "--ssh-endpoint-inventory"],
)
def test_worker_cli_requires_remote_authority_inputs(required_input, capsys):
    arguments = ["worker", "execute", "plan.json", "--authorization", "auth-001"]
    for option in ("--worker-id", "--ssh-endpoint-inventory"):
        if option != required_input:
            arguments.extend([option, "input"])
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
    assert required_input in capsys.readouterr().err


@pytest.mark.parametrize(
    "removed_option",
    [
        "--worker-inventory",
        "--authorization-trust-store",
        "--engagement",
        "--executable-sha256",
        "--db",
    ],
)
def test_worker_cli_rejects_operator_side_authority_inputs(removed_option, capsys):
    with pytest.raises(SystemExit) as error:
        main(
            [
                "worker",
                "execute",
                "plan.json",
                "--authorization",
                "auth-001",
                "--worker-id",
                "cli-worker",
                "--ssh-endpoint-inventory",
                "ssh-endpoints.json",
                removed_option,
                "input",
            ]
        )
    assert error.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
