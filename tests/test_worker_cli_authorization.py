"""CLI regressions for independently provisioned execution authority."""

from __future__ import annotations

import json

import pytest

from cops.cli import main
from cops.contracts import ActionPlan
from cops.execution import ApprovalStore
from cops.execution.authorization import create_execution_authorization
from tests.auth_testkit import (
    authorization_secret_environment,
    make_test_authorization_context,
    worker_inventory_for_plan,
    write_test_authorization_trust_store,
    write_test_worker_inventory,
)


def test_worker_cli_preserves_receipt_and_consumes_exactly_once(tmp_path, monkeypatch, capsys):
    plan = ActionPlan.create(
        plan_id="plan-cli-001",
        engagement_id="eng-cli-001",
        scenario_id="COPS-E03.03-S01",
        specialist_id="cops-pentest-specialist",
        target="10.200.0.10",
        operations=[{
            "step_id": "step-01", "tool": "inert", "tool_version": "1.0.0",
            "action": "probe", "arguments": {}, "timeout_seconds": 5,
        }],
        limits={"max_duration_seconds": 10, "max_output_bytes": 4096, "egress_allowed": False},
        credential_references=[],
        platform_prerequisites=["linux"],
        created_at="2026-01-01T00:00:00Z",
        status="approved",
    )
    signer, _, engagement = make_test_authorization_context(plan)
    auth_args = {
        "signer": signer, "engagement": engagement,
        "worker_identity": "cli-worker", "authorization_id": "auth-cli-00000001",
    }
    stored_receipt = create_execution_authorization(plan, valid_hours=2, **auth_args)
    supplied_receipt = create_execution_authorization(plan, valid_hours=1, **auth_args)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(json.dumps(supplied_receipt.to_dict()), encoding="utf-8")
    engagement_file = tmp_path / "engagement.json"
    engagement_file.write_text(json.dumps(engagement.to_dict()), encoding="utf-8")
    inventory_file = write_test_worker_inventory(
        tmp_path / "inventory.json",
        worker_inventory_for_plan(plan, worker_identity="cli-worker"),
    )
    trust_file = write_test_authorization_trust_store(tmp_path / "trust.json")
    for name, value in authorization_secret_environment().items():
        monkeypatch.setenv(name, value)
    store = ApprovalStore(tmp_path / "private" / "approvals.sqlite3")
    store.store_authorization(stored_receipt)
    base = [
        "worker", "execute", str(plan_file),
        "--worker-inventory", str(inventory_file),
        "--authorization-trust-store", str(trust_file),
        "--engagement", str(engagement_file), "--db", str(store.db_path), "--json",
    ]

    # Both receipts are authentic. The supplied document must survive CLI loading
    # so the transaction can reject its mismatch with the stored receipt.
    assert main([*base, "--authorization", str(receipt_file)]) == 1
    assert "differs from the verified receipt" in capsys.readouterr().err
    assert store.get_authorization(stored_receipt.authorization_id).status == "approved"

    assert main([*base, "--authorization", stored_receipt.authorization_id]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "success"
    assert store.get_authorization(stored_receipt.authorization_id).status == "consumed"

    assert main([*base, "--authorization", stored_receipt.authorization_id]) == 1
    assert "consumed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "required_input",
    ["--worker-inventory", "--authorization-trust-store", "--engagement"],
)
def test_worker_cli_requires_independent_authority_inputs(required_input, capsys):
    arguments = ["worker", "execute", "plan.json", "--authorization", "receipt.json"]
    for option in ("--worker-inventory", "--authorization-trust-store", "--engagement"):
        if option != required_input:
            arguments.extend([option, "input.json"])
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
    assert required_input in capsys.readouterr().err
