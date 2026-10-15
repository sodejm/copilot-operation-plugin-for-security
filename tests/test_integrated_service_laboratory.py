from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cops.evidence.canonical import canonical, digest
from cops.execution.store import ApprovalStore
from cops.laboratory import integrated_lab
from cops.laboratory.service_lab import IsolationProbe
from cops.workflows.contracts import WorkflowDefinition
from cops.workflows.runtime import WorkflowRuntimeError, compile_action_plan
from tests.auth_testkit import make_test_authorization_context


@pytest.mark.parametrize("workflow_id", tuple(integrated_lab.WORKFLOW_STAGES))
def test_integrated_workflow_uses_services_and_action_bound_approvals(
    tmp_path: Path, workflow_id: str,
) -> None:
    report = integrated_lab.run_integrated_service_laboratory(
        tmp_path / workflow_id, workflow_id=workflow_id, run_id="test-" + workflow_id,
    )

    assert report["status"] == "success"
    assert report["setup_status"] == 201
    assert report["stages"] == list(integrated_lab.WORKFLOW_STAGES[workflow_id])
    assert report["authorization"]["provisioned"] == len(report["stages"])
    assert report["authorization"]["consumed"] == len(report["stages"])
    assert len(set(report["authorization"]["plan_digests"].values())) == len(report["stages"])
    assert report["restoration"] == {"baseline_restored": True, "services_stopped": True}
    assert report["telemetry_matches_memory"] is True
    assert report["events"]
    assert all(event["correlation_id"] == report["run_id"] for event in report["events"])
    assert all(request["destination"].startswith("http://127.0.0.1:") for request in report["requests"])
    assert "no production UID boundary claim" in report["authorization"]["boundary_limitation"]
    assessment = report["outputs"]["assessment"]

    if workflow_id == "leaked-credential-blast-radius":
        assert assessment["before_revocation"] == 200
        assert assessment["revocation"] == 200
        assert assessment["after_revocation"] == 401
        assert assessment["corrected"] is True
        assert assessment["synthetic_exposure"]["value_redacted"] is True
        bundle = assessment["bundle"]
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["public_key"]))
        public_key.verify(bytes.fromhex(bundle["signature"]), canonical(bundle["payload"]))
        assert digest(bundle["payload"]) == bundle["payload_digest"]
        with pytest.raises(InvalidSignature):
            public_key.verify(bytes.fromhex(bundle["signature"]), canonical({"tampered": True}))
        assert bundle["authenticity_established"] is False
    elif workflow_id == "cve-reachability-triage":
        assert assessment["vulnerable"]["injection_rows"] == 2
        assert assessment["vulnerable"]["actual_requests"] == 7
        assert assessment["corrected"]["injection_rows"] == 0
        assert assessment["corrected"]["actual_requests"] == 7
        assert assessment["reachability"] == "observed"
        assert assessment["remediation_verified"] is True
        assert assessment["without_runtime_evidence"] == {"reachability": "unknown", "non_exploitable": False}
        assert assessment["advisory"]["production_advisory_support"] is False
    elif workflow_id == "illicit-consent-remediation":
        assert assessment["grant_access_before"] == 200
        assert assessment["revocation"] == 200
        assert assessment["grant_access_after"] == 401
        assert assessment["remediation_verified"] is True
        assert assessment["production_entra_validation"] == "unverified"
    elif workflow_id == "detection-rule-ci-validation":
        assert assessment["attack_and_benign_executed"] is True
        assert assessment["event_counts"]["class:attack"] == 3
        assert assessment["event_counts"]["class:benign"] == 3
        assert assessment["event_counts"]["rule:ioc-hunt-hit"] == 1
        assert len(assessment["alerts"]) == 2
        assert assessment["sigma_kql_engine_validation"] == "unverified"
    else:
        assert assessment["authorized_status"] == 200
        assert assessment["anonymous_status"] == 401
        assert assessment["authentication_verified"] is True
        assert assessment["coverage"] == "explicit loopback destinations only"


def test_integrated_strict_isolation_blocks_before_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    probe = IsolationProbe(False, "loopback-only", "network isolation is unavailable", ())
    monkeypatch.setattr(integrated_lab, "probe_isolated_runtime", lambda: probe)
    state_dir = tmp_path / "must-not-exist"

    with pytest.raises(integrated_lab.IsolationRequiredError, match="network isolation is unavailable"):
        integrated_lab.run_integrated_service_laboratory(
            state_dir, workflow_id="leaked-credential-blast-radius", require_isolation=True,
        )
    assert not state_dir.exists()


def test_integrated_credential_never_enters_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    sentinel = "synthetic-integrated-credential-must-not-persist"
    monkeypatch.setattr(integrated_lab.secrets, "token_urlsafe", lambda _size: sentinel)
    state_dir = tmp_path / "secret-check"
    report = integrated_lab.run_integrated_service_laboratory(
        state_dir, workflow_id="leaked-credential-blast-radius",
    )

    assert sentinel not in json.dumps(report)
    for path in state_dir.rglob("*"):
        if path.is_file():
            assert sentinel.encode() not in path.read_bytes(), path


def test_unknown_integrated_workflow_does_not_create_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "unknown"
    with pytest.raises(KeyError):
        integrated_lab.run_integrated_service_laboratory(state_dir, workflow_id="unknown")
    assert not state_dir.exists()


@pytest.mark.parametrize("change", ("destination", "prior", "action", "authorization", "worker"))
def test_integrated_approval_rejects_changed_concrete_inputs_before_consumption(
    tmp_path: Path, change: str,
) -> None:
    definition = integrated_lab.laboratory_workflow("leaked-credential-blast-radius")
    configuration = {"destinations": {"resource": "http://127.0.0.1:10001"}}
    prior = {"synthetic_exposure": {"fingerprint": "sha256:original", "value_redacted": True}}
    resolved = {"configuration": configuration, "prior": prior}
    now = "2026-10-15T12:00:00Z"
    plan = compile_action_plan(definition, "test-bound-inputs", "correlate", resolved, now)
    signer, trust, engagement = make_test_authorization_context(plan)
    executor = SimpleNamespace(
        workflow_id="leaked-credential-blast-radius", configuration=configuration,
        executed=["scan"], observations=prior,
    )
    control = integrated_lab._IntegratedApprovalControl(
        ApprovalStore(tmp_path / "approvals.sqlite3"), trust, engagement, now,
        signer=signer, authorized_until="2026-10-15T13:00:00Z", definition=definition,
        run_id="test-bound-inputs", executor=executor,
        authorization_ids={"correlate": "auth-correlate"},
    )
    altered = json.loads(json.dumps(resolved))
    if change == "destination":
        altered["configuration"]["destinations"]["resource"] = "http://127.0.0.1:10002"
    elif change == "prior":
        altered["prior"]["synthetic_exposure"]["fingerprint"] = "sha256:substituted"
    elif change == "action":
        document = definition.to_dict()
        document["stages"][1]["action"]["action"] = "revoke"
        definition = WorkflowDefinition.from_dict(document)
    altered_plan = compile_action_plan(definition, "test-bound-inputs", "correlate", altered, now)
    authorization = "auth-unexpected" if change == "authorization" else "auth-correlate"
    worker = "unexpected-worker" if change == "worker" else integrated_lab.WORKER

    with pytest.raises((WorkflowRuntimeError, RuntimeError)):
        control.consume_authorization(authorization, altered_plan, worker)
    assert control.plan_digests == {}
    assert executor.executed == ["scan"]


def test_integrated_approval_is_single_use_and_binds_prior_stage_output(tmp_path: Path) -> None:
    definition = integrated_lab.laboratory_workflow("leaked-credential-blast-radius")
    now = "2026-10-15T12:00:00Z"
    configuration = {"destinations": {"resource": "http://127.0.0.1:10001"}}
    prior = {"before_revocation": 200}
    plan = compile_action_plan(
        definition, "test-once", "assess", {"configuration": configuration, "prior": prior}, now,
    )
    signer, trust, engagement = make_test_authorization_context(plan)
    store = ApprovalStore(tmp_path / "approvals.sqlite3")
    executor = SimpleNamespace(
        workflow_id="leaked-credential-blast-radius", configuration=configuration,
        executed=["scan", "correlate"], observations=prior,
    )
    control = integrated_lab._IntegratedApprovalControl(
        store, trust, engagement, now, signer=signer,
        authorized_until="2026-10-15T13:00:00Z", definition=definition,
        run_id="test-once", executor=executor, authorization_ids={"assess": "auth-assess-stage"},
    )
    receipt = control.consume_authorization("auth-assess-stage", plan, integrated_lab.WORKER)
    assert receipt.plan_digest == plan.plan_digest
    assert store.get_authorization("auth-assess-stage").status == "consumed"
    assert control.plan_digests == {"assess": plan.plan_digest}
    with pytest.raises(WorkflowRuntimeError, match="replayed"):
        control.consume_authorization("auth-assess-stage", plan, integrated_lab.WORKER)
