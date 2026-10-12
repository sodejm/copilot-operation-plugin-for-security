"""Observe approved MCP authorization decisions and independent canary effects."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from foundryharness import auth_approval, auth_laboratory  # noqa: E402
from foundryharness.laboratory import LabError  # noqa: E402
from tests.test_auth_assessment_approval import authorized_batch, patch_executor  # noqa: E402


def case_data(name="delegated-control"):
    return json.loads((PLUGIN_ROOT / "auth_cases" / f"{name}.json").read_text())


def run_data(tmp_path, data):
    cases, context = authorized_batch(tmp_path, [auth_laboratory.AuthCase.from_dict(data)])
    return auth_approval.run_auth_cases(cases, **context)


def test_bundled_authorization_cases_have_independent_effect_evidence(tmp_path):
    schemas = {
        name: json.loads((PLUGIN_ROOT / "schemas" / f"auth-{name}.schema.json").read_text())
        for name in ("case", "report", "adapter", "evidence")
    }
    for path in (PLUGIN_ROOT / "auth_cases").glob("*.json"):
        jsonschema.validate(json.loads(path.read_text()), schemas["case"])
    cases, context = authorized_batch(tmp_path, auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases"))
    assert len(cases) >= 22
    manifest = context["plan"].to_dict()["operations"][0]["arguments"]
    jsonschema.validate(manifest["adapter"], schemas["adapter"])
    report = auth_approval.run_auth_cases(cases, **context)
    jsonschema.validate(report, schemas["report"])
    assert report["assessment_authorization"]["signed_receipt_verified"] is True
    assert report["assessment_authorization"]["consumed_once_for_batch"] is True
    assert report["all_expectations_met"] is True
    assert report["security_pass"] is True
    assert report["pending_case_ids"] == []
    assert report["budget"]["observed_output_bytes"] > 0
    results = {result["case_id"]: result for result in report["results"]}
    for case_id, result in results.items():
        assert result["outcome"] == "pass"
        assert result["evidence_complete"] is True
        assert result["security_pass"] is True
        assert result["environment_verified"] is True
        assert result["cleanup"] == {"process_exit_observed": True, "private_directory_removed": True}
        for index, row in enumerate(result["observations"], 1):
            jsonschema.validate(row, schemas["evidence"])
            assert row["attempt_id"] == f"{case_id}-{index}"
            for witness in (row["peer"], row["target"]):
                for field in ("attempt_id", "request_id", "canary_id", "plan_digest", "test_identity"):
                    assert witness[field] == row[field]
    decisions = lambda name: [row["target"]["decision"] for row in results[name]["observations"]]
    assert decisions("one-time-replay") == ["allowed", "denied"]
    assert len(results["one-time-replay"]["observed_effects"]) == 1
    assert decisions("reusable-grant") == ["allowed", "allowed"]
    assert len(results["reusable-grant"]["observed_effects"]) == 2
    assert results["read-control"]["observed_effects"] == []
    assert results["delegated-control-fabrikam"]["observed_effects"][0]["tenant"] == "tenant-fabrikam-02"
    assert results["cross-tenant-reverse"]["observed_effects"] == []
    for name in ("peer-mutate-tenant", "peer-omit-tenant", "peer-mutate-operation", "peer-substitute-receipt"):
        assert results[name]["observations"][0]["peer"]["peer_identity"] == "hostile-forwarding-peer"
        assert results[name]["observed_effects"] == []
    revocation = results["revoked-grant"]
    assert [row["target"]["reason"] for row in revocation["observations"]] == ["allowed", "revoked_grant"]
    assert revocation["revocation_window"] == {
        "clock": "synthetic_logical_ticks", "revoked_at_tick": 3,
        "observed_start_tick": 2, "observed_end_tick": 3,
        "pre_revocation_control_observed": True, "post_revocation_denial_observed": True,
        "observed_denial_lag_ticks": 0, "provider_propagation_measured": False,
    }
    assert all(result["observed_effects"] == [] for name, result in results.items()
               if name.startswith("wrong-") or name in {"cross-tenant", "expired-grant", "excess-depth", "confused-deputy"})


@pytest.mark.parametrize("tenant,principal,grant", [
    ("tenant-contoso-01", "principal-alice", "delegated-write"),
    ("tenant-fabrikam-02", "principal-bob", "delegated-write-fabrikam"),
])
def test_two_tenants_have_positive_controls_and_cross_tenant_denials(tmp_path, tenant, principal, grant):
    data = case_data()
    data["grant"] = grant
    data["attempts"][0].update(tenant=tenant, principal=principal)
    allowed = run_data(tmp_path / "control", data)["results"][0]
    assert allowed["outcome"] == "pass"
    assert allowed["observed_effects"][0]["tenant"] == tenant
    data["attempts"][0]["tenant"] = "tenant-fabrikam-02" if tenant == "tenant-contoso-01" else "tenant-contoso-01"
    data.update(expected_decisions=["denied"], expected_reasons=["tenant_mismatch"], expected_effect_count=0)
    denied = run_data(tmp_path / "cross", data)["results"][0]
    assert denied["outcome"] == "pass"
    assert denied["observed_effects"] == []


@pytest.mark.parametrize("action,decision,reason,outcome", [
    ("mutate_tenant", "denied", "tenant_mismatch", "pass"),
    ("omit_tenant", "denied", "missing_tenant", "pass"),
    ("mutate_operation", "denied", "operation_mismatch", "pass"),
    ("substitute_receipt", "denied", "unrecognized_grant_or_actor", "pass"),
])
def test_hostile_peer_is_observed_and_cannot_expand_target_authority(tmp_path, action, decision, reason, outcome):
    data = case_data()
    data["attempts"][0]["peer_action"] = action
    data.update(expected_decisions=[decision], expected_reasons=[reason], expected_effect_count=0, expected_outcome=outcome)
    result = run_data(tmp_path, data)["results"][0]
    assert result["outcome"] == outcome
    assert result["observations"][0]["peer"]["peer_identity"] == "hostile-forwarding-peer"
    assert result["observations"][0]["target"]["reason"] == reason
    assert result["observed_effects"] == []


def test_expected_reason_mismatch_is_failure(tmp_path):
    data = case_data("wrong-audience")
    data["expected_reasons"] = ["tenant_mismatch"]
    report = run_data(tmp_path, data)
    assert report["results"][0]["outcome"] == "fail"
    assert report["all_expectations_met"] is False


def test_trusted_peer_preserves_missing_tenant_for_target_denial(tmp_path):
    data = case_data()
    del data["attempts"][0]["tenant"]
    data["attempts"][0]["peer_action"] = "trusted_forward"
    data.update(expected_decisions=["denied"], expected_reasons=["missing_tenant"], expected_effect_count=0)
    report = run_data(tmp_path, data)
    assert report["all_expectations_met"] is True
    assert report["security_pass"] is True
    result = report["results"][0]
    assert result["evidence_complete"] is True
    assert result["observations"][0]["target"]["reason"] == "missing_tenant"
    assert result["observed_effects"] == []


@pytest.mark.parametrize("fault", ["hung_server", "missing_identity_telemetry", "observer_failure"])
def test_incomplete_runtime_evidence_is_inconclusive_with_cleanup(tmp_path, fault):
    data = case_data()
    data["attempts"][0]["fault_mode"] = fault
    result = run_data(tmp_path, data)["results"][0]
    assert result["outcome"] == "inconclusive"
    assert result["expectation_met"] is False
    assert result["security_pass"] is False
    assert result["evidence_complete"] is False
    assert result["cleanup"] == {"process_exit_observed": True, "private_directory_removed": True}


def test_cancellation_returns_pending_work_and_consumes_approval(tmp_path, monkeypatch):
    cases = auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases")[:2]
    cases, context = authorized_batch(tmp_path, cases)
    launched = []
    original_process = auth_approval._JsonLineProcess

    def capture_process(*args, **kwargs):
        child = original_process(*args, **kwargs)
        launched.append((child.process, Path(args[1])))
        return child

    def cancelled(*_args, **_kwargs):
        raise KeyboardInterrupt

    def configure(executor):
        executor._JsonLineProcess = capture_process
        executor._McpClient.call = cancelled

    patch_executor(monkeypatch, configure)
    report = auth_approval.run_auth_cases(cases, **context)
    assert report["cancelled"] is True
    assert report["all_expectations_met"] is False
    assert report["pending_case_ids"]
    assert report["next_action"] == "approve_a_new_plan_for_pending_cases"
    assert launched and all(process.poll() is not None and not directory.exists() for process, directory in launched)
    with pytest.raises((TypeError, ValueError, RuntimeError)):
        auth_approval.run_auth_cases(cases, **context)


def test_unsupported_surface_cannot_launch_fixture(tmp_path, monkeypatch):
    data = case_data()
    data.update(surface="unsupported_provider_surface", expected_outcome="unsupported")

    def forbidden(*_args, **_kwargs):
        pytest.fail("unsupported surface launched fixture")

    patch_executor(monkeypatch, lambda executor: setattr(executor, "_JsonLineProcess", forbidden))
    report = run_data(tmp_path, data)
    assert report["results"][0]["outcome"] == "unsupported"
    assert report["results"][0]["environment_verified"] is False
    assert report["results"][0]["expectation_met"] is False
    assert report["security_pass"] is False


@pytest.mark.parametrize("field,value", [
    ("grant", []), ("flow", {}), ("expected_decisions", [[]]), ("expected_reasons", [[]]),
    ("surface", []), ("expected_outcome", {}), ("case_id", "a" * 65),
])
def test_case_loader_rejects_malformed_values(tmp_path, field, value):
    data = case_data()
    data[field] = value
    (tmp_path / "case.json").write_text(json.dumps(data))
    with pytest.raises(LabError):
        auth_laboratory.load_auth_cases(tmp_path)


@pytest.mark.parametrize("field,value", [("tool", []), ("peer_action", {}), ("fault_mode", []), ("depth", True)])
def test_attempt_fields_are_strict(tmp_path, field, value):
    data = case_data()
    data["attempts"][0][field] = value
    (tmp_path / "case.json").write_text(json.dumps(data))
    with pytest.raises(LabError):
        auth_laboratory.load_auth_cases(tmp_path)


def test_case_loader_rejects_commands_duplicate_keys_symlinks_and_ids(tmp_path):
    data = case_data()
    data["server_command"] = ["sh", "-c", "unsafe"]
    path = tmp_path / "case.json"
    path.write_text(json.dumps(data))
    with pytest.raises(LabError):
        auth_laboratory.load_auth_cases(path)
    path.write_text('{"schema_version":"first","schema_version":"second"}')
    with pytest.raises(LabError):
        auth_laboratory.load_auth_cases(path)
    path.write_text(json.dumps(case_data()))
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(LabError):
        auth_laboratory.load_auth_cases(link)
    link.unlink()
    (tmp_path / "duplicate.json").write_text(path.read_text())
    with pytest.raises(LabError, match="Duplicate"):
        auth_laboratory.load_auth_cases(tmp_path)


def test_unsigned_entrypoint_is_disabled():
    case = auth_laboratory.load_auth_cases(PLUGIN_ROOT / "auth_cases/delegated-control.json")[0]
    with pytest.raises(LabError, match="signed"):
        auth_laboratory.run_auth_case(case)


@pytest.mark.parametrize("filename,decision,outcome", [
    ("auth-authorized.json", "allowed", "pass"),
    ("auth-denied.json", "denied", "pass"),
    ("auth-inconclusive.json", "denied", "inconclusive"),
])
def test_documented_reports_match_schema(filename, decision, outcome):
    schema = json.loads((PLUGIN_ROOT / "schemas/auth-report.schema.json").read_text())
    report = json.loads((PLUGIN_ROOT / "examples" / filename).read_text())
    jsonschema.validate(report, schema)
    result = report["results"][0]
    assert result["outcome"] == outcome
    assert result["observations"][0]["target"]["decision"] == decision
