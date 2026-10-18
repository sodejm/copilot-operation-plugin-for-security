from __future__ import annotations

from pathlib import Path
import hashlib
import json
import shutil
import sys

import pytest

from cops.laboratory import integrated_lab, service_lab, service_supply_chain, workflow_lab
from cops.laboratory.acceptance_cases import ACCEPTANCE_CASE_IDS, INTEGRATED_WORKFLOW_IDS
from cops.laboratory.service_lab import IsolationProbe
from scripts import check_laboratory


def _probe(*, verified: bool) -> IsolationProbe:
    return IsolationProbe(
        verified=verified,
        mechanism="test-verified-boundary" if verified else "loopback-only",
        blocker=None if verified else "verified network isolation is unavailable",
        evidence=("unit-test probe result",),
    )


def _install_probe(monkeypatch: pytest.MonkeyPatch, probe: IsolationProbe) -> None:
    monkeypatch.setattr(check_laboratory, "probe_isolated_runtime", lambda: probe)
    monkeypatch.setattr(service_lab, "probe_isolated_runtime", lambda: probe)
    monkeypatch.setattr(workflow_lab, "probe_isolated_runtime", lambda: probe)
    monkeypatch.setattr(integrated_lab, "probe_isolated_runtime", lambda: probe)
    # These tests exercise gate aggregation; real parser acceptance runs in Linux.
    monkeypatch.setattr(check_laboratory, "_evtx_case", lambda: {"failures": [], "metrics": {"unit_stub": True}})


@pytest.fixture
def reviewed_test_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Supply the test operator's Git pin without creating a runtime prerequisite."""
    executable = shutil.which("git")
    assert executable is not None, "portable laboratory tests require Git"
    pin = hashlib.sha256(Path(executable).resolve().read_bytes()).hexdigest()
    monkeypatch.setattr(integrated_lab, "_runtime_git_pin", lambda: pin)


def _expected_installer_failures(available: bool) -> list[str]:
    if available:
        return []
    failures = [
        "pinned supply-chain installer is unavailable or acceptance is incomplete",
        "synthetic dependency was not installed from the reviewed source",
        "installed dependency service activity or cleanup is incomplete",
        "installed dependency changed the permitted query",
        "installed dependency injection correction differs",
        "pinned dependency advisory disagrees with runtime correction",
        "missing dependency evidence did not remain unknown",
        "supply-chain hash_mismatch_rejected is incomplete",
        "supply-chain tampered_install_absent is incomplete",
        "supply-chain disposable_root_removed is incomplete",
    ]
    return [f"{case}: {failure}" for case in ("service-vulnerable", "service-corrected") for failure in failures]


def test_gate_runs_all_functional_evidence_then_blocks_without_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reviewed_test_git: None,
) -> None:
    _install_probe(monkeypatch, _probe(verified=False))
    installer_available = service_supply_chain.prerequisite_status()["available"]

    exit_code, summary = check_laboratory.run_acceptance_gate(tmp_path)

    assert exit_code == (2 if installer_available else 1), summary["failures"]
    assert summary["status"] == ("blocked" if installer_available else "failed")
    assert summary["blockers"] == ["verified network isolation is unavailable"]
    assert summary["failures"] == _expected_installer_failures(installer_available)
    assert summary["strict_preflight"]["passed"] is True
    assert summary["strict_preflight"]["state_created"] is False
    assert summary["summary"] == {
        "cases_passed": len(ACCEPTANCE_CASE_IDS) - (0 if installer_available else 2),
        "cases_total": len(ACCEPTANCE_CASE_IDS),
        "functional_evidence_only": True,
    }
    cases = {case["name"]: case for case in summary["cases"]}
    assert cases["offline-playback"]["metrics"] == {"fixtures": 4, "telemetry": 8, "alerts": 4}
    assert cases["service-vulnerable"]["metrics"]["lateral_status"] == 200
    assert cases["service-corrected"]["metrics"]["lateral_status"] == 403
    assert cases["workflow-success"]["metrics"]["status"] == "success"
    assert cases["workflow-failure"]["metrics"]["status"] == "partial_failure"
    assert cases["workflow-cancellation"]["metrics"]["status"] == "cancelled"
    assert cases["workflow-cancellation"]["metrics"]["telemetry"] == 2
    assert cases["workflow-cancellation"]["metrics"]["alerts"] == 0
    assert set(cases) == set(ACCEPTANCE_CASE_IDS)
    for workflow_id in INTEGRATED_WORKFLOW_IDS:
        metrics = cases["integrated-" + workflow_id]["metrics"]
        assert metrics["status"] == "success"
        assert metrics["restored"] and metrics["services_stopped"]
        assert metrics["authorizations_consumed"] == len(integrated_lab.WORKFLOW_STAGES[workflow_id])
    for name, case in cases.items():
        assert case["passed"] is (installer_available or name not in ("service-vulnerable", "service-corrected"))


@pytest.mark.parametrize("force_unavailable_installer", [False, True])
def test_gate_can_pass_only_when_probe_and_runtime_reports_verify_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reviewed_test_git: None,
    force_unavailable_installer: bool,
) -> None:
    _install_probe(monkeypatch, _probe(verified=True))
    if force_unavailable_installer:
        monkeypatch.setattr(service_supply_chain.importlib.metadata, "version", lambda _: "unreviewed-version")
    installer_available = service_supply_chain.prerequisite_status()["available"]

    exit_code, summary = check_laboratory.run_acceptance_gate(tmp_path)

    assert exit_code == (0 if installer_available else 1), summary["failures"]
    assert summary["status"] == ("passed" if installer_available else "failed")
    assert summary["blockers"] == []
    assert summary["failures"] == _expected_installer_failures(installer_available)
    assert summary["isolation"]["verified"] is True
    assert summary["summary"] == {
        "cases_passed": len(ACCEPTANCE_CASE_IDS) - (0 if installer_available else 2),
        "cases_total": len(ACCEPTANCE_CASE_IDS),
        "functional_evidence_only": False,
    }


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("2026-10-15T12:00:00Z", True),
        ("2026-10-15T12:00:00+00:00", True),
        ("2026-10-15T12:00:00", False),
        ("not-a-timestamp", False),
        (None, False),
    ],
)
def test_gate_requires_timezone_aware_rfc3339_timestamps(value: object, valid: bool) -> None:
    assert check_laboratory._valid_timestamp(value) is valid


def test_required_evtx_case_cannot_skip_missing_parser(monkeypatch) -> None:
    def unavailable(*args, **kwargs):
        raise check_laboratory.EvtxImportError("parser_unavailable")
    monkeypatch.setattr(check_laboratory, "import_evtx", unavailable)
    result = check_laboratory._run_case("binary-evtx", check_laboratory._evtx_case)
    assert result["passed"] is False
    assert result["failures"] == ["execution raised EvtxImportError"]


def test_container_child_requires_kernel_evidence_before_creating_state(monkeypatch, tmp_path, capsys) -> None:
    state = tmp_path / "must-not-exist"
    _install_probe(monkeypatch, _probe(verified=False))
    monkeypatch.setattr(sys, "argv", ["check_laboratory.py", "--container-child", "--state-dir", str(state)])
    assert check_laboratory.main() == 2
    assert not state.exists()
    assert json.loads(capsys.readouterr().out)["summary"]["cases_passed"] == 0


@pytest.mark.parametrize("arguments", [
    ["--runtime", "docker"],
    ["--runtime", "process", "--image", "sha256:" + "a" * 64],
    ["--runtime", "docker", "--image", "sha256:" + "a" * 64, "--container-child"],
    ["--timeout", "601"],
    ["--kubernetes-timeout", "179"],
])
def test_invalid_cli_options_fail_before_state_creation(monkeypatch, tmp_path, arguments) -> None:
    state = tmp_path / "must-not-exist"
    monkeypatch.setattr(sys, "argv", ["check_laboratory.py", "--state-dir", str(state), *arguments])
    with pytest.raises(SystemExit) as exc:
        check_laboratory.main()
    assert exc.value.code == 2
    assert not state.exists()


def test_docker_cli_forwards_immutable_image_and_deadline(monkeypatch, capsys) -> None:
    image = "sha256:" + "a" * 64
    calls = []
    def launch(repository, *, image, timeout):
        calls.append((repository, image, timeout))
        return 2, {"status": "blocked", "blockers": ["runtime unavailable"]}
    monkeypatch.setattr(check_laboratory, "run_container_acceptance", launch)
    monkeypatch.setattr(sys, "argv", ["check_laboratory.py", "--runtime", "docker", "--image", image, "--timeout", "60"])
    assert check_laboratory.main() == 2
    assert calls == [(check_laboratory.ROOT, image, 60)]
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def _component_reports():
    service = {"status": "passed", "failures": [], "blockers": [], "cases": [
        {"name": name, "passed": True} for name in ACCEPTANCE_CASE_IDS]}
    kubernetes = {"status": "passed", "isolation": {"verified": True}, "cleanup": {"verified": True},
                  "cases": [{"mode": mode, "workflow_status": status, "passed": True, "namespace_removed": True}
                            for mode, status in (("success", "success"), ("failure", "partial_failure"), ("cancellation", "cancelled"))]}
    return service, kubernetes


def test_complete_gate_requires_both_boundaries_and_every_case():
    service, kubernetes = _component_reports()
    code, result = check_laboratory.complete_gate(service, kubernetes)
    assert code == 0
    assert result["summary"] == {"cases_passed": 13, "cases_total": 13, "functional_evidence_only": False}


@pytest.mark.parametrize("mutation", ["isolation", "cleanup", "missing_case", "duplicate_case", "wrong_status", "namespace"])
def test_incomplete_kubernetes_evidence_cannot_pass(mutation):
    service, kubernetes = _component_reports()
    if mutation in ("isolation", "cleanup"):
        kubernetes[mutation]["verified"] = False
    elif mutation == "missing_case":
        kubernetes["cases"].pop()
    elif mutation == "duplicate_case":
        kubernetes["cases"][2] = kubernetes["cases"][0]
    elif mutation == "wrong_status":
        kubernetes["cases"][1]["workflow_status"] = "success"
    else:
        kubernetes["cases"][0]["namespace_removed"] = False
    code, result = check_laboratory.complete_gate(service, kubernetes)
    assert code == 1 and result["status"] == "failed"
    assert result["failures"] == ["Kubernetes lifecycle evidence is incomplete"]


def test_missing_kubernetes_prerequisite_leaves_complete_gate_blocked():
    service, _ = _component_reports()
    code, result = check_laboratory.complete_gate(service, {"status": "blocked", "blockers": ["pinned image absent"]})
    assert code == 2 and result["summary"]["cases_total"] == 13
    assert result["summary"]["cases_passed"] == 12
    assert result["blockers"] == ["pinned image absent"]


@pytest.mark.parametrize("mutation", ["duplicate", "failed", "blocker", "missing"])
def test_service_evidence_cannot_claim_pass_with_incomplete_cases(mutation):
    service, kubernetes = _component_reports()
    if mutation == "duplicate":
        service["cases"].append(service["cases"][0])
    elif mutation == "failed":
        service["cases"][0]["passed"] = False
    elif mutation == "blocker":
        service["blockers"].append("unavailable prerequisite")
    else:
        service["cases"].pop()
    code, result = check_laboratory.complete_gate(service, kubernetes)
    assert code == 1 and result["status"] == "failed"
    assert "Service laboratory evidence is incomplete" in result["failures"]
