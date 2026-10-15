from __future__ import annotations

from pathlib import Path
import json
import sys

import pytest

from cops.laboratory import integrated_lab, service_lab, workflow_lab
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


def test_gate_runs_all_functional_evidence_then_blocks_without_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_probe(monkeypatch, _probe(verified=False))

    exit_code, summary = check_laboratory.run_acceptance_gate(tmp_path)

    assert exit_code == 2
    assert summary["status"] == "blocked"
    assert summary["blockers"] == ["verified network isolation is unavailable"]
    assert summary["failures"] == []
    assert summary["strict_preflight"]["passed"] is True
    assert summary["strict_preflight"]["state_created"] is False
    assert summary["summary"] == {
        "cases_passed": len(ACCEPTANCE_CASE_IDS),
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
    assert all(case["passed"] is True for case in cases.values())


def test_gate_can_pass_only_when_probe_and_runtime_reports_verify_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_probe(monkeypatch, _probe(verified=True))

    exit_code, summary = check_laboratory.run_acceptance_gate(tmp_path)

    assert exit_code == 0
    assert summary["status"] == "passed"
    assert summary["blockers"] == []
    assert summary["failures"] == []
    assert summary["isolation"]["verified"] is True
    assert summary["summary"] == {
        "cases_passed": len(ACCEPTANCE_CASE_IDS),
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
