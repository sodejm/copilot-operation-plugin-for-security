"""The development acceptance gate must never silently omit local-service cases."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import check_web_api_acceptance as gate


def _report(path: Path, *, missing: bool = False, outcome: str | None = None) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for name in sorted(gate.REQUIRED_CASES)[int(missing) :]:
        case = ET.SubElement(suite, "testcase", name=name)
        if outcome:
            ET.SubElement(case, outcome)
    ET.ElementTree(root).write(path, encoding="utf-8")


def _child(monkeypatch, *, missing=False, outcome=None, returncode=0, report=True):
    def run(command, **kwargs):
        assert command[:3] == [sys.executable, "-m", "pytest"]
        assert command[3] == str(gate.TEST_FILE)
        assert kwargs["cwd"] == gate.ROOT
        assert kwargs["timeout"] == gate.TIMEOUT_SECONDS
        destination = Path(command[command.index("--junitxml") + 1])
        if report:
            _report(destination, missing=missing, outcome=outcome)
        return subprocess.CompletedProcess(command, returncode)

    monkeypatch.setattr(gate.subprocess, "run", run)


def test_complete_acceptance_passes_without_claiming_isolation(monkeypatch, capsys):
    _child(monkeypatch)
    assert gate.main() == 0
    output = capsys.readouterr().out
    assert '"scope": "loopback-only"' in output
    assert '"isolation_qualified": false' in output


@pytest.mark.parametrize("outcome", ["skipped", "failure", "error"])
def test_skips_or_failed_cases_are_not_acceptance(monkeypatch, outcome):
    _child(monkeypatch, outcome=outcome)
    assert gate.main() == 1


def test_missing_required_case_fails(monkeypatch):
    _child(monkeypatch, missing=True)
    assert gate.main() == 1


def test_missing_report_fails(monkeypatch):
    _child(monkeypatch, report=False)
    assert gate.main() == 1


@pytest.mark.parametrize("returncode", [1, 2, 4, 5])
def test_child_failure_or_no_collection_propagates(monkeypatch, returncode):
    _child(monkeypatch, returncode=returncode)
    assert gate.main() == 1


@pytest.mark.parametrize("error", [OSError("unavailable"), subprocess.TimeoutExpired("pytest", 120)])
def test_unavailable_child_or_timeout_fails(monkeypatch, error):
    def run(*args, **kwargs):
        raise error

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main() == 1


@pytest.mark.parametrize("document", ["", "<testsuites/>", "not XML", "<testsuites><testcase/>"])
def test_empty_or_invalid_report_fails(tmp_path, document):
    path = tmp_path / "report.xml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError, match="acceptance"):
        gate.validate_report(path)


def test_repository_aggregator_requires_acceptance_success(monkeypatch):
    agent_scripts = gate.ROOT / "scripts/agent"
    monkeypatch.syspath_prepend(str(agent_scripts))
    spec = importlib.util.spec_from_file_location("repository_check_for_api_test", agent_scripts / "check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "check_prerequisites", lambda root: True)
    monkeypatch.setattr(module, "validate_python", lambda: True)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return command != [sys.executable, "scripts/check_web_api_acceptance.py"]

    monkeypatch.setattr(module, "run", run)
    assert module.main() == 1
    assert commands.count([sys.executable, "scripts/check_web_api_acceptance.py"]) == 1
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: True)
    assert module.main() == 0


def test_actual_pytest_failure_is_not_swallowed(monkeypatch, tmp_path):
    failing = tmp_path / "test_rejected_acceptance.py"
    failing.write_text("def test_acceptance_canary():\n    assert False, 'acceptance-canary'\n", encoding="utf-8")
    monkeypatch.setattr(gate, "TEST_FILE", failing)
    monkeypatch.setattr(gate, "WS_TEST_FILE", failing)
    assert gate.main() == 1


def test_offline_package_gate_does_not_import_development_dependencies(tmp_path):
    for module in ("pytest", "cryptography", "jsonschema"):
        (tmp_path / f"{module}.py").write_text(
            "raise RuntimeError('offline gate imported a development dependency')\n", encoding="utf-8"
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tmp_path)
    script = gate.ROOT / "plugins/offensive-security/web-api-assessment-workbench/scripts/validate-package.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=gate.ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"network_requests": 0' in result.stdout
