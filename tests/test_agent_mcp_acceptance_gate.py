"""The repository gate must not silently omit agent/MCP worker acceptance."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import check_agent_mcp_acceptance as gate


def _report(path: Path, *, missing: bool = False, outcome: str | None = None) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for name in sorted(gate.REQUIRED_CASES)[int(missing) :]:
        case = ET.SubElement(suite, "testcase", name=name)
        if outcome:
            ET.SubElement(case, outcome)
    ET.ElementTree(root).write(path, encoding="utf-8")


def _child(monkeypatch, *, missing=False, outcome=None, returncode=0, report=True):
    monkeypatch.setattr(gate.Path, "is_file", lambda self: True)

    def run(command, **kwargs):
        assert command[:3] == [sys.executable, "-m", "pytest"]
        assert command[3 : 3 + len(gate.TEST_FILES)] == [str(path) for path in gate.TEST_FILES]
        assert kwargs["cwd"] == gate.ROOT
        assert kwargs["timeout"] == gate.TIMEOUT_SECONDS
        destination = Path(command[command.index("--junitxml") + 1])
        if report:
            _report(destination, missing=missing, outcome=outcome)
        return subprocess.CompletedProcess(command, returncode)

    monkeypatch.setattr(gate.subprocess, "run", run)


def test_complete_acceptance_reports_narrow_local_scope(monkeypatch, capsys):
    _child(monkeypatch)
    assert gate.main() == 0
    output = capsys.readouterr().out
    assert '"scope": "disposable-stdio-only"' in output
    assert '"hosted_provider_claims": false' in output
    assert '"isolation_qualified": false' in output
    assert '"network_requests": 0' in output


@pytest.mark.parametrize("outcome", ["skipped", "failure", "error"])
def test_skips_or_failed_cases_are_not_acceptance(monkeypatch, outcome):
    _child(monkeypatch, outcome=outcome)
    assert gate.main() == 1


def test_missing_required_case_fails(monkeypatch):
    _child(monkeypatch, missing=True)
    assert gate.main() == 1


def test_missing_test_file_fails_before_pytest(monkeypatch):
    missing = gate.TEST_FILES[0]
    monkeypatch.setattr(gate.Path, "is_file", lambda self: self != missing)
    monkeypatch.setattr(gate.subprocess, "run", lambda *args, **kwargs: pytest.fail("pytest started"))
    assert gate.main() == 1


@pytest.mark.parametrize("returncode", [1, 2, 4, 5])
def test_child_failure_or_no_collection_propagates(monkeypatch, returncode):
    _child(monkeypatch, returncode=returncode)
    assert gate.main() == 1


@pytest.mark.parametrize("error", [OSError("unavailable"), subprocess.TimeoutExpired("pytest", 180)])
def test_unavailable_child_or_timeout_fails(monkeypatch, error):
    monkeypatch.setattr(gate.Path, "is_file", lambda self: True)

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


def test_repository_aggregator_requires_agent_mcp_acceptance(monkeypatch):
    agent_scripts = gate.ROOT / "scripts/agent"
    monkeypatch.syspath_prepend(str(agent_scripts))
    spec = importlib.util.spec_from_file_location("repository_check_for_agent_mcp_test", agent_scripts / "check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "check_prerequisites", lambda root: True)
    monkeypatch.setattr(module, "validate_python", lambda: True)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return command != [sys.executable, "scripts/check_agent_mcp_acceptance.py"]

    monkeypatch.setattr(module, "run", run)
    assert module.main() == 1
    assert commands.count([sys.executable, "scripts/check_agent_mcp_acceptance.py"]) == 1
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: True)
    assert module.main() == 0
