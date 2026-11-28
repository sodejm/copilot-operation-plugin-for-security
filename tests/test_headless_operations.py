from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from threading import Event

import pytest

from cops.operations.catalog import declarations, validate_catalog
from cops.operations.contracts import MAX_BYTES, decode, encode
from cops.operations.service import OperationService

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "plugins/detection-hunting/soc-investigation-workbench"


def call(operation, arguments, **kwargs):
    return OperationService(**kwargs).invoke(
        {
            "schema_version": "cops.operation-request/v1",
            "operation_id": operation,
            "request_id": "test-01",
            "arguments": arguments,
        }
    )


def test_discovery_is_inert(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("discovery executed a payload")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(OperationService, "_dispatch", forbidden)
    catalog = declarations()
    validate_catalog(catalog)
    assert len(catalog) == 28
    assert all(
        item["effects"] == {"network": False, "durable_writes": False, "executes_samples": False}
        for item in catalog
        if item["operation_id"].startswith(("cops.work.", "cops.soc.", "cops.assess."))
    )
    assert all(not item["effects"]["network"] and not item["effects"]["executes_samples"] for item in catalog)
    assert all(item["input_schema"]["additionalProperties"] is False for item in catalog)


def test_catalog_rejects_missing_binding_and_duplicate():
    catalog = declarations()
    with pytest.raises(ValueError):
        validate_catalog(catalog + [catalog[0]])
    broken = copy.deepcopy(catalog)
    broken[0]["implementation"] = "arbitrary.module:run"
    with pytest.raises(ValueError):
        validate_catalog(broken)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b"[]", b"{} trailing", b"\xff"])
def test_strict_json(raw):
    with pytest.raises(ValueError):
        decode(raw)


def test_size_and_depth_bounds():
    with pytest.raises(ValueError):
        decode(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        decode(("{" + '"x":[' * 100 + "0" + "]" * 100 + "}").encode())


def test_lightweight_exploration_and_escalation():
    result = call("cops.work.request", {"task": "Inspect this sample"})
    assert result["status"] == "succeeded"
    assert result["result"]["execution_authorized"] is False
    assert result["result"]["request"]["task"] == "Inspect this sample"
    request = result["result"]["request"]
    note = call("cops.work.note", {"request": request, "note": "Possibly benign; try another parser"})
    assert note["status"] == "succeeded"
    proposal = call("cops.work.escalate", {"request": note["result"]["request"], "action": "Run in a lab"})
    assert proposal["status"] == "blocked"
    assert proposal["result"]["execution_authorized"] is False
    assert proposal["result"]["proposal"]["authority"] == "none"


def test_unknown_authority_and_path_arguments_rejected():
    assert call("os.system", {})["status"] == "blocked"
    assert call("cops.work.request", {"task": "x", "approved": True})["status"] == "failed"
    assert call("cops.soc.validate", {"case": "/etc/passwd"})["status"] == "failed"
    assert call("cops.soc.report", {"case": {}, "output": "/tmp/result"})["status"] == "failed"
    assert call("cops.work.request", {})["status"] == "needs_input"


def test_cancellation_and_retry_are_side_effect_free():
    cancelled = Event()
    cancelled.set()
    service = OperationService()
    request = {
        "schema_version": "cops.operation-request/v1",
        "operation_id": "cops.work.request",
        "arguments": {"task": "try a sample"},
    }
    assert service.invoke(request, cancelled=cancelled)["error"]["code"] == "cancelled"
    cancelled.clear()
    assert service.invoke(request, cancelled=cancelled) == service.invoke(request, cancelled=cancelled)


def test_missing_soc_dependency_is_blocked(tmp_path):
    assert call("cops.soc.validate", {"case": {}}, soc_root=tmp_path)["status"] == "blocked"


def test_cancellation_after_dispatch_suppresses_result(monkeypatch):
    cancelled = Event()
    service = OperationService()

    def dispatch(*_args):
        cancelled.set()
        return {"observation": "must_not_be_published_after_cancellation"}

    monkeypatch.setattr(service, "_dispatch", dispatch)
    result = service.invoke(
        {
            "schema_version": "cops.operation-request/v1",
            "operation_id": "cops.work.request",
            "arguments": {"task": "sample"},
        },
        cancelled=cancelled,
    )
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "cancelled"
    assert "must_not_be_published" not in str(result)


def test_unexpected_runtime_error_never_echoes_evidence(monkeypatch):
    def fail(*_args):
        raise RuntimeError("private_evidence_marker")

    monkeypatch.setattr(OperationService, "_dispatch", fail)
    result = call("cops.work.request", {"task": "sample"})
    assert result["error"]["code"] == "internal_error"
    assert "private_evidence_marker" not in str(result)


def test_soc_validate_next_report_revise_and_import():
    case = json.loads((SOC / "examples/case.json").read_text())
    original = copy.deepcopy(case)
    assert call("cops.soc.validate", {"case": case})["status"] == "succeeded"
    next_result = call("cops.soc.next", {"case": case})
    assert next_result["status"] == "succeeded"
    assert call("cops.soc.report", {"case": case})["status"] == "succeeded"
    revised = call("cops.soc.revise", {"case": case, "steps": case["steps"]})
    assert revised["status"] == "succeeded"
    assert revised["result"]["case"] == case
    assert call("cops.soc.import", {"case": case, "observation": {}})["status"] == "failed"
    assert case == original


def test_soc_positive_handoff_import_and_resume():
    case = json.loads((SOC / "examples/case.json").read_text())
    observation = json.loads((SOC / "examples/signin-result.json").read_text())
    handoff = call("cops.soc.handoff", {"case": case, "step_id": "signin"})
    assert handoff["status"] == "succeeded"
    assert handoff["result"]["step_id"] == "signin"
    assert handoff["result"]["canonical_skills"]
    imported = call("cops.soc.import", {"case": case, "observation": observation})
    assert imported["status"] == "succeeded"
    snapshot = imported["result"]["case"]
    assert snapshot["results"][0]["step_id"] == "signin"
    duplicate = call("cops.soc.import", {"case": snapshot, "observation": observation})
    assert duplicate == imported
    report = call("cops.soc.report", {"case": snapshot})
    assert report["result"]["completed_steps"] == ["signin"]
    invalid_revision = call("cops.soc.revise", {"case": snapshot, "steps": []})
    assert invalid_revision["status"] == "failed"
    assert snapshot["results"][0]["step_id"] == "signin"


FIXTURE = json.loads((ROOT / "tests/fixtures/artifact_assessment_cases_v1.json").read_text())


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[item["id"] for item in FIXTURE["cases"]])
def test_all_assessment_operations_preserve_expected_findings(case):
    result = call("cops.assess." + case["capability"], {"artifacts": case["artifacts"], "as_of": FIXTURE["as_of"]})
    assert result["status"] == "succeeded"
    assert sorted(result["result"]["finding_codes"].values()) == sorted(case["expected_codes"])
    assert result["result"]["assessment_mode"] == "offline"


def test_assessment_is_real_and_does_not_execute_sample():
    result = call(
        "cops.assess.malware_static",
        {
            "artifacts": [{"artifact_id": "sample", "kind": "script", "content": "Write-Host hello"}],
            "as_of": "2026-10-24T00:00:00Z",
        },
    )
    assert result["status"] == "succeeded"
    assert result["result"]["schema_version"] == "cops.artifact-assessment/v1"


def test_cli_equivalence_and_redacted_errors():
    request = {
        "schema_version": "cops.operation-request/v1",
        "operation_id": "cops.work.request",
        "request_id": "cli-01",
        "arguments": {"task": "inspect one sample"},
    }
    process = subprocess.run(
        [sys.executable, "-B", "-m", "cops", "tools", "invoke", "--request", "-"],
        cwd=ROOT,
        input=encode(request),
        capture_output=True,
        timeout=20,
    )
    assert process.returncode == 0, process.stderr
    assert decode(process.stdout) == OperationService().invoke(request)
    bad = subprocess.run(
        [sys.executable, "-B", "-m", "cops", "tools", "invoke", "--request", "-"],
        cwd=ROOT,
        input=b'{"secret":"private_marker",',
        capture_output=True,
        timeout=20,
    )
    assert bad.returncode != 0
    assert b"private_marker" not in bad.stdout + bad.stderr
