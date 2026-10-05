"""Unit and negative fixture tests for capability reconciliation and truth-in-advertising."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import pytest

from cops.capabilities import (
    CapabilityTruthError,
    audit_capabilities,
    build_capability_registry,
    generate_capability_matrix_markdown,
)
from cops.cli import (
    command_capabilities_audit,
    command_capabilities_list,
    command_capabilities_matrix,
)

ROOT = Path(__file__).resolve().parents[1]


def test_build_and_audit_clean_pass():
    """Verify clean pass of capability building and auditing."""
    reg = build_capability_registry(ROOT)
    assert reg["schema_version"] == "cops.capabilities/v1"
    assert len(reg["capabilities"]) == 69

    summary = audit_capabilities(ROOT, registry_data=reg)
    assert summary["status"] == "valid"
    assert summary["total_capabilities"] == 69
    assert summary["by_kind"] == {"plugin": 14, "specialist": 18, "scenario": 37}
    assert summary["by_mode"]["live-validated"] == 0


def test_negative_fixture_unverified_live_claim():
    """Negative test: asserting that claiming live-validated without evidence fails."""
    reg = build_capability_registry(ROOT)
    bad_reg = copy.deepcopy(reg)
    bad_reg["capabilities"][0]["mode"] = "live-validated"
    bad_reg["capabilities"][0]["live_evidence_verified"] = False

    with pytest.raises(CapabilityTruthError) as exc_info:
        audit_capabilities(ROOT, registry_data=bad_reg)
    assert exc_info.value.code == "unverified_live_claim"


def test_negative_fixture_missing_truth_boundaries():
    """Negative test: asserting that empty truth boundaries fail audit."""
    reg = build_capability_registry(ROOT)
    bad_reg = copy.deepcopy(reg)
    bad_reg["capabilities"][5]["truth_boundaries"] = "   "

    with pytest.raises(CapabilityTruthError) as exc_info:
        audit_capabilities(ROOT, registry_data=bad_reg)
    assert exc_info.value.code == "missing_truth_boundary"


def test_negative_fixture_catalog_descriptive_drift():
    """Negative test: asserting that count mismatch raises catalog_descriptive_drift."""
    reg = build_capability_registry(ROOT)
    bad_reg = copy.deepcopy(reg)
    bad_reg["summary"]["by_kind"]["plugin"] = 12

    with pytest.raises(CapabilityTruthError) as exc_info:
        audit_capabilities(ROOT, registry_data=bad_reg)
    assert exc_info.value.code == "catalog_descriptive_drift"


def test_capability_cli_commands(capsys):
    """Verify CLI capabilities commands."""
    assert command_capabilities_list(root=ROOT) == 0
    captured = capsys.readouterr().out
    assert "Reconciled Capabilities (69)" in captured
    assert "security-logging-advisor" in captured

    assert command_capabilities_list(mode="laboratory", as_json=True, root=ROOT) == 0
    lab_json = json.loads(capsys.readouterr().out)
    assert len(lab_json) >= 15
    for c in lab_json:
        assert c["mode"] == "laboratory"

    assert command_capabilities_audit(check=True, root=ROOT) == 0
    audit_out = capsys.readouterr().out
    assert "Capability Truth-in-Advertising Audit Passed" in audit_out

    assert command_capabilities_matrix(root=ROOT) == 0
    matrix_out = capsys.readouterr().out
    assert "## Capability Truth-in-Advertising Mode Matrix" in matrix_out


def test_generate_capability_matrix_markdown():
    """Verify Markdown capability matrix rendering."""
    reg = build_capability_registry(ROOT)
    md = generate_capability_matrix_markdown(reg)
    assert "## Capability Truth-in-Advertising Mode Matrix" in md
    assert "| `security-logging-advisor` |" in md
    assert "| `cops-pentest-specialist` |" in md
    assert "| `COPS-E01.01-S01` |" in md
