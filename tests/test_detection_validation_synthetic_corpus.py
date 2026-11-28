"""Persisted offline detection-validation corpus through the public command."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops.contracts.validation import validate_contract
from cops.reporting.assessment import ReportError
from cops.reporting.cli import command_engagement_detection_validate
from cops.reporting.detection import build_detection_report

ROOT = Path(__file__).resolve().parents[1]
VALID_FIXTURE = ROOT / "cops/contracts/fixtures/valid_detection_validation_outcomes.json"
INVALID_CROSS_TENANT_FIXTURE = ROOT / "cops/contracts/fixtures/invalid_detection_validation_cross_tenant.json"
EXPECTED_STATUSES = {
    "act-detected": "detected",
    "act-missed": "missed",
    "act-ambiguous": "ambiguous",
    "act-unavailable": "unavailable",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _statuses(report: dict) -> dict[str, str]:
    return {row["action_id"]: row["status"] for row in report["checks"]}


def test_persisted_synthetic_corpus_covers_all_outcomes() -> None:
    report = build_detection_report(_load(VALID_FIXTURE))

    assert validate_contract(report, "detection_validation_report") == report
    assert _statuses(report) == EXPECTED_STATUSES
    rows = {row["action_id"]: row for row in report["checks"]}
    assert any(signal["kind"] == "alert" and signal["in_window"] for signal in rows["act-detected"]["observed_signals"])
    assert rows["act-missed"]["search_evidence"]["result_count"] == 0
    assert rows["act-missed"]["search_evidence"]["covers_expanded_window"] is True
    assert any(
        signal["kind"] == "alert" and signal["in_window"] is False
        for signal in rows["act-ambiguous"]["observed_signals"]
    )
    assert rows["act-ambiguous"]["search_evidence"] is None
    assert rows["act-unavailable"]["observed_signals"] == []
    assert "authorized action" in rows["act-unavailable"]["next_action"]
    assert "Source authenticity" in report["source_notice"]
    assert "provider-wide search completeness" in report["source_notice"]


def test_public_command_classifies_persisted_synthetic_corpus(
    tmp_path: Path,
) -> None:
    json_output = tmp_path / "report.json"
    markdown_output = tmp_path / "report.md"

    assert (
        command_engagement_detection_validate(
            SimpleNamespace(
                input=VALID_FIXTURE,
                json_output=json_output,
                markdown_output=markdown_output,
            )
        )
        == 0
    )
    report = _load(json_output)
    assert _statuses(report) == EXPECTED_STATUSES
    markdown = markdown_output.read_text(encoding="utf-8")
    for action_id, status in EXPECTED_STATUSES.items():
        assert action_id in markdown
        assert status in markdown
    assert "does not establish prevention" in markdown


def test_persisted_cross_tenant_corpus_is_rejected() -> None:
    with pytest.raises(ReportError, match="cross-tenant evidence"):
        build_detection_report(_load(INVALID_CROSS_TENANT_FIXTURE))
