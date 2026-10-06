# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Comprehensive unit tests for Telemetry Proof Pack."""

import json
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from proofpack.cli import load_evidence_files
from proofpack.cli import main as cli_main
from proofpack.correlator import (
    correlate_pipeline_evidence,
)
from proofpack.models import (
    ProofError,
    RunManifest,
)
from proofpack.redaction import redact_dict
from proofpack.reporting import (
    render_json_report,
    render_markdown_report,
)


@pytest.fixture
def fixtures_dir() -> Path:
    return PLUGIN_ROOT / "fixtures"


@pytest.fixture
def splunk_manifest(fixtures_dir: Path) -> RunManifest:
    p = fixtures_dir / "routes" / "cribl-splunk-route" / "manifest.json"
    return RunManifest.from_dict(json.loads(p.read_text(encoding="utf-8")))


@pytest.fixture
def sentinel_manifest(fixtures_dir: Path) -> RunManifest:
    p = fixtures_dir / "routes" / "cribl-sentinel-route" / "manifest.json"
    return RunManifest.from_dict(json.loads(p.read_text(encoding="utf-8")))


def test_manifest_validation(splunk_manifest: RunManifest, sentinel_manifest: RunManifest):
    """Test loading and validation of run manifests."""
    assert splunk_manifest.run_id == "RUN-SPLUNK-PROVE-01"
    assert splunk_manifest.synthetic_marker == "SYN-SPLUNK-TRACE-101"
    assert splunk_manifest.pipeline_route == "cribl_to_splunk"
    assert splunk_manifest.destination["platform"] == "splunk"

    assert sentinel_manifest.run_id == "RUN-SENTINEL-PROVE-02"
    assert sentinel_manifest.synthetic_marker == "SYN-SENTINEL-TRACE-202"
    assert sentinel_manifest.pipeline_route == "cribl_to_sentinel"
    assert sentinel_manifest.destination["platform"] == "sentinel"


def test_manifest_missing_required_fields():
    """Verify that incomplete manifests raise ProofError."""
    with pytest.raises(ProofError, match="Missing required manifest field"):
        RunManifest.from_dict({"run_id": "RUN-INVALID"})


def test_cribl_to_splunk_full_trace(fixtures_dir: Path, splunk_manifest: RunManifest):
    """Verify end-to-end healthy proof trace for Cribl-to-Splunk route."""
    evidence_dir = fixtures_dir / "routes" / "cribl-splunk-route"
    evidence = load_evidence_files(evidence_dir)
    report = correlate_pipeline_evidence(splunk_manifest, evidence)

    assert report["pipeline_health"] == "healthy"
    assert report["summary"]["total_expected_stages"] == 5
    assert report["summary"]["observed_stages_count"] == 5
    assert report["summary"]["missing_stages_count"] == 0
    assert report["summary"]["unresolved_stages_count"] == 0
    assert report["summary"]["detection_fired"] is True
    assert report["summary"]["total_latency_seconds"] == 60.0
    assert len(report["stages_breakdown"]) == 5


def test_cribl_to_sentinel_full_trace(fixtures_dir: Path, sentinel_manifest: RunManifest):
    """Verify end-to-end healthy proof trace for Cribl-to-Sentinel route."""
    evidence_dir = fixtures_dir / "routes" / "cribl-sentinel-route"
    evidence = load_evidence_files(evidence_dir)
    report = correlate_pipeline_evidence(sentinel_manifest, evidence)

    assert report["pipeline_health"] == "healthy"
    assert report["summary"]["total_expected_stages"] == 5
    assert report["summary"]["observed_stages_count"] == 5
    assert report["summary"]["detection_fired"] is True
    assert report["summary"]["total_latency_seconds"] == 115.0


def test_hec_indexed_rule_missed_degraded_scenario(fixtures_dir: Path):
    """Verify degraded pipeline status when indexed at destination but detection misses."""
    evidence_dir = fixtures_dir / "failures" / "hec-indexed-rule-missed"
    manifest_path = evidence_dir / "manifest.json"
    manifest = RunManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
    evidence = load_evidence_files(evidence_dir)

    report = correlate_pipeline_evidence(manifest, evidence)
    assert report["pipeline_health"] == "degraded"
    assert report["summary"]["detection_fired"] is False
    assert any("Detection rule 'Suspicious PowerShell Execution' ran but did not match" in d for d in report["diagnostics"])


def test_missing_cribl_stage_broken_scenario(fixtures_dir: Path):
    """Verify broken pipeline status when Cribl drops the event."""
    evidence_dir = fixtures_dir / "failures" / "missing-cribl-stage"
    manifest_path = evidence_dir / "manifest.json"
    manifest = RunManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
    evidence = load_evidence_files(evidence_dir)

    report = correlate_pipeline_evidence(manifest, evidence)
    assert report["pipeline_health"] == "broken"
    assert report["summary"]["observed_stages_count"] == 1
    assert any("Cribl Stream pipeline dropped or filtered out" in d for d in report["diagnostics"])


def test_cross_tenant_collision_scenario(fixtures_dir: Path):
    """Verify unresolved source emission when tenant ID collides with foreign tenant."""
    evidence_dir = fixtures_dir / "failures" / "cross-tenant-collision"
    manifest_path = evidence_dir / "manifest.json"
    manifest = RunManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
    evidence = load_evidence_files(evidence_dir)

    report = correlate_pipeline_evidence(manifest, evidence)
    assert report["stages_breakdown"][0]["status"] == "unresolved"
    assert "Cross-tenant collision" in report["stages_breakdown"][0]["details"]["reason"]
    assert report["pipeline_health"] == "broken"


def test_redaction_utility():
    """Verify redaction scrubs secrets while preserving test markers."""
    data = {
        "api_key": "secret-12345",
        "auth_header": "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
        "nested": {
            "password": "SuperSecretPassword123!",
            "marker": "SYN-TEST-MARKER-99",
        },
    }
    redacted = redact_dict(data)
    assert redacted["api_key"] == "[REDACTED]"
    assert "[REDACTED_TOKEN]" in redacted["auth_header"]
    assert redacted["nested"]["password"] == "[REDACTED]"  # noqa: S105 - schema label or operation identifier, not a credential
    assert redacted["nested"]["marker"] == "SYN-TEST-MARKER-99"


def test_reporting_formatters(fixtures_dir: Path, splunk_manifest: RunManifest):
    """Verify Markdown and JSON reporting outputs."""
    evidence_dir = fixtures_dir / "routes" / "cribl-splunk-route"
    evidence = load_evidence_files(evidence_dir)
    report = correlate_pipeline_evidence(splunk_manifest, evidence)

    md = render_markdown_report(report)
    assert "# Telemetry-to-Detection Proof Pack: RUN-SPLUNK-PROVE-01" in md
    assert "HEALTHY (END-TO-END VERIFIED)" in md
    assert "| `source_emission` | OBSERVED |" in md

    json_str = render_json_report(report)
    parsed = json.loads(json_str)
    assert parsed["schema_version"] == "cops.proof-report/v1"
    assert parsed["pipeline_health"] == "healthy"


def test_cli_trace_and_validate(fixtures_dir: Path, capsys):
    """Verify CLI execution for trace and validate commands."""
    route_dir = fixtures_dir / "routes" / "cribl-splunk-route"
    manifest = route_dir / "manifest.json"

    # validate command
    ret = cli_main(["validate", "--manifest", str(manifest)])
    assert ret == 0
    out, _ = capsys.readouterr()
    assert "Validated run manifest: RUN-SPLUNK-PROVE-01" in out

    # trace command
    ret = cli_main(["trace", "--manifest", str(manifest), "--evidence-dir", str(route_dir)])
    assert ret == 0
    out, _ = capsys.readouterr()
    assert "Stage-by-Stage Proof Trace" in out
