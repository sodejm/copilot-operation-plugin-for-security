# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Executable acceptance scenarios for the catalog-driven operator workflow."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cops.catalog import (
    CatalogError,
    plugin_records,
    validate_declared_command,
)
from cops.portable import export_portable_package
from cops.validation import (
    ValidationError,
    generate_marketplaces,
)

scenarios("../../specs/features/portable_operator_workflow.feature")


EXPECTED_PLAYBACK_FIELDS: dict[str, dict[tuple[str, ...], object]] = {
    "security-logging-advisor": {
        ("playback",): "security-logging-advisor",
        ("status",): "passed",
        ("rerun_semantically_equal",): True,
        ("scanned_files_count",): 4,
    },
    "soc-investigation-workbench": {
        ("status",): "passed",
    },
    "sentinel-hunt-workbench": {
        ("schema_version",): "huntwb.playback-summary/v1",
        ("status",): "passed",
        ("rendered_artifact_count",): 12,
        ("rerun_equivalent",): True,
    },
    "attack-path-workbench": {
        ("candidate_paths",): 1,
        ("expected_failure",): True,
        ("quarantined_records",): 1,
        ("rerun_identical",): True,
        ("supported_paths",): 1,
        ("wiz_status",): "blocked_pending_docs",
    },
    "attack-surface-planner": {
        ("playback",): "attack-surface-planner",
        ("status",): "passed",
        ("network_requests",): 0,
        ("failure_path",): "active mode rejected",
        ("rerun_equal",): True,
        ("summary", "unresolved"): 1,
    },
    "kubernetes-assessment-workbench": {
        ("status",): "passed",
        ("mode",): "offline",
        ("cases", "matched", "cluster_identity", "status"): "matched_sanitized_export",
        ("cases", "limited", "cluster_identity", "status"): "unresolved",
        ("cases", "switched", "rejected"): "context_mismatch",
    },
    "ad-assessment-workbench": {
        ("candidate_paths",): 1,
        ("expected_failure",): True,
        ("queries",): 2,
        ("rerun_identical",): True,
    },
    "entra-identity-workbench": {
        ("edges",): 13,
        ("expected_failure",): True,
        ("hypotheses",): 7,
        ("nodes",): 18,
        ("rerun_equivalent",): True,
    },
    "exposure-triage-workbench": {
        ("expected_failure",): True,
        ("investigation_required",): 2,
        ("items",): 7,
        ("p1",): 2,
        ("rerun_equivalent",): True,
    },
    "foundry-agent-harness": {
        ("playback",): "foundry-agent-harness",
        ("status",): "passed",
        ("denied_count",): 6,
        ("scenario_count",): 6,
        ("failure_path",): "scenario missing approval rejected",
        ("rerun_semantically_equal",): True,
    },
    "detection-quality-workbench": {
        ("schema_version",): "cops.detection-quality-playback/v1",
        ("status",): "passed",
        ("evidence_scope",): "labeled_offline_fixture_evaluation_only",
        ("rerun_equivalent",): True,
    },
    "patch-security-review": {
        ("schema",): "cops.patch-security-review-playback/v1",
        ("execution_boundary", "network_calls"): 0,
        ("execution_boundary", "live_integrations_validated"): False,
        ("execution_boundary", "diffs_executed"): False,
        ("malicious", "candidate_count"): 1,
        ("malicious", "validated_finding_count"): 1,
        ("benign", "candidate_count"): 0,
        ("benign", "validated_finding_count"): 0,
    },
    "threat-intelligence-enrichment": {
        ("schema",): "cops.threat-intelligence-playback/v1",
        ("network_mode",): "injected-mock-only",
        ("live_integrations_validated",): False,
        ("microsoft_failure", "status"): "error",
        ("taxii_partial", "status"): "partial",
        ("misp", "fresh_cache", "cache"): "fresh",
        ("misp", "stale_cache", "cache"): "stale",
    },
    "telemetry-proof-pack": {
        ("schema_version",): "cops.telemetry-proof-playback/v1",
        ("status",): "passed",
        ("evidence_scope",): "supplied_offline_fixture_records_only",
        ("rerun_equivalent",): True,
    },
    "incident-response-sandbox": {
        ("schema",): "cops.incident-response-playback/v1",
        ("execution_boundary", "network_calls"): 0,
        ("execution_boundary", "live_containment_validated"): False,
        ("execution_boundary", "temporary_artifacts_removed"): True,
        ("primary", "dry_run_state_unchanged"): True,
        ("primary", "execute_status"): "applied",
        ("replay_rejection", "rejected"): True,
        ("expiry_rejection", "rejected"): True,
        ("rollback", "execute_status"): "partial-rolled-back",
    },
    "host-assessment-workbench": {
        ("status",): "passed",
        ("mode",): "offline_import",
        ("cases", "positive", "counts", "configuration_candidate"): 6,
        ("cases", "positive", "counts", "reported_canary_crossing"): 1,
        ("cases", "negative", "counts", "reported_canary_blocked"): 1,
        ("cases", "unknown_context", "counts", "not_evaluated"): 8,
        ("cases", "unverified_cleanup", "rejected"): True,
    },
    "offensive-engagement-workbench": {
        ("engagement_id",): "eng-synthetic-e03",
        ("mode",): "planning",
        ("network_requests",): 0,
        ("operations_count",): 1,
        ("status",): "passed",
        ("target",): "10.100.0.10",
    },
}


def _json_documents(output: str) -> list[dict[str, Any]]:
    """Extract JSON objects from CLI framing and optional trailing status text."""
    decoder = json.JSONDecoder()
    documents: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(output):
        starts = [position for token in ("{", "[") if (position := output.find(token, cursor)) >= 0]
        if not starts:
            break
        start = min(starts)
        try:
            value, end = decoder.raw_decode(output, start)
        except json.JSONDecodeError:
            cursor = start + 1
            continue
        if isinstance(value, dict):
            documents.append(value)
        cursor = end
    return documents


def _value_at(payload: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = payload
    for key in path:
        assert isinstance(value, dict) and key in value, f"missing result field {'.'.join(path)}"
        value = value[key]
    return value


def _assert_playback_semantics(plugin_id: str, result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, f"{plugin_id}:\n{result.stdout}{result.stderr}"
    assert plugin_id in EXPECTED_PLAYBACK_FIELDS, f"{plugin_id} has no semantic playback contract"
    documents = _json_documents(result.stdout)
    assert documents, f"{plugin_id} produced no machine-readable JSON result"
    payload = documents[-1]
    for path, expected in EXPECTED_PLAYBACK_FIELDS[plugin_id].items():
        actual = _value_at(payload, path)
        assert actual == expected, f"{plugin_id} {'.'.join(path)}: expected {expected!r}, got {actual!r}"

    if plugin_id == "soc-investigation-workbench":
        summary_path = Path(_value_at(payload, ("summary",)))
        assert summary_path.name == "playback-summary.json" and summary_path.is_file()
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        assert summary["schema_version"] == "soc-investigation.playback/v1"
        assert summary["evidence_scope"] == "synthetic_contract_and_reference_semantics_only"
        assert summary["live_service_validation"] == "not_performed"
        assert set(item["conclusion"] for item in summary["variants"].values()) == {
            "malicious", "benign", "insufficient_evidence",
        }
        assert all(summary["assertions"].values())
    elif plugin_id == "sentinel-hunt-workbench":
        assert {item["hunt_id"] for item in payload["rendered_artifacts"]} == {
            f"H{number:02d}" for number in range(1, 13)
        }
    elif plugin_id == "detection-quality-workbench":
        assert {(rule["platform"], rule["passed"]) for rule in payload["rules"]} == {
            ("sentinel_kql", True), ("splunk_spl", True),
        }
        assert all(rule["metrics"]["schema_error_cases"] > 0 for rule in payload["rules"])
    elif plugin_id == "patch-security-review":
        candidate_id = payload["malicious"]["candidates"][0]["id"]
        assert payload["malicious"]["validated_findings"][0]["candidate_id"] == candidate_id
    elif plugin_id == "telemetry-proof-pack":
        assert {item["scenario"]: item["actual_health"] for item in payload["scenarios"]} == {
            "cribl-splunk-route": "healthy",
            "cribl-sentinel-route": "healthy",
            "hec-indexed-rule-missed": "degraded",
            "missing-cribl-stage": "broken",
            "cross-tenant-collision": "broken",
        }
        assert all(item["passed"] for item in payload["scenarios"])


def _assert_all_playback_results(
    results: dict[str, list[subprocess.CompletedProcess[str]]],
    *,
    expected_plugin_ids: set[str],
    require_public_command: bool,
) -> None:
    """Report every playback failure without skipping later package results."""
    failures: list[str] = []
    if set(results) != expected_plugin_ids:
        failures.append(
            "catalog result mismatch: "
            f"expected {sorted(expected_plugin_ids)!r}, got {sorted(results)!r}"
        )
    for plugin_id, runs in results.items():
        if len(runs) != 2:
            failures.append(f"{plugin_id}: expected 2 runs, got {len(runs)}")
        for run_number, result in enumerate(runs, start=1):
            try:
                _assert_playback_semantics(plugin_id, result)
                if require_public_command:
                    assert result.args == [
                        sys.executable, "-m", "cops", "demo", plugin_id,
                    ]
            except AssertionError as error:
                failures.append(f"{plugin_id} run {run_number}: {error}")
    assert not failures, "playback failures:\n\n" + "\n\n".join(failures)


@pytest.fixture
def context() -> dict[str, object]:
    return {}


@given("the canonical COPS package catalog")
def canonical_catalog(context):
    context["records"] = plugin_records(ROOT)


@when("I list the available cybersecurity packages")
def list_packages(context):
    context["result"] = subprocess.run(
        [sys.executable, "-m", "cops", "list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


@then("every catalog package is shown with offline, host, and live support states")
def catalog_packages_are_visible(context):
    result = context["result"]
    assert result.returncode == 0, result.stderr
    assert all(label in result.stdout for label in ("OFFLINE", "HOST", "LIVE"))
    for record in context["records"]:
        assert record.id in result.stdout
        assert record.support["offline_workflow"] in result.stdout
        assert record.support["host_installation"] in result.stdout
        assert record.support["live_integration"] in result.stdout


@when("I run each package's declared offline demo")
def run_demos(context):
    # Reruns must work without fixture edits or state left by an earlier run.
    context["results"] = {
        record.id: [
            subprocess.run(
                [sys.executable, "-m", "cops", "demo", record.id],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=record.package["demo"]["timeout_seconds"] + 5,
            )
            for _ in range(2)
        ]
        for record in context["records"]
    }


@then("every demo succeeds without shell interpretation")
def demos_succeed(context):
    _assert_all_playback_results(
        context["results"],
        expected_plugin_ids={record.id for record in context["records"]},
        require_public_command=True,
    )


@when("I export and run every playback with an isolated COPS runtime")
def run_exported_demos(context, tmp_path):
    runtime = tmp_path / "runtime"
    for directory in ("cops", "catalog"):
        shutil.copytree(
            ROOT / directory, runtime / directory,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    (runtime / "agents").mkdir()
    shutil.copy2(ROOT / "agents" / "registry.json", runtime / "agents" / "registry.json")
    environment = {**os.environ, "PYTHONPATH": str(runtime), "PYTHONNOUSERSITE": "1"}
    context["exported_results"] = {}
    for record in context["records"]:
        destination = runtime / record.path
        export_portable_package(ROOT / record.path, destination)
        assert not (destination / "tests").exists()
        assert not (destination / "package.json").exists()
        command, timeout = validate_declared_command(record.package["demo"], record, runtime)
        context["exported_results"][record.id] = [
            subprocess.run(
                command, cwd=runtime, env=environment,
                capture_output=True, text=True, timeout=timeout + 5,
            )
            for _ in range(2)
        ]


@then("all exported playbacks verify their results without source package files")
def exported_demos_succeed(context):
    _assert_all_playback_results(
        context["exported_results"],
        expected_plugin_ids={record.id for record in context["records"]},
        require_public_command=False,
    )


@pytest.mark.parametrize("stdout", ["", "playback passed\n"])
def test_playback_acceptance_rejects_exit_zero_noop_runner(stdout):
    result = subprocess.CompletedProcess(
        args=["no-op-runner"], returncode=0, stdout=stdout, stderr="",
    )
    with pytest.raises(AssertionError, match="no machine-readable JSON result"):
        _assert_playback_semantics("security-logging-advisor", result)


def test_playback_acceptance_reports_every_runner_failure():
    results = {
        plugin_id: [
            subprocess.CompletedProcess(
                args=[plugin_id], returncode=1, stdout="", stderr=f"failure {run_number}",
            )
            for run_number in (1, 2)
        ]
        for plugin_id in ("security-logging-advisor", "attack-surface-planner")
    }

    with pytest.raises(AssertionError) as captured:
        _assert_all_playback_results(
            results,
            expected_plugin_ids=set(results),
            require_public_command=False,
        )

    message = str(captured.value)
    for plugin_id in results:
        assert f"{plugin_id} run 1" in message
        assert f"{plugin_id} run 2" in message


@when("a package declares a command outside its own directory")
def escaping_command(context):
    record = context["records"][0]
    definition = {
        "command": ["$PYTHON", "../../scripts/agent/check.py"],
        "timeout_seconds": 10,
    }
    try:
        validate_declared_command(definition, record, ROOT)
    except CatalogError as error:
        context["error"] = error


@then("the package command is rejected before execution")
def escape_is_rejected(context):
    assert "error" in context
    assert "inside its package" in str(context["error"])


@given("a generated host index that differs from its canonical document")
def stale_index(context, tmp_path, monkeypatch):
    target = Path("generated") / "marketplace.json"
    destination = tmp_path / target
    destination.parent.mkdir(parents=True)
    original = json.dumps({"name": "stale"}) + "\n"
    destination.write_text(original, encoding="utf-8")
    monkeypatch.setattr(
        "cops.validation.marketplace_documents",
        lambda root: {target: {"name": "expected"}},
    )
    context.update(root=tmp_path, target=destination, original=original)


@when("generated host indexes are checked")
def check_generated_indexes(context):
    with pytest.raises(ValidationError) as captured:
        generate_marketplaces(context["root"], check=True)
    context["error"] = captured.value


@then("the stale index is reported without being rewritten")
def stale_index_reported(context):
    assert "generated host indexes are stale" in str(context["error"])
    assert context["target"].read_text(encoding="utf-8") == context["original"]
