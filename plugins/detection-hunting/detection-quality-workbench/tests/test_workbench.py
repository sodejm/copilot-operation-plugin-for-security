"""Comprehensive unit tests for Detection Quality Workbench."""

import json
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from detectionquality.cli import main as cli_main
from detectionquality.evaluator import evaluate_fixture_case, evaluate_rule_suite
from detectionquality.models import FixtureCase, FixtureSuite, QualityError, Rule
from detectionquality.reporting import render_json_report, render_markdown_report
from detectionquality.static_analysis import analyze_rule_dependencies


@pytest.fixture
def rules_dir() -> Path:
    return PLUGIN_ROOT / "rules"


@pytest.fixture
def fixtures_dir() -> Path:
    return PLUGIN_ROOT / "fixtures"


@pytest.fixture
def kql_rule(rules_dir: Path) -> Rule:
    path = rules_dir / "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN.json"
    return Rule.from_dict(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def kql_fixtures(fixtures_dir: Path) -> FixtureSuite:
    path = fixtures_dir / "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN.json"
    return FixtureSuite.from_dict(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def spl_rule(rules_dir: Path) -> Rule:
    path = rules_dir / "RULE-SPL-DEFENDER-POWERSHELL-EXEC.json"
    return Rule.from_dict(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def spl_fixtures(fixtures_dir: Path) -> FixtureSuite:
    path = fixtures_dir / "RULE-SPL-DEFENDER-POWERSHELL-EXEC.json"
    return FixtureSuite.from_dict(json.loads(path.read_text(encoding="utf-8")))


def test_rule_loading_and_validation(kql_rule: Rule, spl_rule: Rule):
    """Verify loading and properties of both Sentinel KQL and Splunk SPL rules."""
    assert kql_rule.rule_id == "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN"
    assert kql_rule.platform == "sentinel_kql"
    assert "IPAddress" in kql_rule.required_fields

    assert spl_rule.rule_id == "RULE-SPL-DEFENDER-POWERSHELL-EXEC"
    assert spl_rule.platform == "splunk_spl"
    assert "ScriptBlockText" in spl_rule.required_fields


def test_malformed_rule_raises_error():
    """Verify missing required fields raises QualityError."""
    with pytest.raises(QualityError, match="Missing required rule field"):
        Rule.from_dict({"rule_id": "RULE-TEST"})


def test_static_analysis_flags_missing_fields(kql_rule: Rule, kql_fixtures: FixtureSuite):
    """Verify static analysis flags deliberately removed fields and detects schema drift."""
    analysis = analyze_rule_dependencies(kql_rule, list(kql_fixtures.cases))
    assert analysis["required_fields_present"] is False
    assert "IPAddress" in analysis["missing_fields"]
    assert analysis["schema_drift_detected"] is True


def test_kql_evaluation_metrics(kql_rule: Rule, kql_fixtures: FixtureSuite):
    """Verify reference evaluation metrics on labeled KQL fixtures."""
    report = evaluate_rule_suite(kql_rule, kql_fixtures)
    metrics = report["metrics"]
    assert metrics["total_cases"] == 6
    assert metrics["true_positives"] == 2
    assert metrics["true_negatives"] == 3
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision_on_labeled_fixtures"] == 1.0
    assert metrics["recall_on_labeled_fixtures"] == 1.0


def test_spl_evaluation_metrics(spl_rule: Rule, spl_fixtures: FixtureSuite):
    """Verify reference evaluation metrics on labeled SPL fixtures."""
    report = evaluate_rule_suite(spl_rule, spl_fixtures)
    metrics = report["metrics"]
    assert metrics["total_cases"] == 6
    assert metrics["true_positives"] == 2
    assert metrics["true_negatives"] == 3
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision_on_labeled_fixtures"] == 1.0
    assert metrics["recall_on_labeled_fixtures"] == 1.0


def test_false_positive_and_negative_detection(kql_rule: Rule):
    """Verify that a noisy case causes a false positive and lowers precision."""
    # Create a noisy case: expected_match=False, but telemetry has external IP and Azure Portal login
    noisy_case = FixtureCase(
        case_id="CASE-NOISY-TEST",
        label="negative",
        expected_match=False,
        events=(
            {
                "TimeGenerated": "2026-10-01T12:00:00Z",
                "UserPrincipalName": "user@contoso.com",
                "IPAddress": "203.0.113.50",
                "ResultType": 0,
                "AppDisplayName": "Azure Portal",
            },
        ),
    )
    result = evaluate_fixture_case(noisy_case, kql_rule)
    assert result.actual_match is True
    assert result.outcome_classification == "false_positive"


def test_false_negative_detection(kql_rule: Rule):
    """Verify that a missed attack case causes a false negative and lowers recall."""
    # Create missed attack case: expected_match=True, but ResultType is failed (50126)
    missed_case = FixtureCase(
        case_id="CASE-MISSED-TEST",
        label="positive",
        expected_match=True,
        events=(
            {
                "TimeGenerated": "2026-10-01T12:00:00Z",
                "UserPrincipalName": "attacker@contoso.com",
                "IPAddress": "203.0.113.50",
                "ResultType": 50126,
                "AppDisplayName": "Azure Portal",
            },
        ),
    )
    result = evaluate_fixture_case(missed_case, kql_rule)
    assert result.actual_match is False
    assert result.outcome_classification == "false_negative"


def test_markdown_and_json_reports(kql_rule: Rule, kql_fixtures: FixtureSuite):
    """Verify report formatting in Markdown and JSON."""
    report_data = evaluate_rule_suite(kql_rule, kql_fixtures)

    # Markdown
    md = render_markdown_report(report_data)
    assert "# Detection Quality & Regression Report" in md
    assert "Reference-evaluator output indicates fixture precision/recall only" in md
    assert "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN" in md

    # JSON
    js = render_json_report(report_data)
    parsed = json.loads(js)
    assert parsed["schema_version"] == "cops.detection-quality-report/v1"
    assert parsed["rule"]["rule_id"] == "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN"


def test_cli_execution(rules_dir: Path, fixtures_dir: Path, tmp_path: Path):
    """Verify CLI validate, evaluate, and test-suite commands."""
    # 1. validate
    assert cli_main(["validate", "--rules-dir", str(rules_dir)]) == 0

    # 2. evaluate
    r_path = rules_dir / "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN.json"
    f_path = fixtures_dir / "RULE-KQL-ENTRA-ANOMALOUS-SIGNIN.json"
    out_file = tmp_path / "report.md"
    assert cli_main(["evaluate", "--rule", str(r_path), "--fixtures", str(f_path), "--output", str(out_file)]) == 0
    assert out_file.exists()

    # 3. test-suite
    assert cli_main(["test-suite", "--rules-dir", str(rules_dir), "--fixtures-dir", str(fixtures_dir)]) == 0
