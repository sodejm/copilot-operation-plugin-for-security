"""Unit tests for check_issue_coverage.py."""

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.agent.check_issue_coverage import (
    check_exemptions,
    evaluate_coverage,
    extract_issue_identifier,
    is_doc_file,
    is_test_file,
)

ROOT = Path(__file__).resolve().parents[1]


def test_extract_issue_identifier():
    assert extract_issue_identifier("issue-42", []) == "42"
    assert extract_issue_identifier("issues/105", []) == "105"
    assert extract_issue_identifier("99-fix-leak", []) == "99"
    assert extract_issue_identifier("main", ["Fixes #350"]) == "350"
    assert extract_issue_identifier("main", ["Resolves #777 in scanner"]) == "777"
    assert extract_issue_identifier("main", ["feat(engine): add rule COPS-E05.02-S01"]) == "COPS-E05.02-S01"
    assert extract_issue_identifier("codex/jwt-token-check", []) == "jwt-token-check"
    assert extract_issue_identifier("main", ["refactor: cleanup"]) is None


def test_is_doc_file():
    assert is_doc_file("docs/plugin-guide.md") is True
    assert is_doc_file("docs/api/index.md") is True
    assert is_doc_file("specs/issue-coverage.spec.md") is True
    assert is_doc_file("README.md") is True
    assert is_doc_file("architecture.md") is True
    assert is_doc_file("plugins/logging-telemetry/security-logging-advisor/README.md") is True

    # Not doc files
    assert is_doc_file("specs/features/issue_coverage_gate.feature") is False
    assert is_doc_file("cops/cli.py") is False
    assert is_doc_file("tests/test_cli.py") is False


def test_is_test_file():
    assert is_test_file("tests/test_issue_coverage.py") is True
    assert is_test_file("specs/features/issue_coverage_gate.feature") is True
    assert is_test_file("plugins/detection-hunting/attack-path-workbench/tests/test_plugin.py") is True

    # Not test files
    assert is_test_file("docs/plugin-guide.md") is False
    assert is_test_file("cops/cli.py") is False


def test_check_exemptions():
    doc_ex, doc_re, test_ex, test_re = check_exemptions(["fix: small typo [skip-docs: typo only]"])
    assert doc_ex is True
    assert doc_re == "typo only"
    assert test_ex is False

    doc_ex, doc_re, test_ex, test_re = check_exemptions(["docs: update readme [skip-tests: docs change]"])
    assert doc_ex is False
    assert test_ex is True
    assert test_re == "docs change"

    doc_ex, doc_re, test_ex, test_re = check_exemptions(["feat: regular commit"])
    assert doc_ex is False
    assert test_ex is False


def test_evaluate_coverage_pass():
    result = evaluate_coverage(
        branch_name="codex/issue-12-auth",
        modified_files=["cops/auth.py", "docs/auth.md", "tests/test_auth.py"],
        commit_messages=["feat: add auth"],
    )
    assert result.passed is True
    assert result.issue_id == "12"
    assert len(result.doc_files) == 1
    assert len(result.test_files) == 1


def test_evaluate_coverage_missing_docs():
    result = evaluate_coverage(
        branch_name="issue-12",
        modified_files=["cops/auth.py", "tests/test_auth.py"],
        commit_messages=["feat: add auth"],
    )
    assert result.passed is False
    assert "Missing documentation changes for issue 12" in result.errors


def test_evaluate_coverage_missing_tests():
    result = evaluate_coverage(
        branch_name="issue-12",
        modified_files=["cops/auth.py", "docs/auth.md"],
        commit_messages=["feat: add auth"],
    )
    assert result.passed is False
    assert "Missing test case changes for issue 12" in result.errors


def test_cli_execution_flags():
    cmd = [
        sys.executable,
        "scripts/agent/check_issue_coverage.py",
        "--branch", "codex/issue-999-test",
        "--files", "docs/index.md", "tests/test_something.py",
        "--message", "feat: done",
    ]
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "COPS Issue Coverage Gate" in res.stdout
    assert "Detected Issue:    999" in res.stdout
