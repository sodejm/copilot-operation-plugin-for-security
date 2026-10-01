"""Executable acceptance scenarios for offline patch security review."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

PACKAGE = Path(__file__).resolve().parents[2] / "plugins/vulnerability-management/patch-security-review"
sys.path.insert(0, str(PACKAGE))
from patchreview import ReviewError, review_patch, validate_candidate  # noqa: E402

scenarios("../../specs/features/patch_security_review.feature")


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    ).decode().strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "synthetic@example.invalid")
    git(tmp_path, "config", "user.name", "Synthetic")
    git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "app.py").write_text("def handler(request):\n    return 'safe'\n")
    git(tmp_path, "add", "app.py")
    git(tmp_path, "commit", "-qm", "base")
    base = git(tmp_path, "rev-parse", "HEAD")
    return {"root": tmp_path, "base": base, "error": None, "result": None}


@given("a synthetic Python patch that passes a request parameter to a shell")
def vulnerable_patch(repo):
    (repo["root"] / "app.py").write_text(
        "import os\ndef handler(request):\n    os.system(request)\n"
    )
    git(repo["root"], "commit", "-qam", "changed")


@when("the pinned commits are reviewed")
def review(repo):
    try:
        repo["result"] = review_patch(repo["root"], repo["base"], "HEAD")
    except ReviewError as exc:
        repo["error"] = exc


@then("the report records a candidate and no validated finding")
def candidate_finding(repo):
    result = repo["result"]
    assert len(result["plausible_scenarios"]) == 1
    assert result["validated_findings"] == []


@given("a synthetic Python patch that uses a constant argument list")
def benign_patch(repo):
    (repo["root"] / "app.py").write_text(
        "import subprocess\ndef handler(request):\n    subprocess.run(['echo', 'safe'])\n"
    )
    git(repo["root"], "commit", "-qam", "changed")


@then("the report has no candidate shell path")
def no_candidate(repo):
    assert repo["result"]["plausible_scenarios"] == []


@given("a candidate with asserted preconditions and disconfirming evidence")
def candidate_for_validation(repo):
    (repo["root"] / "app.py").write_text(
        "import os\ndef handler(request):\n    os.system(request)\n"
    )
    git(repo["root"], "commit", "-qam", "changed")
    repo["result"] = review_patch(repo["root"], repo["base"], "HEAD")


@when("an analyst validates the candidate")
def validate(repo):
    repo["validated"] = validate_candidate(
        repo["result"],
        "candidate-001",
        "analyst",
        "request controlled",
        "no sanitizer in bounded source",
    )


@then("the validation is recorded as an unverified analyst assertion")
def analyst_assertion(repo):
    assert (
        repo["validated"]["validated_findings"][0]["provenance"]
        == "unverified self-recorded assertion"
    )


@given("a changed source file beyond the configured byte budget")
def oversized_file(repo):
    (repo["root"] / "app.py").write_text("x = '" + "a" * (256 * 1024) + "'\n")
    git(repo["root"], "commit", "-qam", "changed")


@then("review stops before reading the full source")
def review_stops_budget(repo):
    assert repo["error"] is not None
    assert "byte budget" in str(repo["error"])
