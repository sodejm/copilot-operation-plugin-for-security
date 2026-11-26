"""Behavior of the public one-request fixture review."""

import json
import subprocess
import sys

from pytest_bdd import given, scenarios, then, when

scenarios("../../specs/features/detection_quality_pilot.feature")


@given("an operator requests a review of both bundled detection fixture sets", target_fixture="operator_ask")
def operator_ask():
    return "Review both bundled Detection Quality fixture sets and summarize the gaps."


@when("COPS completes the request", target_fixture="review")
def complete_request(operator_ask, tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "cops", "ask", operator_ask, "--run-dir", str(tmp_path / "run"), "--json"],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    return json.loads(proc.stdout)


@then("the Detection Engineer uses the Detection Quality review skill")
def selected_skill(review):
    assert review["status"] == "verified"
    assert review["specialist"] == "cops-detection-engineer"
    assert review["workbench"] == "detection-quality-workbench"
    assert review["skill"] == "detection-quality-review"


@then("the report identifies the missing Sentinel and Splunk telemetry")
def report_gaps(review):
    assert review["totals"]["schema_error_cases"] == 3
    assert [s["missing_fields"] for s in review["suites"]] == [["IPAddress"], ["ScriptBlockText"]]
