"""BDD step definitions for issue coverage gate scenarios."""

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from scripts.agent.check_issue_coverage import evaluate_coverage

scenarios("../../specs/features/issue_coverage_gate.feature")


@pytest.fixture
def context():
    return {
        "branch": "main",
        "files": [],
        "messages": [],
        "result": None,
    }


@given(parsers.parse('an issue branch "{branch}"'))
def given_issue_branch(context, branch):
    context["branch"] = branch


@given(parsers.parse('modified files "{files}"'))
def given_modified_files(context, files):
    context["files"] = [f.strip() for f in files.split(",") if f.strip()]


@when(parsers.parse('issue coverage gate is evaluated with commit message "{message}"'))
def when_evaluated_with_message(context, message):
    context["messages"] = [message]
    context["result"] = evaluate_coverage(
        branch_name=context["branch"],
        modified_files=context["files"],
        commit_messages=context["messages"],
    )


@then(parsers.parse('the issue coverage check passes with issue identifier "{issue_id}"'))
def then_check_passes_with_issue(context, issue_id):
    result = context["result"]
    assert result.passed, f"Expected pass, got errors: {result.errors}"
    assert result.issue_id == issue_id


@then(parsers.parse('the issue coverage check fails with error "{error_msg}"'))
def then_check_fails_with_error(context, error_msg):
    result = context["result"]
    assert not result.passed, "Expected failure, but check passed"
    assert any(error_msg in err for err in result.errors), f"Error '{error_msg}' not found in {result.errors}"


@then("the issue coverage check passes with documentation exemption")
def then_check_passes_doc_exemption(context):
    result = context["result"]
    assert result.passed, f"Expected pass, got errors: {result.errors}"
    assert result.doc_exempt is True


@then("the issue coverage check passes with test exemption")
def then_check_passes_test_exemption(context):
    result = context["result"]
    assert result.passed, f"Expected pass, got errors: {result.errors}"
    assert result.test_exempt is True
