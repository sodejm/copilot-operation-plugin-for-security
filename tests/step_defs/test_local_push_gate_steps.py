"""Execute shared disposable-remote assertions as specification scenarios."""

import importlib.util
import unittest
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

scenarios("../../specs/features/local_push_gate.feature")


@pytest.fixture
def push_context():
    return {}


@given(parsers.parse('the local push regression "{regression}"'))
def given_regression(push_context, regression):
    path = Path(__file__).resolve().parents[1] / "test_local_push_gate.py"
    spec = importlib.util.spec_from_file_location("push_contract_cases", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    push_context["case"] = module.RemoteTests(regression)


@when("the disposable push regression executes")
def run_regression(push_context):
    result = unittest.TestResult()
    push_context["case"].run(result)
    push_context["result"] = result


@then("its remote-update assertions pass")
def assert_remote_contract(push_context):
    result = push_context["result"]
    assert result.testsRun == 1
    assert not result.skipped
    assert result.wasSuccessful(), result.errors + result.failures
