"""BDD step definitions for tool adapter registry scenarios."""

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.adapters import (
    AdapterInjectionError,
    ToolAdapterRegistry,
)

scenarios("../../specs/features/tool_adapter_registry.feature")


@pytest.fixture
def context():
    return {}


@given("the tool adapter registry is loaded")
def given_registry_loaded(context):
    context["registry"] = ToolAdapterRegistry()


@when(
    parsers.parse(
        'assembling command for tool "{tool}" and action "{action}" with parameter "{param}" as "{value}"'
    )
)
def when_assemble_tool_param(context, tool, action, param, value):
    adapter = context["registry"].get_adapter(tool)
    context["cmd"] = adapter.assemble_command(action, {param: value})


@then("the assembled command line is:")
def then_check_assembled_cmd(context):
    assert context["cmd"] == ["echo", "safe test message"]


@when(
    parsers.parse(
        'attempting to assemble tool "{tool}" and action "{action}" with parameter "{param}" as "{value}"'
    )
)
def when_attempt_assemble_invalid(context, tool, action, param, value):
    adapter = context["registry"].get_adapter(tool)
    try:
        context["cmd"] = adapter.assemble_command(action, {param: value})
        context["error"] = None
    except Exception as err:
        context["error"] = err


@then("an adapter injection error is raised")
def then_check_injection_error(context):
    assert isinstance(context["error"], AdapterInjectionError)


@when(
    parsers.parse(
        'assembling command for tool "{tool}" and action "{action}" with target "{target}" and ports "{ports}"'
    )
)
def when_assemble_nmap(context, tool, action, target, ports):
    adapter = context["registry"].get_adapter(tool)
    context["cmd"] = adapter.assemble_command(action, {"target": target, "ports": ports})


@then(parsers.parse('the assembled command includes target "{target}" and ports flag'))
def then_check_nmap_cmd(context, target):
    cmd = context["cmd"]
    assert target in cmd
    assert "-p" in cmd
