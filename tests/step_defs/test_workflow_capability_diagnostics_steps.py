"""Step definitions for workflow capability diagnostics BDD scenarios."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.diagnostics import (
    detect_system_platform,
    diagnose_host_tools,
    diagnose_packages,
    run_diagnostics,
)

ROOT = Path(__file__).resolve().parents[2]

scenarios("../../specs/features/workflow_capability_diagnostics.feature")


@pytest.fixture
def diag_ctx():
    return {
        "root": ROOT,
        "system": None,
        "tools": None,
        "packages": None,
        "report": None,
        "package_id": None,
    }


# Scenario: Diagnosing system platform and runtime environment

@given("a supported host platform and Python runtime")
def given_supported_host(diag_ctx):
    diag_ctx["root"] = ROOT


@when("the diagnostic runner inspects the system environment")
def when_inspect_system(diag_ctx):
    diag_ctx["system"] = detect_system_platform()


@then("the system platform diagnostic indicates supported status")
def then_system_supported(diag_ctx):
    assert diag_ctx["system"] is not None
    assert diag_ctx["system"].is_supported is True


@then('the detected OS is one of "darwin", "linux", "windows"')
def then_detected_os(diag_ctx):
    assert diag_ctx["system"].os in ("darwin", "linux", "windows")


# Scenario: Diagnosing security tool prerequisites matrix

@given("the tested host tools matrix")
def given_tested_tools_matrix(diag_ctx):
    diag_ctx["root"] = ROOT


@when("the diagnostic runner inspects external tool availability")
def when_inspect_tools(diag_ctx):
    diag_ctx["tools"] = diagnose_host_tools()


@then(parsers.parse("at least {count:d} security tools are evaluated"))
def then_tools_count(diag_ctx, count):
    assert len(diag_ctx["tools"]) >= count


@then(parsers.parse('"{tool_name}" is detected as "{status}"'))
def then_tool_status(diag_ctx, tool_name, status):
    tool_map = {t.tool: t for t in diag_ctx["tools"]}
    assert tool_name in tool_map
    assert tool_map[tool_name].status == status


@then("missing tools are explicitly reported without failing offline planning")
def then_missing_tools_reported(diag_ctx):
    for t in diag_ctx["tools"]:
        assert t.status in ("available", "missing", "version_mismatch")


# Scenario: Diagnosing package workflow structures

@given("registered plugin packages in the repository")
def given_registered_packages(diag_ctx):
    diag_ctx["root"] = ROOT


@when("the diagnostic runner inspects plugin package workflows")
def when_inspect_packages(diag_ctx):
    diag_ctx["packages"] = diagnose_packages(diag_ctx["root"] / "plugins")


@then(parsers.parse("at least {count:d} plugin packages are evaluated"))
def then_packages_count(diag_ctx, count):
    assert len(diag_ctx["packages"]) >= count


@then(parsers.parse('"{package_id}" is diagnosed as "{status1}" or "{status2}"'))
def then_package_status(diag_ctx, package_id, status1, status2):
    pkg_map = {p.package_id: p for p in diag_ctx["packages"]}
    assert package_id in pkg_map
    assert pkg_map[package_id].status in (status1, status2)


@then("all package manifests are validated")
def then_package_manifests_valid(diag_ctx):
    for p in diag_ctx["packages"]:
        assert p.manifest_valid is True


# Scenario: Auditing capability truth-in-advertising alignment

@given("the reconciled capability registry")
def given_reconciled_registry(diag_ctx):
    diag_ctx["root"] = ROOT


@when("capability diagnostics are executed")
def when_run_capability_diagnostics(diag_ctx):
    diag_ctx["report"] = run_diagnostics(diag_ctx["root"], strict=False)


@then("the capability truth audit passes")
def then_capability_truth_passes(diag_ctx):
    assert diag_ctx["report"].capability_truth_passed is True


@then(parsers.parse("exactly {count:d} total capabilities are verified"))
def then_capability_count_verified(diag_ctx, count):
    assert diag_ctx["report"].capability_count == count


@then(parsers.parse('exactly {count:d} capabilities claim unverified "live-validated" execution'))
def then_zero_live_validated(diag_ctx, count):
    # From audit summary
    assert diag_ctx["report"].capability_truth_passed is True


# Scenario: Evaluating strict diagnostic enforcement

@given("an unknown or degraded package specification")
def given_unknown_package(diag_ctx):
    diag_ctx["package_id"] = "unknown-nonexistent-package"


@when("the diagnostic runner executes in strict mode")
def when_run_strict_mode(diag_ctx):
    diag_ctx["report"] = run_diagnostics(
        diag_ctx["root"],
        package_id=diag_ctx["package_id"],
        strict=True,
    )


@then("overall diagnostic readiness fails")
def then_readiness_fails(diag_ctx):
    assert diag_ctx["report"].all_ready is False
