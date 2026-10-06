"""Step definitions for execution scope enforcement BDD scenarios."""

from __future__ import annotations

import ipaddress

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution import ScopeDefinition, ScopeGuard, ScopeViolationError

scenarios("../../specs/features/execution_scope_enforcement.feature")


@pytest.fixture
def scope_context():
    return {}


@given(parsers.parse('an engagement scope containing included subnet "{subnet}" and domain "{domain}"'))
def init_scope_subnet_domain(scope_context, subnet, domain):
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network(subnet)],
        included_domains={domain},
    )
    scope_context["guard"] = ScopeGuard(
        scope_context["scope_def"],
        resolver=lambda d: ["10.0.0.50"] if d == domain else [],
    )


@when(parsers.parse('the ScopeGuard verifies destination "{dest}"'))
def verify_dest(scope_context, dest):
    try:
        scope_context["guard"].check_destination(dest)
        scope_context["last_error"] = None
    except ScopeViolationError as err:
        scope_context["last_error"] = err


@then("the destination is permitted")
def assert_permitted(scope_context):
    assert scope_context["last_error"] is None


@given(parsers.parse('an engagement scope containing included subnet "{subnet}" with excluded IP "{excluded_ip}"'))
def init_scope_with_exclusion(scope_context, subnet, excluded_ip):
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network(subnet)],
        excluded_ips={ipaddress.ip_address(excluded_ip)},
    )
    scope_context["guard"] = ScopeGuard(scope_context["scope_def"])


@then("the destination is rejected as an excluded target")
def assert_excluded(scope_context):
    assert isinstance(scope_context["last_error"], ScopeViolationError)
    assert "excluded" in str(scope_context["last_error"])


@given("an engagement scope")
def init_default_scope(scope_context):
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network("10.0.0.0/24")],
        block_cloud_metadata=True,
    )
    scope_context["guard"] = ScopeGuard(scope_context["scope_def"])


@then("the destination is rejected as a blocked cloud metadata address")
def assert_metadata_blocked(scope_context):
    assert isinstance(scope_context["last_error"], ScopeViolationError)
    assert "cloud metadata" in str(scope_context["last_error"])


@given(parsers.parse('a hostname "{hostname}" resolving to cloud metadata IP "{metadata_ip}"'))
def init_rebind_host(scope_context, hostname, metadata_ip):
    scope_context["rebind_hostname"] = hostname
    scope_context["scope_def"] = ScopeDefinition(
        included_networks=[ipaddress.ip_network("10.0.0.0/24")],
        included_domains={hostname},
        block_cloud_metadata=True,
    )
    scope_context["guard"] = ScopeGuard(
        scope_context["scope_def"],
        resolver=lambda h: [metadata_ip] if h == hostname else [],
    )


@when("the ScopeGuard verifies the hostname destination")
def verify_rebind(scope_context):
    try:
        scope_context["guard"].check_destination(scope_context["rebind_hostname"])
        scope_context["last_error"] = None
    except ScopeViolationError as err:
        scope_context["last_error"] = err
