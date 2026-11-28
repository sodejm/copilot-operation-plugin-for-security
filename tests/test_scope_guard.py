"""Unit tests for execution-time scope and egress enforcement."""

from __future__ import annotations

import ipaddress

import pytest

from cops.execution import ScopeDefinition, ScopeGuard, ScopeViolationError


@pytest.fixture
def test_scope():
    return ScopeDefinition(
        included_networks=[ipaddress.ip_network("10.0.0.0/24")],
        included_ips={ipaddress.ip_address("192.168.1.50")},
        included_domains={"corp.internal", "api.corp.internal"},
        included_cloud_resources={"arn:aws:iam::123456789012:role/secops-role"},
        excluded_networks=[ipaddress.ip_network("10.0.0.128/25")],
        excluded_ips={ipaddress.ip_address("10.0.0.1"), ipaddress.ip_address("10.0.0.5")},
        excluded_domains={"prod-db.corp.internal"},
        excluded_cloud_resources={"arn:aws:iam::123456789012:role/secops-role/admin"},
        block_cloud_metadata=True,
        block_loopback_unless_explicit=True,
    )


@pytest.fixture
def scope_guard(test_scope):
    def mock_resolver(domain: str) -> list[str]:
        if domain == "corp.internal":
            return ["10.0.0.10"]
        if domain == "api.corp.internal":
            return ["10.0.0.20"]
        if domain == "prod-db.corp.internal":
            return ["10.0.0.30"]
        if domain == "rebind-attack.com":
            return ["169.254.169.254"]  # Rebinding attack returning cloud metadata IP
        if domain == "external.com":
            return ["93.184.216.34"]
        return []

    return ScopeGuard(test_scope, resolver=mock_resolver)


def test_positive_in_scope_destinations(scope_guard):
    """Test authorized destinations pass verification."""
    # Included subnet IP
    scope_guard.check_destination("10.0.0.15")
    # Included specific IP
    scope_guard.check_destination("192.168.1.50")
    # Included domain resolving to in-scope IP
    scope_guard.check_destination("corp.internal")
    scope_guard.check_destination("https://api.corp.internal:8443/v1/scan")
    # Included cloud resource ARN
    scope_guard.check_destination("arn:aws:iam::123456789012:role/secops-role")


def test_negative_excluded_targets(scope_guard):
    """Test explicitly excluded targets raise ScopeViolationError."""
    # Excluded IP in otherwise included subnet
    with pytest.raises(ScopeViolationError, match="in explicitly excluded targets"):
        scope_guard.check_destination("10.0.0.1")
    with pytest.raises(ScopeViolationError, match="in explicitly excluded targets"):
        scope_guard.check_destination("10.0.0.5")

    # Excluded subnet
    with pytest.raises(ScopeViolationError, match="falls within excluded subnet"):
        scope_guard.check_destination("10.0.0.200")

    # Excluded domain
    with pytest.raises(ScopeViolationError, match="in explicitly excluded scope"):
        scope_guard.check_destination("prod-db.corp.internal")

    # Excluded cloud resource
    with pytest.raises(ScopeViolationError, match="excluded cloud resource"):
        scope_guard.check_destination("arn:aws:iam::123456789012:role/secops-role/admin")


def test_negative_out_of_scope_destinations(scope_guard):
    """Test targets not in scope are blocked."""
    with pytest.raises(ScopeViolationError, match="NOT within authorized scope"):
        scope_guard.check_destination("8.8.8.8")

    with pytest.raises(ScopeViolationError, match="NOT within authorized scope"):
        scope_guard.check_destination("external.com")


def test_negative_cloud_metadata_blocked(scope_guard):
    """Test AWS/Azure/GCP instance metadata endpoint is strictly blocked."""
    with pytest.raises(ScopeViolationError, match="cloud metadata service '169.254.169.254' is strictly blocked"):
        scope_guard.check_destination("169.254.169.254")

    # DNS rebinding attack resolving to metadata IP
    with pytest.raises(ScopeViolationError, match="cloud metadata service"):
        scope_guard.check_destination("rebind-attack.com")


def test_negative_loopback_blocked(scope_guard):
    """Test loopback addresses are blocked without explicit inclusion."""
    with pytest.raises(ScopeViolationError, match="loopback address '127.0.0.1' is blocked"):
        scope_guard.check_destination("127.0.0.1")
    with pytest.raises(ScopeViolationError, match="loopback address '::1' is blocked"):
        scope_guard.check_destination("::1")
