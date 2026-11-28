"""Unit tests for passive asset discovery, evidence provenance, and scope reconciliation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops.discovery import (
    DiscoveredAsset,
    EvidenceProvenance,
    command_discovery,
    merge_two_assets,
    normalize_certificate_record,
    normalize_cloud_export,
    normalize_dns_record,
    normalize_endpoint_record,
    normalize_ip_record,
    reconcile_asset,
    reconcile_inventory,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_provenance():
    return EvidenceProvenance(
        source_id="S01",
        source_type="dns",
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        timestamp="2026-10-05T00:00:00Z",
        path_or_uri="fixtures/recon/dns.json",
        raw_record_ref="rec-0001",
    )


@pytest.fixture
def sample_scope():
    return {
        "domains": ["example.com", "app.example.com"],
        "ip_ranges": ["192.168.1.0/24", "10.0.0.0/16"],
        "tenant_ids": ["tenant-001"],
        "exclusions": {
            "domains": ["secret.example.com"],
            "ip_ranges": ["192.168.1.254/32"],
            "tenant_ids": ["tenant-excluded"],
        },
    }


def test_normalize_dns_record(sample_provenance):
    """Verify DNS record normalization into DiscoveredAsset."""
    rec = {
        "hostname": "api.example.com",
        "type": "A",
        "value": "192.168.1.50",
        "ttl": 300,
        "owner": "platform-team",
    }
    asset = normalize_dns_record(rec, sample_provenance)
    assert asset.asset_type == "dns"
    assert asset.identifier == "api.example.com"
    assert asset.attributes["domain"] == "api.example.com"
    assert asset.attributes["target_ip"] == "192.168.1.50"
    assert asset.attributes["owner"] == "platform-team"
    assert len(asset.provenance) == 1
    assert asset.provenance[0].source_id == "S01"


def test_normalize_certificate_record(sample_provenance):
    """Verify TLS/CT certificate normalization."""
    rec = {
        "subject_cn": "login.example.com",
        "sans": ["auth.example.com", "login.example.com"],
        "issuer": "Let's Encrypt",
        "serial_number": "123456789",
        "not_after": "2027-01-01T00:00:00Z",
        "owner": "identity-team",
    }
    asset = normalize_certificate_record(rec, sample_provenance)
    assert asset.asset_type == "certificate"
    assert asset.identifier == "login.example.com"
    assert "auth.example.com" in asset.attributes["sans"]
    assert asset.attributes["issuer"] == "Let's Encrypt"


def test_normalize_ip_record(sample_provenance):
    """Verify IP allocation normalization."""
    rec = {
        "ip": "192.168.1.100",
        "asn": "AS13335",
        "owner": "netops",
    }
    asset = normalize_ip_record(rec, sample_provenance)
    assert asset.asset_type == "ip_address"
    assert asset.identifier == "192.168.1.100"
    assert asset.attributes["version"] == 4
    assert asset.attributes["asn"] == "AS13335"


def test_normalize_endpoint_record(sample_provenance):
    """Verify HTTP endpoint normalization."""
    rec = {
        "url": "https://api.example.com:443/v1/health",
        "methods": ["GET"],
        "owner": "platform-team",
    }
    asset = normalize_endpoint_record(rec, sample_provenance)
    assert asset.asset_type == "endpoint"
    assert asset.identifier == "https://api.example.com:443/v1/health"
    assert asset.attributes["host"] == "api.example.com"
    assert asset.attributes["port"] == 443


def test_normalize_cloud_export(sample_provenance):
    """Verify cloud resource export normalization."""
    rec = {
        "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-1",
        "provider": "azure",
        "ip": "192.168.1.200",
        "tenant_id": "tenant-001",
        "subscription_id": "sub-1",
        "owner": "cloud-sec",
    }
    asset = normalize_cloud_export(rec, sample_provenance)
    assert asset.asset_type == "cloud_resource"
    assert asset.attributes["tenant_id"] == "tenant-001"
    assert asset.attributes["ip"] == "192.168.1.200"


def test_reconcile_verified_in_scope(sample_provenance, sample_scope):
    """Verify asset correctly classified as verified_in_scope."""
    asset = normalize_dns_record(
        {"hostname": "app.example.com", "value": "192.168.1.10", "owner": "app-team"},
        sample_provenance,
    )
    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "verified_in_scope"
    assert len(reconciled.quarantine_reasons) == 0


def test_reconcile_quarantine_conflicting_ownership(sample_provenance, sample_scope):
    """Verify asset with conflicting ownership is quarantined."""
    asset = normalize_dns_record(
        {"hostname": "app.example.com", "value": "192.168.1.10", "owner": "team-a"},
        sample_provenance,
    )
    asset.attributes["conflicting_ownership"] = True
    asset.attributes["conflicting_owners"] = ["team-a", "team-b"]

    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "quarantined"
    assert "conflicting_ownership" in reconciled.quarantine_reasons


def test_reconcile_quarantine_stale_record(sample_provenance, sample_scope):
    """Verify asset with stale / dangling pointers is quarantined."""
    asset = normalize_dns_record(
        {
            "hostname": "legacy.example.com",
            "value": "192.168.1.10",
            "owner": "app-team",
            "stale": True,
        },
        sample_provenance,
    )
    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "quarantined"
    assert "stale_record" in reconciled.quarantine_reasons


def test_reconcile_quarantine_missing_provenance(sample_scope):
    """Verify asset with missing or absent provenance is quarantined."""
    asset = DiscoveredAsset(
        asset_id="asset-no-prov",
        asset_type="dns",
        identifier="app.example.com",
        attributes={"domain": "app.example.com", "owner": "app-team"},
        provenance=[],  # Absent provenance
    )
    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "quarantined"
    assert "missing_provenance" in reconciled.quarantine_reasons


def test_reconcile_quarantine_uncertain_ownership(sample_provenance, sample_scope):
    """Verify asset with missing or uncertain owner is quarantined."""
    asset = normalize_dns_record(
        {"hostname": "app.example.com", "value": "192.168.1.10"},  # No owner
        sample_provenance,
    )
    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "quarantined"
    assert "uncertain_ownership" in reconciled.quarantine_reasons


def test_reconcile_quarantine_outside_scope(sample_provenance, sample_scope):
    """Verify asset outside approved targets is quarantined."""
    asset = normalize_dns_record(
        {"hostname": "rogue.external.com", "value": "8.8.8.8", "owner": "unknown"},
        sample_provenance,
    )
    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "quarantined"
    assert "outside_scope" in reconciled.quarantine_reasons


def test_reconcile_excluded_asset(sample_provenance, sample_scope):
    """Verify explicitly excluded domain or IP is classified as excluded."""
    # Excluded domain
    asset = normalize_dns_record(
        {"hostname": "secret.example.com", "value": "192.168.1.10", "owner": "secops"},
        sample_provenance,
    )
    reconciled = reconcile_asset(asset, sample_scope)
    assert reconciled.status == "excluded"
    assert "explicitly_excluded" in reconciled.quarantine_reasons

    # Excluded IP
    ip_asset = normalize_ip_record(
        {"ip": "192.168.1.254", "owner": "secops"},
        sample_provenance,
    )
    reconciled_ip = reconcile_asset(ip_asset, sample_scope)
    assert reconciled_ip.status == "excluded"
    assert "explicitly_excluded" in reconciled_ip.quarantine_reasons


def test_merge_deduplication_and_provenance(sample_provenance):
    """Verify merging duplicate assets preserves all provenance envelopes."""
    prov1 = sample_provenance
    prov2 = EvidenceProvenance(
        source_id="S02",
        source_type="dns",
        sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        timestamp="2026-10-05T01:00:00Z",
        path_or_uri="fixtures/recon/cert.json",
        raw_record_ref="rec-0002",
    )

    asset1 = normalize_dns_record(
        {"hostname": "app.example.com", "owner": "secops"},
        prov1,
    )
    asset2 = normalize_dns_record(
        {"hostname": "app.example.com", "owner": "secops", "ttl": 600},
        prov2,
    )

    merged = merge_two_assets(asset1, asset2)
    assert merged.identifier == "app.example.com"
    assert len(merged.provenance) == 2
    assert {p.source_id for p in merged.provenance} == {"S01", "S02"}
    assert merged.attributes["ttl"] == 600


def test_merge_detects_conflicting_ownership(sample_provenance):
    """Verify merge flags conflicting owners."""
    prov2 = EvidenceProvenance(
        source_id="S02",
        source_type="dns",
        sha256="9999999999999999999999999999999999999999999999999999999999999999",
        timestamp="2026-10-05T01:00:00Z",
        path_or_uri="fixtures/recon/dns2.json",
    )

    asset1 = normalize_dns_record(
        {"hostname": "app.example.com", "owner": "finance-dept"},
        sample_provenance,
    )
    asset2 = normalize_dns_record(
        {"hostname": "app.example.com", "owner": "marketing-dept"},
        prov2,
    )

    merged = merge_two_assets(asset1, asset2)
    assert merged.attributes.get("conflicting_ownership") is True
    assert "conflicting_ownership" in merged.quarantine_reasons
    assert merged.status == "quarantined"


def test_reconcile_inventory_summary(sample_provenance, sample_scope):
    """Verify reconcile_inventory aggregates summary statistics accurately."""
    a1 = normalize_dns_record(
        {"hostname": "app.example.com", "value": "192.168.1.10", "owner": "team"},
        sample_provenance,
    )
    a2 = normalize_dns_record(
        {"hostname": "secret.example.com", "value": "192.168.1.10", "owner": "team"},
        sample_provenance,
    )
    a3 = normalize_dns_record(
        {"hostname": "unknown.org", "value": "8.8.8.8"},  # uncertain owner, outside scope
        sample_provenance,
    )

    inv = reconcile_inventory([a1, a2, a3], sample_scope)
    assert inv.summary["total_assets"] == 3
    assert inv.summary["verified_in_scope"] == 1
    assert inv.summary["excluded"] == 1
    assert inv.summary["quarantined"] == 1


def test_command_discovery_cli(tmp_path, sample_scope):
    """Verify CLI discovery subcommands execution."""
    raw_dns = tmp_path / "raw_dns.json"
    raw_dns.write_text(json.dumps([
        {"hostname": "app.example.com", "type": "A", "value": "192.168.1.10", "owner": "secops"},
        {"hostname": "secret.example.com", "type": "A", "value": "192.168.1.254", "owner": "secops"},
    ]))

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(sample_scope))

    norm_out = tmp_path / "normalized.json"
    rec_out = tmp_path / "reconciled.json"

    # 1. Normalize
    res = command_discovery(
        subcommand="normalize",
        file_path=str(raw_dns),
        asset_type="dns",
        output_path=str(norm_out),
    )
    assert res == 0
    assert norm_out.is_file()

    # 2. Reconcile
    res = command_discovery(
        subcommand="reconcile",
        file_path=str(norm_out),
        scope_path=str(scope_file),
        output_path=str(rec_out),
    )
    assert res == 0
    assert rec_out.is_file()
    rec_data = json.loads(rec_out.read_text())
    assert rec_data["summary"]["verified_in_scope"] == 1
    assert rec_data["summary"]["excluded"] == 1

    # 3. Inspect
    res = command_discovery(
        subcommand="inspect",
        file_path=str(rec_out),
        as_json=True,
    )
    assert res == 0
