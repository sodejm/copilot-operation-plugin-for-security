"""Step definitions for Network Passive Discovery BDD scenarios."""

from __future__ import annotations

from pathlib import Path
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.discovery import (
    DiscoveredAsset,
    DiscoveryInventory,
    EvidenceProvenance,
    merge_inventories,
    normalize_certificate_record,
    normalize_cloud_export,
    normalize_dns_record,
    normalize_endpoint_record,
    normalize_ip_record,
    reconcile_asset,
)

ROOT = Path(__file__).resolve().parents[2]

scenarios("../../specs/features/network_passive_discovery.feature")


@pytest.fixture
def bdd_ctx():
    prov = EvidenceProvenance(
        source_id="S01",
        source_type="recon",
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        timestamp="2026-10-05T00:00:00Z",
        path_or_uri="fixtures/recon/data.json",
        raw_record_ref="rec-001",
    )
    scope = {
        "domains": ["corp.internal", "app.corp.internal"],
        "ip_ranges": ["10.10.0.0/16"],
        "exclusions": {
            "domains": ["excluded.corp.internal"],
            "ip_ranges": ["10.10.99.0/24"],
        },
    }
    return {
        "prov": prov,
        "scope": scope,
        "raw_records": [],
        "assets": [],
        "merged": None,
        "reconciled": [],
    }


# Scenario 1: Normalizing multi-source asset telemetry with cryptographic provenance

@given("raw DNS, certificate, IP allocation, endpoint, and cloud export records")
def given_raw_records(bdd_ctx):
    prov = bdd_ctx["prov"]
    bdd_ctx["assets"] = [
        normalize_dns_record({"hostname": "dns.corp.internal", "type": "A", "value": "10.10.1.5", "owner": "netops"}, prov),
        normalize_certificate_record({"subject_cn": "cert.corp.internal", "sans": ["cert.corp.internal"], "owner": "secops"}, prov),
        normalize_ip_record({"ip": "10.10.1.10", "owner": "netops"}, prov),
        normalize_endpoint_record({"url": "https://app.corp.internal:443/login", "owner": "webops"}, prov),
        normalize_cloud_export({"id": "/subscriptions/sub-1/resourceGroups/rg/pip/p1", "provider": "azure", "owner": "cloudops"}, prov),
    ]


@when("the records are normalized into discovered assets")
def when_normalize_records(bdd_ctx):
    assert len(bdd_ctx["assets"]) == 5


@then("each asset contains a canonical identifier and deterministic asset ID")
def then_check_asset_ids(bdd_ctx):
    for a in bdd_ctx["assets"]:
        assert len(a.asset_id) == 24
        assert len(a.identifier) > 0


@then("each asset binds an immutable evidence provenance record with SHA-256 digest")
def then_check_provenance(bdd_ctx):
    for a in bdd_ctx["assets"]:
        assert len(a.provenance) >= 1
        assert len(a.provenance[0].sha256) == 64
        assert a.provenance[0].source_id == "S01"


# Scenario 2: Deduplicating multi-source assets preserves complete evidence lineage

@given("multiple telemetry records observing the same network asset")
def given_multiple_observations(bdd_ctx):
    prov1 = bdd_ctx["prov"]
    prov2 = EvidenceProvenance(
        source_id="S02",
        source_type="cert",
        sha256="1111222233334444555566667777888899990000111122223333444455556666",
        timestamp="2026-10-05T01:00:00Z",
        path_or_uri="fixtures/recon/cert.json",
        raw_record_ref="cert-01",
    )
    a1 = normalize_dns_record({"hostname": "shared.corp.internal", "owner": "netops"}, prov1)
    a2 = normalize_dns_record({"hostname": "shared.corp.internal", "owner": "netops", "ttl": 300}, prov2)
    bdd_ctx["assets"] = [a1, a2]


@when("the discovery merger deduplicates the inventories")
def when_merge_inventories(bdd_ctx):
    bdd_ctx["merged"] = merge_inventories(bdd_ctx["assets"])


@then("a single consolidated asset is produced")
def then_single_asset(bdd_ctx):
    assert len(bdd_ctx["merged"].assets) == 1
    assert bdd_ctx["merged"].assets[0].identifier == "shared.corp.internal"


@then("all distinct evidence provenance envelopes are preserved")
def then_all_provenance_preserved(bdd_ctx):
    provs = bdd_ctx["merged"].assets[0].provenance
    assert len(provs) == 2
    sources = {p.source_id for p in provs}
    assert sources == {"S01", "S02"}


# Scenario 3: Quarantining assets with conflicting ownership

@given("two discovery records asserting contradictory ownership for the same domain")
def given_conflicting_ownership(bdd_ctx):
    prov1 = bdd_ctx["prov"]
    prov2 = EvidenceProvenance(
        source_id="S02",
        source_type="dns",
        sha256="2222333344445555666677778888999900001111222233334444555566667777",
        timestamp="2026-10-05T01:00:00Z",
        path_or_uri="fixtures/recon/dns2.json",
    )
    a1 = normalize_dns_record({"hostname": "conflict.corp.internal", "owner": "finance-org"}, prov1)
    a2 = normalize_dns_record({"hostname": "conflict.corp.internal", "owner": "external-vendor"}, prov2)
    bdd_ctx["assets"] = [a1, a2]


@when("the assets are merged and reconciled against approved scope")
def when_merge_and_reconcile(bdd_ctx):
    inv = merge_inventories(bdd_ctx["assets"])
    bdd_ctx["reconciled"] = [reconcile_asset(a, bdd_ctx["scope"]) for a in inv.assets]


@then(parsers.parse('the asset is classified as "{expected_status}"'))
def then_asset_status(bdd_ctx, expected_status):
    assert bdd_ctx["reconciled"][0].status == expected_status


@then(parsers.parse('"{reason}" is recorded in quarantine reasons'))
def then_quarantine_reason(bdd_ctx, reason):
    assert reason in bdd_ctx["reconciled"][0].quarantine_reasons


# Scenario 4: Quarantining assets with stale or dangling pointers

@given("a DNS record with a dangling target pointer or expired certificate")
def given_stale_record(bdd_ctx):
    bdd_ctx["assets"] = [
        normalize_dns_record(
            {
                "hostname": "stale.corp.internal",
                "value": "10.10.1.10",
                "owner": "netops",
                "stale": True,
            },
            bdd_ctx["prov"],
        )
    ]


@when("the asset is reconciled against approved scope")
def when_reconcile_single_asset(bdd_ctx):
    bdd_ctx["reconciled"] = [reconcile_asset(bdd_ctx["assets"][0], bdd_ctx["scope"])]


# Scenario 5: Quarantining assets with absent provenance or uncertain ownership

@given("a discovered asset without valid evidence provenance or missing an owner")
def given_absent_provenance_asset(bdd_ctx):
    bdd_ctx["assets"] = [
        DiscoveredAsset(
            asset_id="asset-no-owner",
            asset_type="dns",
            identifier="app.corp.internal",
            attributes={"domain": "app.corp.internal"},
            provenance=[],  # Missing provenance
        )
    ]


@then("the asset cannot expand engagement boundaries into verified status")
def then_cannot_expand_boundaries(bdd_ctx):
    assert bdd_ctx["reconciled"][0].status != "verified_in_scope"
    assert bdd_ctx["reconciled"][0].status == "quarantined"


# Scenario 6: Excluding assets matching explicit scope exclusions

@given("discovered assets matching explicit domain or CIDR exclusions")
def given_excluded_assets(bdd_ctx):
    bdd_ctx["assets"] = [
        normalize_dns_record(
            {"hostname": "excluded.corp.internal", "owner": "netops"},
            bdd_ctx["prov"],
        ),
        normalize_ip_record(
            {"ip": "10.10.99.5", "owner": "netops"},
            bdd_ctx["prov"],
        ),
    ]


@when("the assets are reconciled against approved scope")
def when_reconcile_multiple_assets(bdd_ctx):
    bdd_ctx["reconciled"] = [reconcile_asset(a, bdd_ctx["scope"]) for a in bdd_ctx["assets"]]


@then(parsers.parse('the assets are classified as "{expected_status}"'))
def then_multiple_assets_status(bdd_ctx, expected_status):
    for a in bdd_ctx["reconciled"]:
        assert a.status == expected_status
