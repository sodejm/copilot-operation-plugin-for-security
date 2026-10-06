# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Tests for network-passive-discovery contributor skill."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    EvidenceProvenance,
    merge_inventories,
    normalize_dns_record,
    reconcile_asset,
)


class TestNetworkPassiveDiscoverySkill(unittest.TestCase):
    def setUp(self):
        self.prov = EvidenceProvenance(
            source_id="S01",
            source_type="dns",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            timestamp="2026-10-05T00:00:00Z",
            path_or_uri="fixtures/recon/dns.json",
        )
        self.scope = {
            "domains": ["corp.internal", "app.corp.internal"],
            "ip_ranges": ["10.0.0.0/16"],
            "exclusions": {
                "domains": ["forbidden.corp.internal"],
                "ip_ranges": ["10.0.99.0/24"],
            },
        }

    def test_normalization_and_reconciliation_pass(self):
        raw_rec = {
            "domain": "app.corp.internal",
            "type": "A",
            "value": "10.0.1.10",
            "owner": "secops-team",
        }
        asset = normalize_dns_record(raw_rec, self.prov)
        self.assertEqual(asset.asset_type, "dns")
        self.assertEqual(asset.identifier, "app.corp.internal")

        reconciled = reconcile_asset(asset, self.scope)
        self.assertEqual(reconciled.status, "verified_in_scope")
        self.assertEqual(len(reconciled.quarantine_reasons), 0)

    def test_quarantine_uncertain_ownership(self):
        raw_rec = {
            "domain": "app.corp.internal",
            "type": "A",
            "value": "10.0.1.10",
            # owner missing
        }
        asset = normalize_dns_record(raw_rec, self.prov)
        reconciled = reconcile_asset(asset, self.scope)
        self.assertEqual(reconciled.status, "quarantined")
        self.assertIn("uncertain_ownership", reconciled.quarantine_reasons)

    def test_deduplication_preserves_provenance(self):
        asset1 = normalize_dns_record(
            {"domain": "app.corp.internal", "type": "A", "owner": "secops"},
            self.prov,
        )
        prov2 = EvidenceProvenance(
            source_id="S02",
            source_type="dns",
            sha256="1111222233334444555566667777888899990000111122223333444455556666",
            timestamp="2026-10-05T01:00:00Z",
            path_or_uri="fixtures/recon/cert.json",
        )
        asset2 = normalize_dns_record(
            {"domain": "app.corp.internal", "type": "A", "owner": "secops"},
            prov2,
        )

        inv = merge_inventories([asset1], [asset2])
        self.assertEqual(len(inv.assets), 1)
        self.assertEqual(len(inv.assets[0].provenance), 2)


if __name__ == "__main__":
    unittest.main()
