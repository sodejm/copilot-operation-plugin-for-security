"""Tests for network-active-discovery contributor skill."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    ActiveScanSession,
    ActiveScanner,
    OfflineSyntheticDispatcher,
    ScanBudget,
    ScanVantage,
    compare_active_scans,
)


class TestNetworkActiveDiscoverySkill(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "domains": ["corp.internal"],
            "ip_ranges": ["198.51.100.0/24"],
            "exclusions": {
                "domains": ["forbidden.corp.internal"],
                "ip_ranges": ["198.51.100.99/32"],
            },
        }
        self.mock_targets = {
            "app.corp.internal": {
                "ports": {
                    80: {
                        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
                        "headers": {"Server": "nginx/1.18.0"},
                        "http_status": 200,
                    },
                    443: {
                        "tls": {
                            "version": "TLSv1.3",
                            "cipher_suite": "TLS_AES_256_GCM_SHA384",
                            "subject_cn": "app.corp.internal",
                            "sans": ["app.corp.internal", "www.corp.internal"],
                            "valid_until": "2027-01-01T00:00:00Z",
                        },
                        "headers": {"Server": "nginx/1.18.0"},
                        "http_status": 200,
                    },
                    22: {
                        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
                    },
                }
            }
        }
        self.dns_map = {
            "app.corp.internal": "198.51.100.10",
        }

    def test_bounded_scan_and_fingerprint_generation(self):
        session = ActiveScanSession(
            session_id="test-session-001",
            scope_reference="ROE-TEST",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 22],
            vantage=ScanVantage.EXTERNAL.value,
            budget=ScanBudget(rate_limit_pps=100.0),
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        completed = scanner.run()
        self.assertEqual(completed.status, "completed")
        self.assertEqual(len(completed.assessments), 3)
        self.assertEqual(completed.total_side_effects, 3)

        # Verify fingerprints
        ass_by_port = {a.port: a for a in completed.assessments}
        ssh_ass = ass_by_port[22]
        self.assertEqual(ssh_ass.inferred_fingerprint.service_name, "ssh")
        self.assertEqual(ssh_ass.inferred_fingerprint.product, "OpenSSH")
        self.assertEqual(ssh_ass.inferred_fingerprint.confidence, "high")

        http_ass = ass_by_port[80]
        self.assertEqual(http_ass.inferred_fingerprint.service_name, "http")
        self.assertEqual(http_ass.inferred_fingerprint.product, "nginx")
        self.assertIn("Server header can be masked", " ".join(http_ass.inferred_fingerprint.uncertainty_reasons))

    def test_resumable_execution_avoids_repeated_side_effects(self):
        session = ActiveScanSession(
            session_id="test-resume-001",
            scope_reference="ROE-TEST",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 22],
            vantage=ScanVantage.EXTERNAL.value,
            budget=ScanBudget(rate_limit_pps=100.0),
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)

        # Pre-mark port 80 as already completed
        key_80 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 80)
        session.completed_probe_keys.add(key_80)

        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)
        resumed = scanner.run()

        # Should only dispatch remaining ports (443 and 22)
        self.assertEqual(dispatcher.side_effect_count, 2)
        self.assertEqual(len(resumed.assessments), 2)
        self.assertNotIn(80, {a.port for a in resumed.assessments})

    def test_scope_shift_and_dns_rebind_quarantine(self):
        session = ActiveScanSession(
            session_id="test-rebind-001",
            scope_reference="ROE-TEST",
            approved_targets=["app.corp.internal"],
            approved_ports=[80],
            vantage=ScanVantage.EXTERNAL.value,
        )
        # Point to excluded/out-of-scope IP
        rebind_dns = {"app.corp.internal": "10.0.0.1"}
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=rebind_dns)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        result = scanner.run()
        self.assertEqual(len(result.assessments), 0)
        self.assertEqual(len(result.quarantined_targets), 1)
        self.assertEqual(result.quarantined_targets[0].reason, "dns_rebind_detected")
        self.assertEqual(dispatcher.side_effect_count, 0)

    def test_remediation_delta_comparison(self):
        base_session = ActiveScanSession(
            session_id="baseline",
            scope_reference="ROE-TEST",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 22],
        )
        disp_base = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner_base = ActiveScanner(session=base_session, dispatcher=disp_base, scope=self.scope)
        base_session = scanner_base.run()

        # Current session: port 22 remediated (closed)
        remediated_targets = {
            "app.corp.internal": {
                "ports": {
                    80: self.mock_targets["app.corp.internal"]["ports"][80],
                    22: {"state": "closed"},
                }
            }
        }
        curr_session = ActiveScanSession(
            session_id="current",
            scope_reference="ROE-TEST",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 22],
        )
        disp_curr = OfflineSyntheticDispatcher(targets=remediated_targets, dns_map=self.dns_map)
        scanner_curr = ActiveScanner(session=curr_session, dispatcher=disp_curr, scope=self.scope)
        curr_session = scanner_curr.run()

        delta = compare_active_scans(base_session, curr_session)
        self.assertEqual(len(delta.remediated_exposures), 1)
        self.assertEqual(delta.remediated_exposures[0]["port"], 22)
        self.assertEqual(len(delta.persistent_exposures), 1)
        self.assertEqual(delta.persistent_exposures[0]["port"], 80)
        self.assertEqual(delta.remediation_rate, 50.0)


if __name__ == "__main__":
    unittest.main()
