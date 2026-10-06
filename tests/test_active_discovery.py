"""Unit and contract tests for bounded active discovery, service identification, and resumability."""

from __future__ import annotations

import argparse
import json
import ssl
import tempfile
import time
import unittest
from pathlib import Path

from cops.discovery import (
    ActiveScanSession,
    ActiveScanner,
    ActiveServiceAssessment,
    ConfidenceLevel,
    ObservedConfiguration,
    ObservedTLS,
    OfflineSyntheticDispatcher,
    PortState,
    Protocol,
    ScanBudget,
    ScanDelta,
    ScanVantage,
    ServiceReachability,
    compare_active_scans,
    import_masscan_json,
    import_nmap_xml,
    infer_service_fingerprint,
)
from cops.discovery.active_scanner import _create_tls_context
from cops.discovery.cli import command_active_discovery


class TestActiveDiscoveryModelsAndFingerprinting(unittest.TestCase):
    def test_live_tls_probe_requires_tls_12_or_newer(self):
        context = _create_tls_context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_ssh_fingerprint_high_confidence(self):
        obs = ObservedConfiguration(raw_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        fp = infer_service_fingerprint("ssh.corp.internal", 22, "tcp", obs)
        self.assertEqual(fp.service_name, "ssh")
        self.assertEqual(fp.product, "OpenSSH")
        self.assertEqual(fp.version, "8.9p1")
        self.assertEqual(fp.os_inferred, "Ubuntu Linux")
        self.assertEqual(fp.confidence, ConfidenceLevel.HIGH.value)
        self.assertIn("ssh_protocol_banner", fp.evidence_sources)

    def test_http_nginx_fingerprint_with_proxy_uncertainty(self):
        obs = ObservedConfiguration(
            http_status=200,
            http_headers={"Server": "nginx/1.18.0", "Content-Type": "text/html"},
        )
        fp = infer_service_fingerprint("web.corp.internal", 80, "tcp", obs)
        self.assertEqual(fp.service_name, "http")
        self.assertEqual(fp.product, "nginx")
        self.assertEqual(fp.version, "1.18.0")
        self.assertEqual(fp.confidence, ConfidenceLevel.MEDIUM.value)
        self.assertTrue(any("Server header can be masked" in r for r in fp.uncertainty_reasons))

    def test_cloudflare_cdn_masking_detected(self):
        obs = ObservedConfiguration(
            http_status=403,
            http_headers={"Server": "cloudflare", "cf-ray": "823902348092-IAD"},
        )
        fp = infer_service_fingerprint("edge.example.com", 443, "tcp", obs)
        self.assertEqual(fp.service_name, "https")
        self.assertEqual(fp.product, "Cloudflare Edge Proxy")
        self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)
        self.assertTrue(any("Cloudflare reverse proxy fronting origin" in r for r in fp.uncertainty_reasons))

    def test_tls_mismatched_san_records_uncertainty(self):
        tls = ObservedTLS(
            version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            subject_cn="other.internal",
            sans=["other.internal", "alt.internal"],
            valid_until="2028-01-01T00:00:00Z",
        )
        obs = ObservedConfiguration(tls=tls, http_status=200)
        fp = infer_service_fingerprint("target.corp.internal", 443, "tcp", obs)
        self.assertEqual(fp.service_name, "https")
        self.assertEqual(fp.confidence, ConfidenceLevel.LOW.value)
        self.assertTrue(any("does not match target host" in r for r in fp.uncertainty_reasons))

    def test_expired_tls_certificate_uncertainty(self):
        tls = ObservedTLS(
            version="TLSv1.2",
            subject_cn="target.corp.internal",
            sans=["target.corp.internal"],
            valid_until="2020-01-01T00:00:00Z",
        )
        obs = ObservedConfiguration(tls=tls, http_status=200)
        fp = infer_service_fingerprint("target.corp.internal", 443, "tcp", obs)
        self.assertTrue(any("TLS certificate is expired" in r for r in fp.uncertainty_reasons))

    def test_generic_open_port_without_banner_is_uncertain(self):
        obs = ObservedConfiguration()
        fp = infer_service_fingerprint("198.51.100.10", 9999, "tcp", obs)
        self.assertEqual(fp.service_name, "unknown-9999")
        self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)
        self.assertTrue(any("Port accepted TCP connection but emitted no descriptive" in r for r in fp.uncertainty_reasons))


class TestActiveScannerExecutionAndBudgets(unittest.TestCase):
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
                    80: {"banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n", "headers": {"Server": "Apache/2.4.41 (Ubuntu)"}, "http_status": 200},
                    443: {"tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal", "sans": ["app.corp.internal"]}, "headers": {"Server": "Apache/2.4.41 (Ubuntu)"}, "http_status": 200},
                    8080: {"state": "closed"},
                    9000: {"state": "filtered", "timeout": True},
                }
            },
            "unreachable.corp.internal": {
                "unreachable": True,
            },
        }
        self.dns_map = {
            "app.corp.internal": "198.51.100.10",
            "unreachable.corp.internal": "198.51.100.50",
            "forbidden.corp.internal": "198.51.100.20",
        }

    def test_full_bounded_assessment(self):
        session = ActiveScanSession(
            session_id="sess-001",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 8080, 9000],
            vantage=ScanVantage.EXTERNAL.value,
            budget=ScanBudget(rate_limit_pps=200.0),
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        completed = scanner.run()
        self.assertEqual(completed.status, "completed")
        self.assertEqual(len(completed.assessments), 4)

        ports = {a.port: a.port_state for a in completed.assessments}
        self.assertEqual(ports[80], PortState.OPEN.value)
        self.assertEqual(ports[443], PortState.OPEN.value)
        self.assertEqual(ports[8080], PortState.CLOSED.value)
        self.assertEqual(ports[9000], PortState.FILTERED.value)

    def test_unreachable_host_handling(self):
        session = ActiveScanSession(
            session_id="sess-unreach",
            scope_reference="ROE-2026-001",
            approved_targets=["unreachable.corp.internal"],
            approved_ports=[80],
            vantage=ScanVantage.INTERNAL.value,
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        completed = scanner.run()
        self.assertEqual(len(completed.assessments), 1)
        ass = completed.assessments[0]
        self.assertEqual(ass.reachability, ServiceReachability.UNREACHABLE.value)
        self.assertEqual(ass.port_state, PortState.UNREACHABLE.value)
        self.assertIn("unreachable", ass.error_message.lower())

    def test_resumable_execution_does_not_repeat_side_effects(self):
        session = ActiveScanSession(
            session_id="sess-resume",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 8080],
            vantage=ScanVantage.EXTERNAL.value,
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)

        # Pre-mark port 80 and 443 as completed
        key_80 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 80)
        key_443 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 443)
        session.completed_probe_keys.update([key_80, key_443])

        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)
        resumed = scanner.run()

        # Only port 8080 dispatched
        self.assertEqual(dispatcher.side_effect_count, 1)
        self.assertEqual(len(resumed.assessments), 1)
        self.assertEqual(resumed.assessments[0].port, 8080)

    def test_dns_rebind_and_target_shift_detection(self):
        session = ActiveScanSession(
            session_id="sess-rebind",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80],
        )
        # DNS resolves to out-of-scope IP 10.0.0.1
        bad_dns = {"app.corp.internal": "10.0.0.1"}
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=bad_dns)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        completed = scanner.run()
        self.assertEqual(dispatcher.side_effect_count, 0)
        self.assertEqual(len(completed.assessments), 0)
        self.assertEqual(len(completed.quarantined_targets), 1)
        self.assertEqual(completed.quarantined_targets[0].reason, "dns_rebind_detected")

    def test_explicit_domain_exclusion_quarantine(self):
        session = ActiveScanSession(
            session_id="sess-excl",
            scope_reference="ROE-2026-001",
            approved_targets=["forbidden.corp.internal"],
            approved_ports=[80],
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        completed = scanner.run()
        self.assertEqual(dispatcher.side_effect_count, 0)
        self.assertEqual(len(completed.quarantined_targets), 1)
        self.assertEqual(completed.quarantined_targets[0].reason, "outside_scope")

    def test_budget_exhaustion_preserves_partial_results(self):
        session = ActiveScanSession(
            session_id="sess-budget",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 8080, 9000],
            budget=ScanBudget(max_targets=1, max_total_seconds=0.0001),  # tiny budget
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)

        completed = scanner.run()
        self.assertEqual(completed.status, "budget_exhausted")

    def test_rate_limiting_delay_invoked(self):
        session = ActiveScanSession(
            session_id="sess-rate",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443],
            budget=ScanBudget(rate_limit_pps=5.0),  # interval 0.2s
        )
        sleep_calls = []

        def mock_sleep(d: float) -> None:
            sleep_calls.append(d)

        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope, sleeper=mock_sleep)

        scanner.run()
        self.assertEqual(len(sleep_calls), 2)
        self.assertAlmostEqual(sleep_calls[0], 0.2, places=2)


class TestRemediatedExposureVerification(unittest.TestCase):
    def test_compare_active_scans_calculates_remediation_delta(self):
        mock_baseline = {
            "app.corp.internal": {
                "ports": {
                    80: {"banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n", "headers": {"Server": "Apache/2.4.41"}},
                    443: {"tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal"}},
                    22: {"banner": "SSH-2.0-OpenSSH_7.4\r\n"},
                }
            }
        }
        dns_map = {"app.corp.internal": "198.51.100.10"}
        disp_base = OfflineSyntheticDispatcher(targets=mock_baseline, dns_map=dns_map)
        sess_base = ActiveScanSession(
            session_id="baseline-01",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 22],
        )
        scanner_base = ActiveScanner(session=sess_base, dispatcher=disp_base)
        sess_base = scanner_base.run()

        # Re-test: port 22 remediated (closed), port 80 updated to Apache 2.4.52, port 8443 new exposure
        mock_current = {
            "app.corp.internal": {
                "ports": {
                    80: {"banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n", "headers": {"Server": "Apache/2.4.52"}},
                    443: {"tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal"}},
                    22: {"state": "closed"},
                    8443: {"tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal"}},
                }
            }
        }
        disp_curr = OfflineSyntheticDispatcher(targets=mock_current, dns_map=dns_map)
        sess_curr = ActiveScanSession(
            session_id="current-02",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443, 22, 8443],
        )
        scanner_curr = ActiveScanner(session=sess_curr, dispatcher=disp_curr)
        sess_curr = scanner_curr.run()

        delta = compare_active_scans(sess_base, sess_curr)
        self.assertEqual(len(delta.remediated_exposures), 1)
        self.assertEqual(delta.remediated_exposures[0]["port"], 22)
        self.assertEqual(len(delta.persistent_exposures), 2)
        self.assertEqual(len(delta.new_exposures), 1)
        self.assertEqual(delta.new_exposures[0]["port"], 8443)
        self.assertEqual(len(delta.fingerprint_changes), 1)
        self.assertEqual(delta.fingerprint_changes[0]["port"], 80)
        self.assertEqual(delta.fingerprint_changes[0]["previous_version"], "2.4.41")
        self.assertEqual(delta.fingerprint_changes[0]["current_version"], "2.4.52")
        self.assertAlmostEqual(delta.remediation_rate, 33.33, places=1)


class TestToolOutputImporters(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_import_masscan_json(self):
        masscan_data = [
            {"ip": "198.51.100.10", "timestamp": "1728130000", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 58}]},
            {"ip": "198.51.100.10", "timestamp": "1728130005", "ports": [{"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 58}]},
            {"ip": "198.51.100.20", "timestamp": "1728130010", "ports": [{"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 60}]},
        ]
        file_path = self.root / "masscan.json"
        file_path.write_text(json.dumps(masscan_data), encoding="utf-8")

        session = import_masscan_json(file_path, vantage="external", scope_ref="MASS-01")
        self.assertEqual(session.status, "completed")
        self.assertEqual(len(session.assessments), 3)
        self.assertEqual(set(session.approved_targets), {"198.51.100.10", "198.51.100.20"})
        self.assertEqual(set(session.approved_ports), {80, 443, 22})
        self.assertEqual(session.assessments[0].provenance.source_type, "masscan_export")

    def test_import_nmap_xml(self):
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX out.xml 198.51.100.10">
<host>
  <status state="up"/>
  <address addr="198.51.100.10" addrtype="ipv4"/>
  <hostnames>
    <hostname name="web.corp.internal" type="user"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="nginx" version="1.18.0" method="probed"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="nginx" version="1.18.0" tunnel="ssl" method="probed"/>
      <script id="ssl-cert" output="Subject: commonName=web.corp.internal"/>
    </port>
  </ports>
</host>
</nmaprun>
"""
        file_path = self.root / "nmap.xml"
        file_path.write_text(nmap_xml, encoding="utf-8")

        session = import_nmap_xml(file_path, vantage="external", scope_ref="NMAP-01")
        self.assertEqual(len(session.assessments), 2)
        self.assertEqual(session.approved_targets, ["web.corp.internal"])
        self.assertEqual(session.approved_ports, [80, 443])

        p80 = next(a for a in session.assessments if a.port == 80)
        self.assertEqual(p80.inferred_fingerprint.product, "nginx")
        self.assertEqual(p80.inferred_fingerprint.version, "1.18.0")
        self.assertEqual(p80.inferred_fingerprint.confidence, ConfidenceLevel.HIGH.value)

        p443 = next(a for a in session.assessments if a.port == 443)
        self.assertEqual(p443.observed_config.tls.subject_cn, "web.corp.internal")


class TestActiveDiscoveryCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_cli_plan_scan_resume_diff_pipeline(self):
        plan_out = str(self.root / "plan.json")
        scan_out = str(self.root / "scan.json")
        chk_out = str(self.root / "chk.json")
        delta_out = str(self.root / "delta.json")

        # 1. plan
        args_plan = argparse.Namespace(
            active_command="plan",
            targets="198.51.100.10,app.corp.internal",
            ports="80,443",
            vantage="external",
            rate_limit=50.0,
            timeout=2.0,
            max_total_seconds=None,
            scope_ref="ENG-01",
            output=plan_out,
        )
        self.assertEqual(command_active_discovery(args_plan), 0)
        self.assertTrue(Path(plan_out).is_file())

        # 2. scan (with checkpoint)
        args_scan = argparse.Namespace(
            active_command="scan",
            session=plan_out,
            scope=None,
            mode="synthetic",
            offline_targets=None,
            checkpoint=chk_out,
            output=scan_out,
        )
        self.assertEqual(command_active_discovery(args_scan), 0)
        self.assertTrue(Path(scan_out).is_file())
        self.assertTrue(Path(chk_out).is_file())

        # 3. resume (checkpoint)
        res_out = str(self.root / "resumed.json")
        args_resume = argparse.Namespace(
            active_command="resume",
            checkpoint=chk_out,
            scope=None,
            mode="synthetic",
            offline_targets=None,
            checkpoint_out=None,
            output=res_out,
        )
        self.assertEqual(command_active_discovery(args_resume), 0)
        self.assertTrue(Path(res_out).is_file())

        # 4. diff baseline vs current
        args_diff = argparse.Namespace(
            active_command="diff",
            baseline=scan_out,
            current=res_out,
            output=delta_out,
        )
        self.assertEqual(command_active_discovery(args_diff), 0)
        self.assertTrue(Path(delta_out).is_file())
        delta = json.loads(Path(delta_out).read_text(encoding="utf-8"))
        self.assertIn("remediation_rate", delta)


if __name__ == "__main__":
    unittest.main()
