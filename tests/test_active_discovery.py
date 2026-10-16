"""Unit and contract tests for bounded active discovery, service identification, and resumability."""

from __future__ import annotations

import argparse
import errno
import json
import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cops.discovery import (
    ActiveScanner,
    ActiveScanSession,
    ActiveServiceAssessment,
    ConfidenceLevel,
    ObservedConfiguration,
    ObservedTLS,
    OfflineSyntheticDispatcher,
    PortState,
    ScanBudget,
    ScanVantage,
    ServiceReachability,
    compare_active_scans,
    expand_target_specs,
    import_masscan_json,
    import_nmap_xml,
    infer_service_fingerprint,
)
from cops.discovery.active_models import MAX_ACTIVE_PLANNED_PROBES, TargetShiftQuarantine, active_assessment_digest
from cops.discovery.active_scanner import (
    ActiveScanError,
    ProbeDispatcher,
    StandardSocketDispatcher,
    _create_tls_context,
    _live_checkpoint_lock,
)
from cops.discovery.cli import build_active_parser, command_active_discovery


class TestActiveDiscoveryModelsAndFingerprinting(unittest.TestCase):
    @staticmethod
    def _journal_session() -> ActiveScanSession:
        return ActiveScanSession(
            session_id="journal-boundary",
            scope_reference="approved-engagement",
            approved_targets=["127.0.0.1"],
            approved_ports=[65000, 65001],
            budget=ScanBudget(max_probes=2),
        )

    def test_target_specs_expand_bounded_ipv4_and_ipv6_cidrs(self):
        self.assertEqual(
            expand_target_specs(
                ["192.0.2.0/31", "2001:db8::/127", "EXAMPLE.test"],
                max_targets=5,
            ),
            ["192.0.2.0", "192.0.2.1", "2001:db8::", "2001:db8::1", "example.test"],
        )
        with self.assertRaisesRegex(ValueError, "max_targets"):
            expand_target_specs(["192.0.2.0/29"], max_targets=4)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            expand_target_specs(["2001:db8::/127", "2001:0db8:0:0:0:0:0:1"], max_targets=4)

    def test_checkpoint_round_trips_beyond_default_evidence_limit(self):
        session = ActiveScanSession(
            session_id="full-tcp-checkpoint",
            scope_reference="approved-engagement",
            approved_targets=["198.51.100.10"],
            approved_ports=list(range(1, 1201)),
            budget=ScanBudget(max_probes=1200),
        )
        session.assessments = [
            ActiveServiceAssessment(
                probe_id=f"probe-{port}",
                target_host="198.51.100.10",
                resolved_ip="198.51.100.10",
                port=port,
                observed_config=ObservedConfiguration(raw_banner="B" * 1024),
            )
            for port in session.approved_ports
        ]
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            session.save_checkpoint(checkpoint)
            self.assertGreater(checkpoint.stat().st_size, 1024 * 1024)
            restored = ActiveScanSession.load_checkpoint(checkpoint)
        self.assertEqual(len(restored.assessments), 1200)
        self.assertEqual(restored.assessments[-1].port, 1200)

    def test_checkpoint_journal_rejects_symlink_without_touching_target(self):
        session = self._journal_session()
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            victim = Path(directory) / "victim"
            session.save_checkpoint(checkpoint)
            victim.write_bytes(b"unchanged")
            victim.chmod(0o600)
            journal = session.checkpoint_journal_path(checkpoint)
            try:
                journal.symlink_to(victim)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                session.append_probe_reservation(checkpoint, key)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                ActiveScanSession.load_checkpoint(checkpoint)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                session.save_checkpoint(checkpoint)
            self.assertEqual(victim.read_bytes(), b"unchanged")
            self.assertTrue(journal.is_symlink())

    def test_checkpoint_journal_rejects_hard_link_without_touching_target(self):
        session = self._journal_session()
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            victim = Path(directory) / "victim"
            session.save_checkpoint(checkpoint)
            victim.write_bytes(b"unchanged")
            victim.chmod(0o600)
            journal = session.checkpoint_journal_path(checkpoint)
            try:
                os.link(victim, journal)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
            with self.assertRaisesRegex(ValueError, "hard links"):
                session.append_probe_reservation(checkpoint, key)
            with self.assertRaisesRegex(ValueError, "hard links"):
                ActiveScanSession.load_checkpoint(checkpoint)
            with self.assertRaisesRegex(ValueError, "hard links"):
                session.save_checkpoint(checkpoint)
            self.assertEqual(victim.read_bytes(), b"unchanged")
            self.assertTrue(journal.exists())

    def test_checkpoint_journal_replays_completion_and_release(self):
        session = self._journal_session()
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            session.save_checkpoint(checkpoint)
            first = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
            second = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65001)
            session.append_probe_reservations(checkpoint, [first, second])
            assessment = ActiveServiceAssessment(
                probe_id="journal-probe",
                target_host="127.0.0.1",
                resolved_ip="127.0.0.1",
                port=65000,
                vantage=session.vantage,
            )
            session.append_probe_completion(checkpoint, first, assessment)
            session.append_probe_release(checkpoint, [second])
            restored = ActiveScanSession.load_checkpoint(checkpoint)
        self.assertEqual(restored.completed_probe_keys, {first})
        self.assertEqual(restored.pending_probe_keys, set())
        self.assertEqual(restored.total_probes_dispatched, 1)
        self.assertEqual(restored.total_side_effects, 1)
        self.assertEqual([item.probe_id for item in restored.assessments], ["journal-probe"])

    def test_checkpoint_journal_portable_path_replays_and_compacts(self):
        session = self._journal_session()
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            session.save_checkpoint(checkpoint)
            key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
            assessment = ActiveServiceAssessment(
                probe_id="portable-journal-probe",
                target_host="127.0.0.1",
                resolved_ip="127.0.0.1",
                port=65000,
                vantage=session.vantage,
            )

            with patch.object(
                ActiveScanSession,
                "_supports_checkpoint_directory_fd",
                return_value=False,
            ):
                session.append_probe_reservation(checkpoint, key)
                session.append_probe_completion(checkpoint, key, assessment)
                restored = ActiveScanSession.load_checkpoint(checkpoint)
                restored.save_checkpoint(checkpoint)

            self.assertFalse(session.checkpoint_journal_path(checkpoint).exists())
            compacted = ActiveScanSession.load_checkpoint(checkpoint)

        self.assertEqual(compacted.completed_probe_keys, {key})
        self.assertEqual(compacted.pending_probe_keys, set())
        self.assertEqual([item.probe_id for item in compacted.assessments], ["portable-journal-probe"])

    def test_checkpoint_journal_portable_cleanup_closes_before_unlink(self):
        session = self._journal_session()
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            session.save_checkpoint(checkpoint)
            key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
            journal = session.checkpoint_journal_path(checkpoint)
            with patch.object(
                ActiveScanSession,
                "_supports_checkpoint_directory_fd",
                return_value=False,
            ):
                session.append_probe_reservation(checkpoint, key)

            real_open = os.open
            real_close = os.close
            real_unlink = os.unlink
            journal_descriptors: set[int] = set()
            unlink_saw_open_descriptor: list[bool] = []

            def tracking_open(path, *args, **kwargs):
                descriptor = real_open(path, *args, **kwargs)
                if Path(path) == journal:
                    journal_descriptors.add(descriptor)
                return descriptor

            def tracking_close(descriptor):
                journal_descriptors.discard(descriptor)
                real_close(descriptor)

            def windows_unlink(path, *args, **kwargs):
                if Path(path) == journal:
                    unlink_saw_open_descriptor.append(bool(journal_descriptors))
                    if journal_descriptors:
                        raise PermissionError(errno.EACCES, "file is open", path)
                real_unlink(path, *args, **kwargs)

            with (
                patch.object(
                    ActiveScanSession,
                    "_supports_checkpoint_directory_fd",
                    return_value=False,
                ),
                patch("cops.discovery.active_models.os.open", side_effect=tracking_open),
                patch("cops.discovery.active_models.os.close", side_effect=tracking_close),
                patch("cops.discovery.active_models.os.unlink", side_effect=windows_unlink),
            ):
                self.assertTrue(session._remove_checkpoint_journal(checkpoint))

            self.assertEqual(unlink_saw_open_descriptor, [False])
            self.assertFalse(journal.exists())

    def test_checkpoint_journal_portable_path_rejects_links_without_mutation(self):
        for link_kind in ("symlink", "hardlink"):
            with self.subTest(link_kind=link_kind), tempfile.TemporaryDirectory() as directory:
                session = self._journal_session()
                checkpoint = Path(directory) / "checkpoint.json"
                victim = Path(directory) / "victim"
                session.save_checkpoint(checkpoint)
                victim.write_bytes(b"unchanged")
                victim.chmod(0o600)
                journal = session.checkpoint_journal_path(checkpoint)
                try:
                    if link_kind == "symlink":
                        journal.symlink_to(victim)
                    else:
                        os.link(victim, journal)
                except (NotImplementedError, OSError) as error:
                    self.skipTest(f"{link_kind} unavailable: {error}")
                key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)

                with (
                    patch.object(
                        ActiveScanSession,
                        "_supports_checkpoint_directory_fd",
                        return_value=False,
                    ),
                    self.assertRaisesRegex(ValueError, "unsafe|hard links"),
                ):
                    session.append_probe_reservation(checkpoint, key)

                self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_truncated_final_completion_keeps_durable_reservation_pending(self):
        session = self._journal_session()
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            session.save_checkpoint(checkpoint)
            key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
            session.append_probe_reservation(checkpoint, key)
            journal = session.checkpoint_journal_path(checkpoint)
            with journal.open("ab") as stream:
                stream.write(b'{"event":"complete"')
            restored = ActiveScanSession.load_checkpoint(checkpoint)
        self.assertEqual(restored.pending_probe_keys, {key})
        self.assertEqual(restored.completed_probe_keys, set())
        self.assertEqual(restored.total_probes_dispatched, 1)
        self.assertEqual(restored.total_side_effects, 0)

    def test_live_tls_probe_requires_tls_12_or_newer(self):
        context = _create_tls_context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_ssh_fingerprint_preserves_banner_uncertainty(self):
        obs = ObservedConfiguration(raw_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        fp = infer_service_fingerprint("ssh.corp.internal", 22, "tcp", obs)
        self.assertEqual(fp.service_name, "ssh")
        self.assertEqual(fp.product, "OpenSSH")
        self.assertEqual(fp.version, "8.9p1")
        self.assertIsNone(fp.os_inferred)
        self.assertEqual(fp.confidence, ConfidenceLevel.MEDIUM.value)
        self.assertTrue(any("self-reported" in reason for reason in fp.uncertainty_reasons))
        self.assertIn("ssh_protocol_banner", fp.evidence_sources)

    def test_generic_220_banner_does_not_identify_smtp_or_ftp_by_port(self):
        for port in (21, 25, 465, 587):
            with self.subTest(port=port):
                fp = infer_service_fingerprint(
                    "198.51.100.10", port, "tcp", ObservedConfiguration(raw_banner="220 Welcome\r\n")
                )
                self.assertEqual(fp.service_name, f"unknown-{port}")
                self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)

    def test_udp_dns_requires_a_validated_query_response(self):
        for valid, expected in ((True, "dns"), (False, "unknown-5353")):
            with self.subTest(valid=valid):
                observed = ObservedConfiguration(
                    protocol_metadata={"probe_payload": "dns_root_ns_query", "dns_response_validated": valid}
                )
                fingerprint = infer_service_fingerprint("198.51.100.10", 5353, "udp", observed)
                self.assertEqual(fingerprint.service_name, expected)
                self.assertIsNone(fingerprint.product)
                self.assertIsNone(fingerprint.version)

    def test_protocol_specific_220_banner_identifies_service_on_nonstandard_port(self):
        for port, banner, service in (
            (2525, "220 mail.example.com ESMTP Postfix\r\n", "smtp"),
            (2121, "220 FTP service ready\r\n", "ftp"),
        ):
            with self.subTest(port=port):
                fp = infer_service_fingerprint("198.51.100.10", port, "tcp", ObservedConfiguration(raw_banner=banner))
                self.assertEqual(fp.service_name, service)
                self.assertEqual(fp.confidence, ConfidenceLevel.MEDIUM.value)

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
        self.assertEqual(fp.service_name, "http")
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

    def test_invalid_or_naive_tls_expiry_records_uncertainty(self):
        for expiry in ("invalid", "2028-01-01T00:00:00"):
            with self.subTest(expiry=expiry):
                tls = ObservedTLS(subject_cn="target.example.com", sans=["target.example.com"], valid_until=expiry)
                fp = infer_service_fingerprint("target.example.com", 443, "tcp", ObservedConfiguration(tls=tls))
                self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)
                self.assertTrue(any("expiry date could not be parsed" in reason for reason in fp.uncertainty_reasons))

    def test_tls_handshake_does_not_claim_http(self):
        fp = infer_service_fingerprint(
            "target.example.com", 443, "tcp", ObservedConfiguration(tls=ObservedTLS(version="TLSv1.3"))
        )
        self.assertEqual(fp.service_name, "tls")
        self.assertEqual(fp.evidence_sources, ["tls_handshake"])
        self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)

    def test_port_association_is_not_http_evidence(self):
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                fp = infer_service_fingerprint("198.51.100.10", 443, protocol, ObservedConfiguration())
                self.assertEqual(fp.service_name, "unknown-443")
                self.assertEqual(fp.evidence_sources, ["port_association"])
                self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)
                self.assertNotIn("http_service_probe", fp.evidence_sources)
                self.assertNotIn("tls_handshake", fp.evidence_sources)

    def test_generic_open_port_without_banner_is_uncertain(self):
        obs = ObservedConfiguration()
        fp = infer_service_fingerprint("198.51.100.10", 9999, "tcp", obs)
        self.assertEqual(fp.service_name, "unknown-9999")
        self.assertEqual(fp.confidence, ConfidenceLevel.UNCERTAIN.value)
        self.assertTrue(
            any("Port accepted TCP connection but emitted no descriptive" in r for r in fp.uncertainty_reasons)
        )

    def test_coverage_summary_matches_quarantined_hosts_across_many_targets(self):
        targets = [f"host-{index}.example" for index in range(200)]
        quarantined = targets[::2]
        session = ActiveScanSession(
            session_id="quarantine-coverage",
            scope_reference="approved-engagement",
            approved_targets=targets,
            approved_ports=[443],
            budget=ScanBudget(max_probes=200),
            quarantined_targets=[
                TargetShiftQuarantine(target_host=host, original_ip="192.0.2.1", new_ip="192.0.2.2", reason="shift")
                for host in quarantined
            ],
        )
        summary = session.coverage_summary()
        self.assertEqual(summary["planned"], 200)
        self.assertEqual(summary["skipped"]["quarantined"], 100)
        self.assertEqual(summary["unassessed"], 100)


class TestStandardSocketDispatcherErrors(unittest.TestCase):
    def test_network_route_error_is_unreachable_and_refusal_is_closed(self):
        dispatcher = StandardSocketDispatcher()
        cases = (
            (errno.ENETUNREACH, PortState.UNREACHABLE.value, ServiceReachability.UNREACHABLE.value),
            (errno.EHOSTUNREACH, PortState.UNREACHABLE.value, ServiceReachability.UNREACHABLE.value),
            (errno.ECONNREFUSED, PortState.CLOSED.value, ServiceReachability.REACHABLE.value),
            (errno.EACCES, PortState.UNKNOWN.value, ServiceReachability.UNKNOWN.value),
        )
        for error_number, expected_state, expected_reachability in cases:
            with self.subTest(error_number=error_number):
                with patch(
                    "cops.discovery.active_scanner.socket.create_connection",
                    side_effect=OSError(error_number, "socket failure"),
                ):
                    assessment = dispatcher.dispatch_probe("127.0.0.1", "127.0.0.1", 12345)
                self.assertEqual(assessment.port_state, expected_state)
                self.assertEqual(assessment.reachability, expected_reachability)

    def test_udp_timeout_is_unknown_and_counted_as_timed_out(self):
        class TimeoutSocket:
            def settimeout(self, _timeout):
                pass

            def connect(self, _address):
                pass

            def send(self, payload):
                return len(payload)

            def recv(self, _size):
                raise TimeoutError

            def close(self):
                pass

        with patch("cops.discovery.active_scanner.socket.socket", return_value=TimeoutSocket()):
            assessment = StandardSocketDispatcher().dispatch_probe(
                "198.51.100.10", "198.51.100.10", 53, protocol="udp", timeout=0.1
            )
        self.assertEqual(assessment.port_state, PortState.UNKNOWN.value)
        self.assertEqual(assessment.reachability, ServiceReachability.UNKNOWN.value)
        self.assertIn("timed out", assessment.error_message)

        session = ActiveScanSession(
            session_id="udp-timeout",
            scope_reference="approved-engagement",
            approved_targets=["198.51.100.10"],
            approved_ports=[],
            approved_udp_ports=[53],
            budget=ScanBudget(max_probes=1),
            assessments=[assessment],
            completed_probe_keys={ActiveScanSession.make_probe_key("external", "udp", "198.51.100.10", 53)},
        )
        self.assertEqual(session.coverage_summary()["timed_out"], 1)


class RecordingSocketDispatcher(StandardSocketDispatcher):
    """Exercise live admission and checkpoints without opening network sockets."""

    def __init__(self, resolved_ip="198.51.100.10", fail=False):
        self.resolved_ip = resolved_ip
        self.fail = fail
        self.resolutions = 0
        self.probes = []

    def resolve_target(self, target_host):
        self.resolutions += 1
        return self.resolved_ip

    def dispatch_probe(self, target_host, resolved_ip, port, protocol="tcp", timeout=2.0, vantage="external"):
        self.probes.append((target_host, resolved_ip, port))
        if self.fail:
            raise OSError("uncertain probe outcome")
        observed_config = ObservedConfiguration()
        if protocol == "udp":
            observed_config.protocol_metadata["probe_payload"] = "empty_datagram"
        return ActiveServiceAssessment(
            probe_id=f"recorded-{port}",
            target_host=target_host,
            resolved_ip=resolved_ip,
            port=port,
            protocol=protocol,
            vantage=vantage,
            observed_config=observed_config,
        )


class RecordingCustomDispatcher(ProbeDispatcher):
    """Custom dispatchers must receive the same admission as live sockets."""

    def __init__(self):
        self.recording = RecordingSocketDispatcher()

    @property
    def resolutions(self):
        return self.recording.resolutions

    @property
    def probes(self):
        return self.recording.probes

    def resolve_target(self, target_host):
        return self.recording.resolve_target(target_host)

    def dispatch_probe(self, target_host, resolved_ip, port, protocol="tcp", timeout=2.0, vantage="external"):
        return self.recording.dispatch_probe(target_host, resolved_ip, port, protocol, timeout, vantage)


class TestLiveScanSafety(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.checkpoint = Path(self.temp_dir.name) / "checkpoint.json"
        self.scope = {"domains": ["corp.internal"], "ip_ranges": ["198.51.100.0/24"]}

    def session(self, ports=None, max_probes=3):
        return ActiveScanSession(
            session_id="live-regression",
            scope_reference="approved-engagement",
            approved_targets=["app.corp.internal"],
            approved_ports=ports or [80],
            budget=ScanBudget(rate_limit_pps=10, max_probes=max_probes, max_total_seconds=60),
        )

    def scanner(self, session, dispatcher=None, scope=None, checkpoint=None):
        return ActiveScanner(
            session=session,
            dispatcher=dispatcher or RecordingSocketDispatcher(),
            scope=self.scope if scope is None else scope,
            checkpoint=self.checkpoint if checkpoint is None else checkpoint,
            sleeper=lambda _: None,
        )

    def test_live_admission_requires_durable_checkpoint_rate_and_ip_scope(self):
        cases = (
            (None, self.scope, 10, "checkpoint"),
            (self.checkpoint, self.scope, 0, "rate"),
            (self.checkpoint, {"domains": ["corp.internal"]}, 10, "IP ranges"),
            (self.checkpoint, {"ip_ranges": ["not-a-cidr"]}, 10, "IP scope"),
        )
        for checkpoint, scope, rate, message in cases:
            with self.subTest(message=message):
                session = self.session()
                session.budget.rate_limit_pps = rate
                dispatcher = RecordingSocketDispatcher()
                scanner = self.scanner(session, dispatcher, scope, checkpoint)
                if checkpoint is None:
                    scanner.checkpoint = None
                with self.assertRaisesRegex(ActiveScanError, message):
                    scanner.run()
                self.assertEqual(dispatcher.probes, [])

        session = self.session()
        session.budget.max_total_seconds = None
        dispatcher = RecordingSocketDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "execution duration"):
            self.scanner(session, dispatcher).run()
        self.assertEqual(dispatcher.probes, [])

    def test_custom_dispatcher_cannot_bypass_live_admission(self):
        dispatcher = RecordingCustomDispatcher()
        scanner = self.scanner(self.session(), dispatcher)
        scanner.checkpoint = None
        with self.assertRaisesRegex(ActiveScanError, "checkpoint"):
            scanner.run()
        self.assertEqual(dispatcher.resolutions, 0)
        self.assertEqual(dispatcher.probes, [])

        scanner = self.scanner(self.session(), dispatcher)
        result = scanner.run()
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(dispatcher.probes), 1)
        self.assertIsNotNone(result.bound_plan_sha256)
        self.assertEqual(ActiveScanSession.load_checkpoint(self.checkpoint).to_dict(), result.to_dict())

    def test_dns_probe_profile_is_checked_for_custom_and_mutating_dispatchers(self):
        dns_session = self.session()
        dns_session.approved_ports = []
        dns_session.approved_udp_ports = [53]
        dns_session.udp_dns_probe_ports = [53]
        custom = RecordingCustomDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "DNS probe selection differs"):
            self.scanner(dns_session, custom).run()
        self.assertEqual(custom.resolutions, 0)
        self.assertEqual(custom.probes, [])

        class MutatingDispatcher(RecordingSocketDispatcher):
            def __init__(self):
                super().__init__()
                self.udp_dns_probe_ports = frozenset()

            def resolve_target(self, target_host):
                self.udp_dns_probe_ports = frozenset({53})
                return super().resolve_target(target_host)

        plain_session = self.session()
        plain_session.approved_ports = []
        plain_session.approved_udp_ports = [53]
        changing = MutatingDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "DNS probe selection differs"):
            self.scanner(plain_session, changing).run()
        self.assertEqual(changing.probes, [])
        self.assertEqual(plain_session.total_probes_dispatched, 0)

    def test_resumed_ledger_rejects_unapproved_dns_payload_evidence(self):
        session = self.session()
        session.approved_ports = []
        session.approved_udp_ports = [53]
        self.scanner(session).run()
        saved = ActiveScanSession.load_checkpoint(self.checkpoint)
        saved.assessments[0].observed_config.protocol_metadata["probe_payload"] = "dns_root_ns_query"
        saved.save_checkpoint(self.checkpoint)

        dispatcher = RecordingSocketDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "Live checkpoint probe evidence"):
            self.scanner(ActiveScanSession.load_checkpoint(self.checkpoint), dispatcher).run()
        self.assertEqual(dispatcher.resolutions, 0)
        self.assertEqual(dispatcher.probes, [])

    def test_resolution_consuming_duration_does_not_dispatch(self):
        clock = [0.0]

        class SlowResolver(RecordingSocketDispatcher):
            def resolve_target(self, target_host):
                clock[0] += 2.0
                return super().resolve_target(target_host)

        session = self.session()
        session.budget.max_total_seconds = 1.0
        dispatcher = SlowResolver()
        with patch("cops.discovery.active_scanner.time.monotonic", side_effect=lambda: clock[0]):
            result = self.scanner(session, dispatcher).run()
        self.assertEqual(result.status, "budget_exhausted")
        self.assertEqual(dispatcher.probes, [])
        self.assertEqual(result.total_probes_dispatched, 0)

    def test_literal_ipv4_and_ipv6_obey_cidr_despite_domain_allowlist(self):
        for address, cidr in (("198.51.101.10", "198.51.100.0/24"), ("2001:db8:2::10", "2001:db8:1::/64")):
            with self.subTest(address=address):
                session = self.session()
                session.approved_targets = [address]
                dispatcher = RecordingSocketDispatcher(resolved_ip=address)
                checkpoint = Path(self.temp_dir.name) / f"{address.replace(':', '_')}.json"
                result = self.scanner(
                    session, dispatcher, {"domains": ["corp.internal"], "ip_ranges": [cidr]}, checkpoint
                ).run()
                self.assertEqual(result.status, "partial")
                self.assertEqual(result.quarantined_targets[0].reason, "outside_scope")
                self.assertEqual(dispatcher.resolutions, 0)
                self.assertEqual(dispatcher.probes, [])

    def test_live_checkpoint_binds_plan_and_scope_before_resuming(self):
        first = self.scanner(self.session()).run()
        self.assertEqual(first.status, "completed")
        for changed_scope, changed_ports in (
            ({"domains": ["corp.internal"], "ip_ranges": ["198.51.100.0/25"]}, [80]),
            (self.scope, [80, 443]),
        ):
            with self.subTest(changed_scope=changed_scope, changed_ports=changed_ports):
                resumed = ActiveScanSession.load_checkpoint(self.checkpoint)
                resumed.approved_ports = changed_ports
                dispatcher = RecordingSocketDispatcher()
                with self.assertRaisesRegex(ActiveScanError, "plan or scope changed"):
                    self.scanner(resumed, dispatcher, changed_scope).run()
                self.assertEqual(dispatcher.resolutions, 0)
                self.assertEqual(dispatcher.probes, [])

    def test_uncertain_probe_is_reserved_and_not_retried_on_resume(self):
        dispatcher = RecordingSocketDispatcher(fail=True)
        first = self.scanner(self.session(), dispatcher).run()
        self.assertEqual(first.status, "requires_reconciliation")
        self.assertEqual(first.total_probes_dispatched, 1)
        self.assertEqual(len(first.pending_probe_keys), 1)
        self.assertEqual(len(dispatcher.probes), 1)

        resumed = ActiveScanSession.load_checkpoint(self.checkpoint)
        next_dispatcher = RecordingSocketDispatcher()
        second = self.scanner(resumed, next_dispatcher).run()
        self.assertEqual(second.status, "requires_reconciliation")
        self.assertEqual(next_dispatcher.resolutions, 0)
        self.assertEqual(next_dispatcher.probes, [])

    def test_completion_journal_replays_provenance_after_crash_before_memory_update(self):
        session = self.session()
        original_append = ActiveScanSession.append_probe_completion

        def append_then_crash(current, path, probe_key, assessment):
            original_append(current, path, probe_key, assessment)
            raise KeyboardInterrupt("simulated crash")

        with patch.object(ActiveScanSession, "append_probe_completion", append_then_crash):
            with self.assertRaises(KeyboardInterrupt):
                self.scanner(session).run()

        probe_key = "external:tcp:app.corp.internal:80"
        self.assertIn(probe_key, session.pending_probe_keys)
        self.assertNotIn(probe_key, session.completed_probe_keys)
        self.assertEqual(session.assessments, [])

        replayed = ActiveScanSession.load_checkpoint(self.checkpoint)
        self.assertNotIn(probe_key, replayed.pending_probe_keys)
        self.assertIn(probe_key, replayed.completed_probe_keys)
        self.assertEqual(len(replayed.assessments), 1)
        provenance = replayed.assessments[0].provenance
        self.assertIsNotNone(provenance)
        assert provenance is not None
        self.assertEqual(provenance.source_id, replayed.session_id)
        self.assertEqual(provenance.raw_record_ref, probe_key)
        self.assertEqual(provenance.sha256, active_assessment_digest(replayed.assessments[0]))

    def test_pending_checkpoint_status_is_reconciled_durably(self):
        self.scanner(self.session(), RecordingSocketDispatcher(fail=True)).run()
        data = json.loads(self.checkpoint.read_text(encoding="utf-8"))
        data["status"] = "in_progress"  # Crash before status update reached disk.
        self.checkpoint.write_text(json.dumps(data), encoding="utf-8")

        dispatcher = RecordingSocketDispatcher()
        result = self.scanner(ActiveScanSession.load_checkpoint(self.checkpoint), dispatcher).run()
        self.assertEqual(result.status, "requires_reconciliation")
        self.assertEqual(ActiveScanSession.load_checkpoint(self.checkpoint).status, "requires_reconciliation")
        self.assertEqual(dispatcher.resolutions, 0)
        self.assertEqual(dispatcher.probes, [])

    def test_probe_cap_persists_across_restart(self):
        first = self.scanner(self.session(ports=[80, 443], max_probes=1)).run()
        self.assertEqual(first.status, "budget_exhausted")
        self.assertEqual(first.total_probes_dispatched, 1)

        dispatcher = RecordingSocketDispatcher()
        second = self.scanner(ActiveScanSession.load_checkpoint(self.checkpoint), dispatcher).run()
        self.assertEqual(second.status, "budget_exhausted")
        self.assertEqual(second.total_probes_dispatched, 1)
        self.assertEqual(dispatcher.probes, [])

    def test_mixed_tcp_udp_uses_separate_keys_and_shared_budget(self):
        session = self.session(ports=[53], max_probes=1)
        session.approved_udp_ports = [53]
        first = self.scanner(session).run()
        self.assertEqual(first.status, "budget_exhausted")
        self.assertEqual(first.completed_probe_keys, {"external:tcp:app.corp.internal:53"})
        self.assertEqual(first.total_probes_dispatched, 1)

        resumed = ActiveScanSession.load_checkpoint(self.checkpoint)
        dispatcher = RecordingSocketDispatcher()
        second = self.scanner(resumed, dispatcher).run()
        self.assertEqual(second.status, "budget_exhausted")
        self.assertEqual(second.total_probes_dispatched, 1)
        self.assertEqual(dispatcher.probes, [])

    def test_udp_only_plan_and_plan_binding(self):
        session = self.session()
        session.approved_ports = []
        session.approved_udp_ports = [53]
        first = self.scanner(session).run()
        self.assertEqual(first.status, "completed")
        self.assertEqual(first.assessments[0].protocol, "udp")
        self.assertEqual(first.completed_probe_keys, {"external:udp:app.corp.internal:53"})

        changed = ActiveScanSession.load_checkpoint(self.checkpoint)
        changed.approved_udp_ports = [53, 123]
        dispatcher = RecordingSocketDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "plan or scope changed"):
            self.scanner(changed, dispatcher).run()
        self.assertEqual(dispatcher.probes, [])

    def test_completed_resume_does_not_resolve_or_probe(self):
        self.scanner(self.session()).run()
        dispatcher = RecordingSocketDispatcher()
        resumed = self.scanner(ActiveScanSession.load_checkpoint(self.checkpoint), dispatcher).run()
        self.assertEqual(resumed.status, "completed")
        self.assertEqual(dispatcher.resolutions, 0)
        self.assertEqual(dispatcher.probes, [])

    def test_inconsistent_live_checkpoint_fails_before_network_activity(self):
        self.scanner(self.session()).run()
        for corruption in ("missing_assessment", "duplicate_assessment", "wrong_ip", "wrong_count", "unknown_probe"):
            with self.subTest(corruption=corruption):
                session = ActiveScanSession.load_checkpoint(self.checkpoint)
                if corruption == "missing_assessment":
                    session.assessments.clear()
                elif corruption == "duplicate_assessment":
                    session.assessments.append(session.assessments[0])
                elif corruption == "wrong_ip":
                    session.assessments[0].resolved_ip = "203.0.113.1"
                elif corruption == "wrong_count":
                    session.total_probes_dispatched += 1
                else:
                    session.pending_probe_keys.add("external:tcp:other.corp.internal:80")
                dispatcher = RecordingSocketDispatcher()
                with self.assertRaisesRegex(ActiveScanError, "Live checkpoint"):
                    self.scanner(session, dispatcher).run()
                self.assertEqual(dispatcher.resolutions, 0)
                self.assertEqual(dispatcher.probes, [])

    def test_stale_bound_session_cannot_replace_newer_checkpoint(self):
        completed = self.scanner(self.session()).run()
        saved = self.checkpoint.read_bytes()
        stale = self.session()
        stale.started_at = completed.started_at
        stale.bound_plan_sha256 = completed.bound_plan_sha256
        dispatcher = RecordingSocketDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "Live checkpoint differs"):
            self.scanner(stale, dispatcher).run()
        self.assertEqual(self.checkpoint.read_bytes(), saved)
        self.assertEqual(dispatcher.resolutions, 0)
        self.assertEqual(dispatcher.probes, [])

    def test_concurrent_live_controller_cannot_dispatch(self):
        dispatcher = RecordingSocketDispatcher()
        with _live_checkpoint_lock(self.checkpoint):
            with self.assertRaisesRegex(ActiveScanError, "another active controller"):
                self.scanner(self.session(), dispatcher).run()
        self.assertEqual(dispatcher.resolutions, 0)
        self.assertEqual(dispatcher.probes, [])

    @unittest.skipIf(os.name == "nt", "POSIX replacement semantics")
    def test_controller_lock_rejects_path_replaced_during_acquisition(self):
        import fcntl

        lock_path = self.checkpoint.with_name(f"{self.checkpoint.name}.lock")
        displaced_lock = lock_path.with_name(f"{lock_path.name}.displaced")
        real_flock = fcntl.flock
        replaced = False

        def replace_path_before_lock(descriptor, operation):
            nonlocal replaced
            if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB) and not replaced:
                os.replace(lock_path, displaced_lock)
                lock_path.touch(mode=0o600)
                replaced = True
            return real_flock(descriptor, operation)

        with (
            patch.object(ActiveScanSession, "_supports_checkpoint_directory_fd", return_value=False),
            patch.object(fcntl, "flock", side_effect=replace_path_before_lock),
        ):
            with self.assertRaisesRegex(ActiveScanError, "unsafe"):
                with _live_checkpoint_lock(self.checkpoint):
                    self.fail("replaced lock path was admitted")

        self.assertTrue(replaced)

    def test_checkpoint_alias_uses_same_controller_lock(self):
        alias = self.checkpoint.with_name("checkpoint-alias.json")
        alias.symlink_to(self.checkpoint)
        dispatcher = RecordingSocketDispatcher()
        scanner = self.scanner(self.session(), dispatcher, checkpoint=alias)
        self.assertEqual(scanner.checkpoint, self.checkpoint.resolve())
        with _live_checkpoint_lock(self.checkpoint):
            with self.assertRaisesRegex(ActiveScanError, "another active controller"):
                scanner.run()
        self.assertEqual(dispatcher.probes, [])

    def test_portable_controller_lock_rejects_symlink_without_modifying_victim(self):
        victim = self.checkpoint.with_name("lock-victim")
        victim.write_bytes(b"")
        victim.chmod(0o600)
        lock_path = self.checkpoint.with_name(f"{self.checkpoint.name}.lock")
        try:
            lock_path.symlink_to(victim)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symlink or reparse-point creation unavailable: {error}")

        with patch.object(ActiveScanSession, "_supports_checkpoint_directory_fd", return_value=False):
            with self.assertRaisesRegex(ActiveScanError, "unsafe"):
                with _live_checkpoint_lock(self.checkpoint):
                    self.fail("unsafe lock path was acquired")

        self.assertEqual(victim.read_bytes(), b"")
        self.assertTrue(lock_path.is_symlink())

    def test_portable_controller_lock_rejects_hard_link_without_modifying_victim(self):
        victim = self.checkpoint.with_name("lock-victim")
        victim.write_bytes(b"")
        victim.chmod(0o600)
        lock_path = self.checkpoint.with_name(f"{self.checkpoint.name}.lock")
        try:
            os.link(victim, lock_path)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard-link creation unavailable: {error}")

        with patch.object(ActiveScanSession, "_supports_checkpoint_directory_fd", return_value=False):
            with self.assertRaisesRegex(ActiveScanError, "unsafe"):
                with _live_checkpoint_lock(self.checkpoint):
                    self.fail("unsafe lock path was acquired")

        self.assertEqual(victim.read_bytes(), b"")
        self.assertTrue(lock_path.exists())

    def test_fractional_checkpoint_accounting_fails_closed(self):
        self.scanner(self.session()).run()
        for field, value in (("total_probes_dispatched", 1.9), ("elapsed_seconds", "0.1")):
            with self.subTest(field=field):
                data = json.loads(self.checkpoint.read_text(encoding="utf-8"))
                data[field] = value
                self.checkpoint.write_text(json.dumps(data), encoding="utf-8")
                dispatcher = RecordingSocketDispatcher()
                with self.assertRaisesRegex(ActiveScanError, "Live checkpoint probe accounting"):
                    self.scanner(ActiveScanSession.load_checkpoint(self.checkpoint), dispatcher).run()
                self.assertEqual(dispatcher.resolutions, 0)
                self.assertEqual(dispatcher.probes, [])
                data[field] = 1 if field == "total_probes_dispatched" else 0.0
                self.checkpoint.write_text(json.dumps(data), encoding="utf-8")

        data = json.loads(self.checkpoint.read_text(encoding="utf-8"))
        data["budget"]["max_probes"] = 1.9
        self.checkpoint.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "max_probes must be an integer"):
            ActiveScanSession.load_checkpoint(self.checkpoint)

    def test_untrusted_probe_result_identity_requires_reconciliation(self):
        class WrongIdentity(RecordingSocketDispatcher):
            def dispatch_probe(self, *args, **kwargs):
                result = super().dispatch_probe(*args, **kwargs)
                result.port = 443
                return result

        result = self.scanner(self.session(), WrongIdentity()).run()
        self.assertEqual(result.status, "requires_reconciliation")
        self.assertEqual(len(result.pending_probe_keys), 1)
        self.assertEqual(result.assessments, [])

    def test_oversized_probe_evidence_requires_reconciliation(self):
        class OversizedEvidence(RecordingSocketDispatcher):
            def dispatch_probe(self, *args, **kwargs):
                result = super().dispatch_probe(*args, **kwargs)
                result.observed_config.raw_banner = "B" * 70_000
                return result

        result = self.scanner(self.session(), OversizedEvidence()).run()
        self.assertEqual(result.status, "requires_reconciliation")
        self.assertEqual(len(result.pending_probe_keys), 1)
        self.assertEqual(result.completed_probe_keys, set())
        self.assertEqual(result.assessments, [])
        self.assertEqual(result.total_probes_dispatched, 1)
        self.assertEqual(result.total_side_effects, 0)
        restored = ActiveScanSession.load_checkpoint(self.checkpoint)
        self.assertEqual(restored.status, "requires_reconciliation")
        self.assertEqual(restored.pending_probe_keys, result.pending_probe_keys)

    def test_new_live_run_cannot_overwrite_existing_checkpoint(self):
        self.checkpoint.write_text("prior checkpoint", encoding="utf-8")
        dispatcher = RecordingSocketDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "already exists"):
            self.scanner(self.session(), dispatcher).run()
        self.assertEqual(self.checkpoint.read_text(encoding="utf-8"), "prior checkpoint")
        self.assertEqual(dispatcher.probes, [])

    def test_duplicate_targets_and_ports_cannot_repeat_network_effects(self):
        for targets, ports in (
            (["app.corp.internal", "APP.CORP.INTERNAL"], [80]),
            (["::1", "0:0:0:0:0:0:0:1"], [80]),
            (["app.corp.internal"], [80, 80]),
        ):
            with self.subTest(targets=targets, ports=ports):
                session = self.session(ports=ports)
                session.approved_targets = targets
                dispatcher = RecordingSocketDispatcher()
                with self.assertRaisesRegex(ActiveScanError, "Duplicate"):
                    self.scanner(session, dispatcher).run()
                self.assertEqual(dispatcher.probes, [])

    def test_equivalent_ipv6_literals_have_one_probe_key_identity(self):
        self.assertEqual(
            ActiveScanSession.make_probe_key("external", "tcp", "::1", 443),
            ActiveScanSession.make_probe_key("external", "tcp", "0:0:0:0:0:0:0:1", 443),
        )

    def test_bound_session_requires_its_durable_checkpoint(self):
        self.scanner(self.session()).run()
        resumed = ActiveScanSession.load_checkpoint(self.checkpoint)
        self.checkpoint.unlink()
        dispatcher = RecordingSocketDispatcher()
        with self.assertRaisesRegex(ActiveScanError, "no checkpoint"):
            self.scanner(resumed, dispatcher).run()
        self.assertEqual(dispatcher.probes, [])

    def test_resume_waits_full_rate_interval_before_next_probe(self):
        first = self.scanner(self.session(ports=[80, 443])).run()
        self.assertEqual(first.status, "completed")
        # Simulate a completed first probe and interruption before a second
        # dispatch; the saved bound plan and counters remain unchanged.
        resumed = ActiveScanSession.load_checkpoint(self.checkpoint)
        resumed.completed_probe_keys.remove(
            ActiveScanSession.make_probe_key(resumed.vantage, "tcp", "app.corp.internal", 443)
        )
        resumed.assessments = [assessment for assessment in resumed.assessments if assessment.port == 80]
        resumed.total_probes_dispatched = 1
        resumed.total_side_effects = 1
        resumed.save_checkpoint(self.checkpoint)
        sleeps = []
        dispatcher = RecordingSocketDispatcher()
        scanner = ActiveScanner(
            resumed,
            dispatcher,
            scope=self.scope,
            checkpoint=self.checkpoint,
            sleeper=sleeps.append,
        )
        result = scanner.run()
        self.assertEqual(result.status, "completed")
        self.assertEqual(sleeps, [0.1])
        self.assertEqual([probe[2] for probe in dispatcher.probes], [443])


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
                    80: {
                        "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
                        "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
                        "http_status": 200,
                    },
                    443: {
                        "tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal", "sans": ["app.corp.internal"]},
                        "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
                        "http_status": 200,
                    },
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
        for assessment in completed.assessments:
            with self.subTest(port=assessment.port):
                probe_key = ActiveScanSession.make_probe_key(
                    assessment.vantage, assessment.protocol, assessment.target_host, assessment.port
                )
                self.assertIn(probe_key, completed.completed_probe_keys)
                self.assertIsNotNone(assessment.provenance)
                self.assertEqual(assessment.provenance.source_type, "active_scan")
                self.assertEqual(assessment.provenance.source_id, completed.session_id)
                self.assertEqual(assessment.provenance.path_or_uri, completed.scope_reference)
                self.assertEqual(assessment.provenance.raw_record_ref, probe_key)
                self.assertEqual(assessment.provenance.timestamp, assessment.timestamp_utc)
                self.assertEqual(assessment.provenance.sha256, active_assessment_digest(assessment))

    def test_offline_udp_fixtures_are_protocol_aware_and_evidence_bound(self):
        fixtures = {
            "app.corp.internal": {
                "ports": {
                    "tcp": {
                        "53": {"state": "closed"},
                        "443": {"state": "closed"},
                    },
                    "udp": {
                        "53": {"timeout": True},
                        "5353": {
                            "state": "open",
                            "protocol_metadata": {
                                "probe_payload": "dns_root_ns_query",
                                "dns_response_validated": True,
                            },
                        },
                    },
                }
            }
        }
        session = ActiveScanSession(
            session_id="protocol-aware-fixtures",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[53, 443],
            approved_udp_ports=[53, 5353, 9999],
            udp_dns_probe_ports=[5353],
            budget=ScanBudget(max_probes=5),
        )
        result = ActiveScanner(
            session=session,
            dispatcher=OfflineSyntheticDispatcher(targets=fixtures, dns_map=self.dns_map),
            scope=self.scope,
        ).run()
        by_key = {(item.protocol, item.port): item for item in result.assessments}
        self.assertEqual(by_key[("tcp", 53)].port_state, PortState.CLOSED.value)
        self.assertEqual(by_key[("tcp", 443)].port_state, PortState.CLOSED.value)
        self.assertEqual(by_key[("udp", 53)].port_state, PortState.UNKNOWN.value)
        self.assertIn("timed out", by_key[("udp", 53)].error_message)
        self.assertEqual(by_key[("udp", 9999)].port_state, PortState.UNKNOWN.value)
        self.assertIn("No UDP fixture", by_key[("udp", 9999)].error_message)
        dns_metadata = by_key[("udp", 5353)].observed_config.protocol_metadata
        self.assertEqual(dns_metadata["probe_payload"], "dns_root_ns_query")
        self.assertIs(dns_metadata["dns_response_validated"], True)
        self.assertEqual(result.coverage_summary()["timed_out"], 1)

        invalid = json.loads(json.dumps(fixtures))
        invalid["app.corp.internal"]["ports"]["udp"]["5353"]["protocol_metadata"].pop("dns_response_validated")
        invalid_session = ActiveScanSession(
            session_id="invalid-dns-fixture",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[],
            approved_udp_ports=[5353],
            udp_dns_probe_ports=[5353],
            budget=ScanBudget(max_probes=1),
        )
        invalid_result = ActiveScanner(
            session=invalid_session,
            dispatcher=OfflineSyntheticDispatcher(targets=invalid, dns_map=self.dns_map),
            scope=self.scope,
        ).run()
        self.assertEqual(invalid_result.status, "requires_reconciliation")
        self.assertEqual(invalid_result.assessments, [])
        self.assertEqual(
            invalid_result.pending_probe_keys,
            {ActiveScanSession.make_probe_key("external", "udp", "app.corp.internal", 5353)},
        )

    def test_direct_scanner_rejects_probe_ledger_above_materialization_cap(self):
        per_target = (MAX_ACTIVE_PLANNED_PROBES // 3) + 1
        session = ActiveScanSession(
            session_id="oversized-ledger",
            scope_reference="ROE-2026-001",
            approved_targets=["a.example", "b.example", "c.example"],
            approved_ports=list(range(1, per_target + 1)),
            budget=ScanBudget(max_probes=MAX_ACTIVE_PLANNED_PROBES + 3),
        )
        with self.assertRaisesRegex(ActiveScanError, "probe ledger materialization cap"):
            ActiveScanner(session=session, dispatcher=OfflineSyntheticDispatcher())._validate_run()

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

        # Restore completed probes and their pinned address from a checkpoint.
        key_80 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 80)
        key_443 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 443)
        session.completed_probe_keys.update([key_80, key_443])
        session.assessments.extend(
            ActiveServiceAssessment(
                probe_id=f"prior-{port}",
                target_host="app.corp.internal",
                resolved_ip="198.51.100.10",
                port=port,
                vantage=ScanVantage.EXTERNAL.value,
            )
            for port in (80, 443)
        )

        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope)
        resumed = scanner.run()

        # Only port 8080 dispatched
        self.assertEqual(dispatcher.side_effect_count, 1)
        self.assertEqual(len(resumed.assessments), 3)
        self.assertEqual(resumed.assessments[-1].port, 8080)

    def test_explicit_cancellation_reports_coverage_and_resumes_remaining_probe(self):
        session = ActiveScanSession(
            session_id="sess-cancel-resume",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 443],
            budget=ScanBudget(rate_limit_pps=0, max_concurrency=1),
        )
        first_dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        partial = ActiveScanner(
            session=session,
            dispatcher=first_dispatcher,
            scope=self.scope,
            cancel_requested=lambda: first_dispatcher.side_effect_count >= 1,
        ).run()

        self.assertEqual(partial.status, "cancelled")
        self.assertEqual(first_dispatcher.side_effect_count, 1)
        self.assertEqual(partial.coverage_summary()["attempted"], 1)
        self.assertEqual(partial.coverage_summary()["unassessed"], 1)

        resume_dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        resumed = ActiveScanner(
            session=ActiveScanSession.from_dict(partial.to_dict()),
            dispatcher=resume_dispatcher,
            scope=self.scope,
        ).run()
        self.assertEqual(resumed.status, "completed")
        self.assertEqual(resume_dispatcher.side_effect_count, 1)
        self.assertEqual(resumed.coverage_summary()["attempted"], 2)
        self.assertEqual(resumed.coverage_summary()["unassessed"], 0)

    def test_nonserial_concurrency_is_rejected_before_dispatch(self):
        session = ActiveScanSession(
            session_id="sess-invalid-concurrency",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80],
            budget=ScanBudget(max_concurrency=2),
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        with self.assertRaisesRegex(ActiveScanError, "max_concurrency=1"):
            ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope).run()
        self.assertEqual(dispatcher.side_effect_count, 0)

    def test_resume_quarantines_in_scope_dns_shift(self):
        session = ActiveScanSession(
            session_id="sess-resume-rebind",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 8080],
            budget=ScanBudget(rate_limit_pps=0),
        )
        first_dispatcher = OfflineSyntheticDispatcher(
            targets=self.mock_targets,
            dns_map={"app.corp.internal": "198.51.100.10"},
        )
        session.approved_ports = [80]
        ActiveScanner(session=session, dispatcher=first_dispatcher, scope=self.scope).run()
        checkpoint = ActiveScanSession.from_dict(session.to_dict())
        checkpoint.approved_ports = [80, 8080]

        shifted_dispatcher = OfflineSyntheticDispatcher(
            targets=self.mock_targets,
            dns_map={"app.corp.internal": "198.51.100.11"},
        )
        resumed = ActiveScanner(session=checkpoint, dispatcher=shifted_dispatcher, scope=self.scope).run()

        self.assertEqual(shifted_dispatcher.side_effect_count, 0)
        self.assertEqual([a.port for a in resumed.assessments], [80])
        self.assertEqual(len(resumed.quarantined_targets), 1)
        quarantine = resumed.quarantined_targets[0]
        self.assertEqual(quarantine.reason, "dns_rebind_detected")
        self.assertEqual(quarantine.original_ip, "198.51.100.10")
        self.assertEqual(quarantine.new_ip, "198.51.100.11")

    def test_resume_quarantines_completed_key_without_resolution_evidence(self):
        session = ActiveScanSession(
            session_id="sess-incomplete-checkpoint",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 8080],
        )
        session.completed_probe_keys.add(
            ActiveScanSession.make_probe_key(session.vantage, "tcp", "app.corp.internal", 80)
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets, dns_map=self.dns_map)
        first = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope).run()
        self.assertEqual(dispatcher.side_effect_count, 0)
        self.assertEqual(first.quarantined_targets[0].reason, "checkpoint_missing_resolution")

        # A persisted quarantine must not be bypassed by another resume.
        resumed = ActiveScanner(
            session=ActiveScanSession.from_dict(first.to_dict()), dispatcher=dispatcher, scope=self.scope
        ).run()
        self.assertEqual(dispatcher.side_effect_count, 0)
        self.assertEqual(len(resumed.quarantined_targets), 1)

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

    def test_dns_shift_between_ports_quarantines_remaining_probe(self):
        session = ActiveScanSession(
            session_id="sess-mid-scan-rebind",
            scope_reference="ROE-2026-001",
            approved_targets=["app.corp.internal"],
            approved_ports=[80, 8080],
            budget=ScanBudget(rate_limit_pps=0),
        )
        dispatcher = OfflineSyntheticDispatcher(targets=self.mock_targets)
        resolutions = iter(["198.51.100.10", "10.0.0.1"])
        dispatcher.set_dns_hook("app.corp.internal", lambda: next(resolutions))

        completed = ActiveScanner(session=session, dispatcher=dispatcher, scope=self.scope).run()

        self.assertEqual([a.port for a in completed.assessments], [80])
        self.assertEqual(dispatcher.side_effect_count, 1)
        self.assertEqual(len(completed.quarantined_targets), 1)
        quarantine = completed.quarantined_targets[0]
        self.assertEqual(quarantine.reason, "dns_rebind_detected")
        self.assertEqual(quarantine.original_ip, "198.51.100.10")
        self.assertEqual(quarantine.new_ip, "10.0.0.1")

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
        self.assertEqual(len(sleep_calls), 1)
        self.assertAlmostEqual(sleep_calls[0], 0.2, places=2)


class TestRemediatedExposureVerification(unittest.TestCase):
    def test_equivalent_ipv6_spellings_share_retest_identity(self):
        baseline = ActiveScanSession("baseline", "test-scope", ["app.example"], [443])
        baseline.assessments = [
            ActiveServiceAssessment(
                probe_id="baseline-probe",
                target_host="app.example",
                resolved_ip="0:0:0:0:0:0:0:1",
                port=443,
                port_state=PortState.OPEN.value,
            )
        ]

        for state in (PortState.CLOSED.value, PortState.OPEN.value):
            with self.subTest(state=state):
                current = ActiveScanSession("retest", "test-scope", ["app.example"], [443])
                current.assessments = [
                    ActiveServiceAssessment(
                        probe_id="retest-probe",
                        target_host="app.example",
                        resolved_ip="::1",
                        port=443,
                        port_state=state,
                    )
                ]

                delta = compare_active_scans(baseline, current)
                self.assertEqual(len(delta.remediated_exposures), int(state == PortState.CLOSED.value))
                self.assertEqual(len(delta.persistent_exposures), int(state == PortState.OPEN.value))
                self.assertEqual(delta.unverified_exposures, [])
                self.assertEqual(delta.new_exposures, [])

    def test_equivalent_ipv6_literal_targets_share_retest_identity(self):
        baseline = ActiveScanSession("baseline", "test-scope", ["0:0:0:0:0:0:0:1"], [443])
        baseline.assessments = [
            ActiveServiceAssessment(
                probe_id="baseline-probe",
                target_host="0:0:0:0:0:0:0:1",
                resolved_ip="0:0:0:0:0:0:0:1",
                port=443,
                port_state=PortState.OPEN.value,
            )
        ]
        current = ActiveScanSession("retest", "test-scope", ["::1"], [443])
        current.assessments = [
            ActiveServiceAssessment(
                probe_id="retest-probe",
                target_host="::1",
                resolved_ip="::1",
                port=443,
                port_state=PortState.CLOSED.value,
            )
        ]

        delta = compare_active_scans(baseline, current)
        self.assertEqual(len(delta.remediated_exposures), 1)
        self.assertEqual(delta.unverified_exposures, [])

    def test_conflicting_retest_observations_cannot_confirm_remediation(self):
        baseline = ActiveScanSession("baseline", "test-scope", ["app.example"], [443])
        baseline.assessments = [
            ActiveServiceAssessment(
                probe_id="baseline-probe",
                target_host="app.example",
                resolved_ip="198.51.100.10",
                port=443,
                port_state=PortState.OPEN.value,
            )
        ]

        for earlier_state, expected_persistent in (
            (PortState.OPEN.value, True),
            (PortState.FILTERED.value, False),
        ):
            with self.subTest(earlier_state=earlier_state):
                current = ActiveScanSession("retest", "test-scope", ["app.example"], [443])
                current.assessments = [
                    ActiveServiceAssessment(
                        probe_id="retest-earlier",
                        target_host="app.example",
                        resolved_ip="198.51.100.10",
                        port=443,
                        port_state=earlier_state,
                    ),
                    ActiveServiceAssessment(
                        probe_id="retest-later",
                        target_host="app.example",
                        resolved_ip="198.51.100.10",
                        port=443,
                        port_state=PortState.CLOSED.value,
                    ),
                ]

                delta = compare_active_scans(baseline, current)
                self.assertEqual(delta.remediated_exposures, [])
                self.assertEqual(delta.remediation_rate, 0.0)
                self.assertEqual(len(delta.persistent_exposures), int(expected_persistent))
                self.assertEqual(len(delta.unverified_exposures), int(not expected_persistent))

    def test_retest_of_different_address_or_vantage_cannot_confirm_remediation(self):
        baseline = ActiveScanSession("baseline", "test-scope", ["app.example"], [443])
        baseline.assessments = [
            ActiveServiceAssessment(
                probe_id="baseline-probe",
                target_host="app.example",
                resolved_ip="198.51.100.10",
                port=443,
                vantage=ScanVantage.EXTERNAL.value,
                port_state=PortState.OPEN.value,
            )
        ]

        for resolved_ip, vantage, state in (
            ("198.51.100.11", ScanVantage.EXTERNAL.value, PortState.CLOSED.value),
            ("198.51.100.10", ScanVantage.INTERNAL.value, PortState.CLOSED.value),
            ("198.51.100.11", ScanVantage.EXTERNAL.value, PortState.OPEN.value),
        ):
            with self.subTest(resolved_ip=resolved_ip, vantage=vantage, state=state):
                current = ActiveScanSession("retest", "test-scope", ["app.example"], [443], vantage=vantage)
                current.assessments = [
                    ActiveServiceAssessment(
                        probe_id="retest-probe",
                        target_host="app.example",
                        resolved_ip=resolved_ip,
                        port=443,
                        vantage=vantage,
                        port_state=state,
                    )
                ]

                delta = compare_active_scans(baseline, current)
                self.assertEqual(delta.remediated_exposures, [])
                self.assertEqual(delta.persistent_exposures, [])
                self.assertEqual(delta.remediation_rate, 0.0)
                self.assertEqual(len(delta.unverified_exposures), 1)
                self.assertEqual(delta.unverified_exposures[0]["reason"], "identity_changed")
                self.assertEqual(delta.unverified_exposures[0]["current_state"], state)
                self.assertEqual(delta.unverified_exposures[0]["previous_resolved_ip"], "198.51.100.10")
                self.assertEqual(delta.unverified_exposures[0]["current_resolved_ip"], resolved_ip)
                self.assertEqual(delta.unverified_exposures[0]["previous_vantage"], ScanVantage.EXTERNAL.value)
                self.assertEqual(delta.unverified_exposures[0]["current_vantage"], vantage)
                self.assertEqual(len(delta.new_exposures), int(state == PortState.OPEN.value))

    def test_missing_or_inconclusive_retest_is_not_remediated(self):
        baseline = ActiveScanner(
            ActiveScanSession("baseline", "test-scope", ["127.0.0.1"], [18001, 18002]),
            OfflineSyntheticDispatcher(),
            sleeper=lambda _: None,
        ).run()
        current = ActiveScanner(
            ActiveScanSession("partial", "test-scope", ["127.0.0.1"], [18001]),
            OfflineSyntheticDispatcher(targets={"127.0.0.1": {"ports": {18001: {"state": "filtered"}}}}),
            sleeper=lambda _: None,
        ).run()

        delta = compare_active_scans(baseline, current)
        self.assertEqual(delta.remediated_exposures, [])
        self.assertEqual(delta.remediation_rate, 0.0)
        self.assertEqual(
            {(item["port"], item["current_state"]) for item in delta.unverified_exposures},
            {(18001, PortState.FILTERED.value), (18002, "not_probed")},
        )

    def test_compare_active_scans_calculates_remediation_delta(self):
        mock_baseline = {
            "app.corp.internal": {
                "ports": {
                    80: {
                        "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
                        "headers": {"Server": "Apache/2.4.41"},
                    },
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
                    80: {
                        "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n",
                        "headers": {"Server": "Apache/2.4.52"},
                    },
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
            {
                "ip": "198.51.100.10",
                "timestamp": "1728130000",
                "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 58}],
            },
            {
                "ip": "198.51.100.10",
                "timestamp": "1728130005",
                "ports": [{"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 58}],
            },
            {
                "ip": "198.51.100.20",
                "timestamp": "1728130010",
                "ports": [
                    {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 60},
                    {"port": 53, "proto": "udp", "status": "open", "reason": "udp-response", "ttl": 60},
                ],
            },
        ]
        file_path = self.root / "masscan.json"
        file_path.write_text(json.dumps(masscan_data), encoding="utf-8")

        session = import_masscan_json(file_path, vantage="external", scope_ref="MASS-01")
        self.assertEqual(session.status, "completed")
        self.assertEqual(len(session.assessments), 4)
        self.assertEqual(set(session.approved_targets), {"198.51.100.10", "198.51.100.20"})
        self.assertEqual(set(session.approved_ports), {80, 443, 22})
        self.assertEqual(session.approved_udp_ports, [53])
        self.assertEqual({assessment.protocol for assessment in session.assessments}, {"tcp", "udp"})
        self.assertEqual(session.assessments[0].provenance.source_type, "masscan_export")

    def test_import_masscan_rejects_unsupported_protocol(self):
        file_path = self.root / "masscan-unsupported.json"
        file_path.write_text(
            json.dumps([{"ip": "198.51.100.10", "ports": [{"port": 53, "proto": "sctp"}]}]),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "Unsupported Masscan protocol"):
            import_masscan_json(file_path)

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
    <port protocol="udp" portid="53">
      <state state="open" reason="udp-response"/>
      <service name="domain" method="table"/>
    </port>
  </ports>
</host>
</nmaprun>
"""
        file_path = self.root / "nmap.xml"
        file_path.write_text(nmap_xml, encoding="utf-8")

        session = import_nmap_xml(file_path, vantage="external", scope_ref="NMAP-01")
        self.assertEqual(len(session.assessments), 3)
        self.assertEqual(session.approved_targets, ["web.corp.internal"])
        self.assertEqual(session.approved_ports, [80, 443])
        self.assertEqual(session.approved_udp_ports, [53])

        p80 = next(a for a in session.assessments if a.port == 80)
        self.assertEqual(p80.inferred_fingerprint.product, "nginx")
        self.assertEqual(p80.inferred_fingerprint.version, "1.18.0")
        self.assertEqual(p80.inferred_fingerprint.confidence, ConfidenceLevel.HIGH.value)

        p443 = next(a for a in session.assessments if a.port == 443)
        self.assertEqual(p443.observed_config.tls.subject_cn, "web.corp.internal")

        p53 = next(a for a in session.assessments if a.port == 53)
        self.assertEqual(p53.protocol, "udp")
        self.assertEqual(p53.inferred_fingerprint.service_name, "domain")
        self.assertIsNone(p53.inferred_fingerprint.product)
        self.assertEqual(p53.inferred_fingerprint.confidence, ConfidenceLevel.LOW.value)

    def test_import_nmap_rejects_unsupported_protocol(self):
        file_path = self.root / "nmap-unsupported.xml"
        file_path.write_text(
            """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="198.51.100.10" addrtype="ipv4"/>
    <ports>
      <port protocol="sctp" portid="3868"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
""",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "Unsupported Nmap protocol"):
            import_nmap_xml(file_path)


class TestActiveDiscoveryCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_cli_rejects_oversized_json_inputs_before_dispatch(self):
        oversized = self.root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate((4 * 1024 * 1024) + 1)

        parser = argparse.ArgumentParser()
        build_active_parser(parser)
        plan_args = parser.parse_args(["plan", "--targets", str(oversized)])
        with self.assertRaisesRegex(ValueError, "Targets file must be valid bounded JSON"):
            command_active_discovery(plan_args)

        plan_path = self.root / "plan.json"
        ActiveScanSession(
            session_id="bounded-cli-input",
            scope_reference="approved-engagement",
            approved_targets=["198.51.100.10"],
            approved_ports=[80],
        ).save_checkpoint(plan_path)
        scan_args = argparse.Namespace(
            active_command="scan",
            session=str(plan_path),
            scope=str(oversized),
            mode="synthetic",
            offline_targets=None,
            checkpoint=None,
            output=None,
        )
        with patch("cops.discovery.cli.ActiveScanner.run") as run:
            with self.assertRaisesRegex(ValueError, "Scope file must be valid bounded JSON"):
                command_active_discovery(scan_args)
            run.assert_not_called()

            scan_args.scope = None
            scan_args.offline_targets = str(oversized)
            with self.assertRaisesRegex(ValueError, "Offline targets file must be valid bounded JSON"):
                command_active_discovery(scan_args)
            run.assert_not_called()

    def test_cli_rejects_missing_or_nonobject_offline_fixture_before_dispatch(self):
        plan_path = self.root / "plan.json"
        ActiveScanSession(
            session_id="offline-fixture-shape",
            scope_reference="approved-engagement",
            approved_targets=["198.51.100.10"],
            approved_ports=[80],
        ).save_checkpoint(plan_path)
        scan_args = argparse.Namespace(
            active_command="scan",
            session=str(plan_path),
            scope=None,
            mode="synthetic",
            offline_targets=str(self.root / "missing.json"),
            checkpoint=None,
            output=None,
        )
        with patch("cops.discovery.cli.ActiveScanner.run") as run:
            with self.assertRaisesRegex(ValueError, "Offline targets file must be valid bounded JSON"):
                command_active_discovery(scan_args)
            run.assert_not_called()

            invalid_shape = self.root / "not-an-object.json"
            invalid_shape.write_text("[]", encoding="utf-8")
            scan_args.offline_targets = str(invalid_shape)
            with self.assertRaisesRegex(ValueError, "Offline targets file must contain a JSON object"):
                command_active_discovery(scan_args)
            run.assert_not_called()

    def test_cli_plan_allows_unthrottled_synthetic_scan(self):
        plan_out = self.root / "plan-zero-rate.json"
        args = argparse.Namespace(
            active_command="plan",
            targets="198.51.100.10",
            ports="80",
            vantage="external",
            rate_limit=0.0,
            timeout=2.0,
            max_total_seconds=None,
            scope_ref="ENG-01",
            output=str(plan_out),
        )
        self.assertEqual(command_active_discovery(args), 0)
        self.assertEqual(ActiveScanSession.load_checkpoint(plan_out).budget.rate_limit_pps, 0.0)

    def test_cli_plan_expands_bounded_ipv4_and_ipv6_cidrs(self):
        parser = argparse.ArgumentParser()
        build_active_parser(parser)
        plan_out = self.root / "cidr-plan.json"
        args = parser.parse_args(
            [
                "plan",
                "--targets",
                "192.0.2.0/31,2001:db8::/127",
                "--max-targets",
                "4",
                "--ports",
                "443",
                "--max-probes",
                "4",
                "--output",
                str(plan_out),
            ]
        )
        self.assertEqual(command_active_discovery(args), 0)
        session = ActiveScanSession.load_checkpoint(plan_out)
        self.assertEqual(
            session.approved_targets,
            ["192.0.2.0", "192.0.2.1", "2001:db8::", "2001:db8::1"],
        )
        self.assertEqual(session.budget.max_targets, 4)

        args = parser.parse_args(
            [
                "plan",
                "--targets",
                "192.0.2.0/29",
                "--max-targets",
                "4",
                "--ports",
                "443",
                "--output",
                str(self.root / "oversized-cidr-plan.json"),
            ]
        )
        with self.assertRaisesRegex(ValueError, "max_targets"):
            command_active_discovery(args)

    def test_cli_plan_udp_selection_does_not_add_default_tcp_ports(self):
        parser = argparse.ArgumentParser()
        build_active_parser(parser)
        udp_plan = self.root / "udp-only.json"
        args = parser.parse_args(["plan", "--targets", "198.51.100.10", "--udp-ports", "53", "--output", str(udp_plan)])
        self.assertEqual(command_active_discovery(args), 0)
        session = ActiveScanSession.load_checkpoint(udp_plan)
        self.assertEqual(session.approved_ports, [])
        self.assertEqual(session.approved_udp_ports, [53])

        tcp_plan = self.root / "default-tcp.json"
        args = parser.parse_args(["plan", "--targets", "198.51.100.10", "--output", str(tcp_plan)])
        self.assertEqual(command_active_discovery(args), 0)
        session = ActiveScanSession.load_checkpoint(tcp_plan)
        self.assertEqual(session.approved_ports, [22, 80, 443])
        self.assertEqual(session.approved_udp_ports, [])

    def test_cli_plan_dns_probe_requires_explicit_udp_selection(self):
        parser = argparse.ArgumentParser()
        build_active_parser(parser)
        output = self.root / "dns-plan.json"
        args = parser.parse_args(
            [
                "plan",
                "--targets",
                "198.51.100.10",
                "--udp-ports",
                "5353",
                "--udp-dns-probe-ports",
                "5353",
                "--output",
                str(output),
            ]
        )
        self.assertEqual(command_active_discovery(args), 0)
        session = ActiveScanSession.load_checkpoint(output)
        self.assertEqual(session.udp_dns_probe_ports, [5353])
        self.assertEqual(session.approved_ports, [])
        self.assertEqual(ActiveScanSession.from_dict(session.to_dict()).udp_dns_probe_ports, [5353])
        dns_digest = ActiveScanner(session, StandardSocketDispatcher([5353]))._live_plan_digest()
        with self.assertRaisesRegex(ActiveScanError, "selection differs"):
            ActiveScanner(session, StandardSocketDispatcher([]))._validate_run()

        class InheritedDnsDispatcher(StandardSocketDispatcher):
            pass

        session.udp_dns_probe_ports = []
        with self.assertRaisesRegex(ActiveScanError, "selection differs"):
            ActiveScanner(session, InheritedDnsDispatcher([5353]))._validate_run()
        empty_digest = ActiveScanner(session, StandardSocketDispatcher([]))._live_plan_digest()
        self.assertNotEqual(dns_digest, empty_digest)

        args.udp_dns_probe_ports = "53"
        with self.assertRaisesRegex(ValueError, "subset"):
            command_active_discovery(args)

        session.udp_dns_probe_ports = [53]
        with self.assertRaisesRegex(ActiveScanError, "approved UDP ports"):
            ActiveScanner(session, StandardSocketDispatcher(session.udp_dns_probe_ports))._validate_run()

    def test_cli_plan_binds_udp_only_selection_and_budget(self):
        plan_out = self.root / "udp-plan.json"
        args = argparse.Namespace(
            active_command="plan",
            targets="198.51.100.10",
            ports="",
            udp_ports="53,161",
            allow_full_udp=False,
            max_probes=2,
            vantage="external",
            rate_limit=10.0,
            timeout=1.0,
            max_total_seconds=5.0,
            scope_ref="ENG-UDP",
            output=str(plan_out),
        )
        self.assertEqual(command_active_discovery(args), 0)
        plan = ActiveScanSession.load_checkpoint(plan_out)
        self.assertEqual(plan.approved_ports, [])
        self.assertEqual(plan.approved_udp_ports, [53, 161])
        self.assertEqual(plan.budget.max_probes, 2)

        args.udp_ports = "all"
        args.max_probes = 65535
        with self.assertRaisesRegex(ValueError, "--allow-full-udp"):
            command_active_discovery(args)
        args.allow_full_udp = True
        args.max_probes = 65534
        with self.assertRaisesRegex(ValueError, "--max-probes"):
            command_active_discovery(args)

    def test_cli_plan_enforces_cartesian_probe_budget_and_materialization_cap(self):
        parser = argparse.ArgumentParser()
        build_active_parser(parser)
        output = self.root / "bounded-plan.json"
        base_args = [
            "plan",
            "--targets",
            "198.51.100.10,198.51.100.11",
            "--ports",
            "80",
            "--udp-ports",
            "53",
            "--output",
            str(output),
        ]

        with self.assertRaisesRegex(ValueError, "--max-probes"):
            command_active_discovery(parser.parse_args([*base_args, "--max-probes", "3"]))

        self.assertEqual(command_active_discovery(parser.parse_args([*base_args, "--max-probes", "4"])), 0)
        bounded = ActiveScanSession.load_checkpoint(output)
        self.assertEqual(bounded.budget.max_probes, 4)
        self.assertEqual(bounded.coverage_summary()["planned"], 4)

        with self.assertRaisesRegex(ValueError, "--max-probes"):
            command_active_discovery(
                parser.parse_args(
                    [
                        "plan",
                        "--targets",
                        "198.51.100.10,198.51.100.11",
                        "--ports",
                        "1-100",
                        "--max-probes",
                        "199",
                        "--output",
                        str(self.root / "over-budget-plan.json"),
                    ]
                )
            )

        with self.assertRaisesRegex(ValueError, "probe ledger materialization cap"):
            command_active_discovery(
                parser.parse_args(
                    [
                        "plan",
                        "--targets",
                        "198.51.100.10,198.51.100.11,198.51.100.12",
                        "--max-targets",
                        "3",
                        "--ports",
                        "all",
                        "--allow-full-tcp",
                        "--max-probes",
                        str(3 * 65535),
                        "--output",
                        str(self.root / "oversized-ledger-plan.json"),
                    ]
                )
            )

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

    def test_cli_does_not_write_checkpoint_after_scanner_returns(self):
        plan_path = self.root / "plan.json"
        checkpoint_path = self.root / "checkpoint.json"
        planned = ActiveScanSession(
            session_id="cli-checkpoint-ownership",
            scope_reference="approved-engagement",
            approved_targets=["198.51.100.10"],
            approved_ports=[80],
        )
        planned.save_checkpoint(plan_path)

        def complete_scan(scanner):
            newer = ActiveScanSession.from_dict(scanner.session.to_dict())
            newer.status = "completed"
            newer.save_checkpoint(scanner.checkpoint)
            return scanner.session

        scan_args = argparse.Namespace(
            active_command="scan",
            session=str(plan_path),
            scope=None,
            mode="synthetic",
            offline_targets=None,
            checkpoint=str(checkpoint_path),
            output=None,
        )
        with patch("cops.discovery.cli.ActiveScanner.run", complete_scan):
            self.assertEqual(command_active_discovery(scan_args), 2)
        self.assertEqual(ActiveScanSession.load_checkpoint(checkpoint_path).status, "completed")

        resume_args = argparse.Namespace(
            active_command="resume",
            checkpoint=str(checkpoint_path),
            scope=None,
            mode="synthetic",
            offline_targets=None,
            checkpoint_out=None,
            output=None,
        )

        def resume_with_newer_checkpoint(scanner):
            newer = ActiveScanSession.from_dict(scanner.session.to_dict())
            newer.status = "requires_reconciliation"
            newer.save_checkpoint(scanner.checkpoint)
            return scanner.session

        with patch("cops.discovery.cli.ActiveScanner.run", resume_with_newer_checkpoint):
            self.assertEqual(command_active_discovery(resume_args), 0)
        self.assertEqual(ActiveScanSession.load_checkpoint(checkpoint_path).status, "requires_reconciliation")

    def test_live_output_cannot_overwrite_checkpoint_or_alias(self):
        plan_path = self.root / "plan.json"
        checkpoint_path = self.root / "checkpoint.json"
        ActiveScanSession(
            session_id="cli-output-separation",
            scope_reference="approved-engagement",
            approved_targets=["198.51.100.10"],
            approved_ports=[80],
        ).save_checkpoint(plan_path)
        scan_args = argparse.Namespace(
            active_command="scan",
            session=str(plan_path),
            scope=None,
            mode="live",
            offline_targets=None,
            checkpoint=str(checkpoint_path),
            output=str(checkpoint_path),
        )
        with self.assertRaisesRegex(ValueError, "distinct"):
            command_active_discovery(scan_args)
        self.assertFalse(checkpoint_path.exists())

        ActiveScanSession.load_checkpoint(plan_path).save_checkpoint(checkpoint_path)
        alias = self.root / "checkpoint-alias.json"
        alias.symlink_to(checkpoint_path)
        resume_args = argparse.Namespace(
            active_command="resume",
            checkpoint=str(checkpoint_path),
            scope=None,
            mode="live",
            offline_targets=None,
            checkpoint_out=None,
            output=str(alias),
        )
        with self.assertRaisesRegex(ValueError, "distinct"):
            command_active_discovery(resume_args)
        self.assertEqual(
            ActiveScanSession.load_checkpoint(checkpoint_path).session_id,
            "cli-output-separation",
        )


if __name__ == "__main__":
    unittest.main()


def test_nmap_import_rejects_declared_entities(tmp_path):
    from cops.discovery.importer import import_nmap_xml

    scan = tmp_path / "entities.xml"
    scan.write_text('<!DOCTYPE nmaprun [<!ENTITY expanded "payload">]><nmaprun>&expanded;</nmaprun>')
    with unittest.TestCase().assertRaisesRegex(ValueError, "entity declarations"):
        import_nmap_xml(scan)
