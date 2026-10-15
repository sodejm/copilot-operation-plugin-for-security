"""Offline service handoff: checkpoint provenance, route, and scope gates."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from cops.discovery.active_models import (
    ActiveScanSession,
    ActiveServiceAssessment,
    InferredFingerprint,
    ObservedConfiguration,
    TargetShiftQuarantine,
    active_assessment_digest,
)
from cops.discovery.models import EvidenceProvenance
from cops.discovery.service_entry_validation import ApprovedEndpoint, prepare_session_service_handoffs
from cops.routing.catalog import get_specialist


def assessment(**changes: object) -> ActiveServiceAssessment:
    values: dict[str, object] = {
        "probe_id": "probe-285",
        "target_host": "lab.example",
        "resolved_ip": "192.0.2.10",
        "port": 2222,
        "protocol": "tcp",
        "vantage": "internal",
        "port_state": "open",
        "reachability": "reachable",
        "observed_config": ObservedConfiguration(raw_banner="SSH-2.0-OpenSSH_9.0\r\n"),
        "timestamp_utc": "2026-10-14T12:00:00Z",
    }
    values.update(changes)
    return ActiveServiceAssessment(**values)


def scan_session(observed: ActiveServiceAssessment, *, with_provenance: bool = True) -> ActiveScanSession:
    key = ActiveScanSession.make_probe_key(observed.vantage, observed.protocol, observed.target_host, observed.port)
    session = ActiveScanSession(
        session_id="session-285",
        scope_reference="scope-285",
        approved_targets=[observed.target_host],
        approved_ports=[observed.port],
        vantage=observed.vantage,
        status="completed",
        completed_probe_keys={key},
        assessments=[observed],
    )
    if with_provenance:
        observed.provenance = EvidenceProvenance(
            source_id=session.session_id,
            source_type="active_scan",
            sha256=active_assessment_digest(observed),
            timestamp=observed.timestamp_utc,
            path_or_uri=session.scope_reference,
            raw_record_ref=key,
        )
    return session


class ServiceEntryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoint = ApprovedEndpoint("lab.example", "192.0.2.10", 2222, "tcp", "internal")

    def handoff(
        self,
        observed: ActiveServiceAssessment | None = None,
        *,
        approved_endpoints: set[ApprovedEndpoint] | None = None,
    ):
        session = scan_session(observed or assessment())
        return prepare_session_service_handoffs(
            session,
            approved_endpoints={self.endpoint} if approved_endpoints is None else approved_endpoints,
        )[0]

    def test_nonstandard_ssh_port_routes_to_registered_specialist_without_execution(self) -> None:
        result = self.handoff()
        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.specialist, "cops-pentest-specialist")
        self.assertEqual(result.skill_id, "network-remote-and-file-services")
        self.assertIn(result.skill_id, get_specialist(result.specialist).skills)
        self.assertEqual(result.plan.endpoint, self.endpoint)
        self.assertEqual(result.plan.specialist, result.specialist)
        self.assertEqual(result.plan.skill_id, result.skill_id)
        self.assertEqual(result.plan.session_id, "session-285")
        self.assertEqual(result.plan.scope_reference, "scope-285")
        self.assertEqual(result.plan.probe_key, "internal:tcp:lab.example:2222")
        self.assertTrue(result.plan.requires_execution_authorization)
        self.assertTrue(result.plan.requires_budget)
        self.assertIsNone(result.verified_finding)
        self.assertIsNone(result.authorized_use)
        self.assertEqual(result.plan.plan_id, self.handoff().plan.plan_id)

    def test_port_fingerprint_and_tls_are_not_service_evidence(self) -> None:
        web_endpoint = ApprovedEndpoint("lab.example", "192.0.2.10", 443, "tcp", "internal")
        result = self.handoff(
            assessment(
                port=443,
                observed_config=ObservedConfiguration(),
                inferred_fingerprint=InferredFingerprint(service_name="http", confidence="high"),
            ),
            approved_endpoints={web_endpoint},
        )
        self.assertEqual(result.status, "unverified_protocol")
        self.assertIsNone(result.plan)

    def test_scope_is_exact_including_ip_port_transport_and_vantage(self) -> None:
        for changes in (
            {"resolved_ip": "192.0.2.11"},
            {"port": 22},
            {"protocol": "udp"},
            {"vantage": "external"},
            {"target_host": "elsewhere.example"},
        ):
            with self.subTest(changes=changes):
                result = self.handoff(assessment(**changes))
                self.assertEqual(result.status, "blocked_scope")
                self.assertIsNone(result.plan)

    def test_closed_or_unreachable_has_no_candidate(self) -> None:
        for changes in ({"port_state": "closed"}, {"reachability": "unreachable"}):
            with self.subTest(changes=changes):
                result = self.handoff(assessment(**changes))
                self.assertEqual(result.status, "unavailable")
                self.assertIsNone(result.plan)

    def test_unknown_banner_has_no_specialist_or_finding(self) -> None:
        result = self.handoff(assessment(observed_config=ObservedConfiguration(raw_banner="unknown")))
        self.assertEqual(result.status, "unverified_protocol")
        self.assertIsNone(result.plan)
        self.assertIsNone(result.verified_finding)

    def test_http_response_routes_to_registered_web_specialist(self) -> None:
        result = self.handoff(assessment(observed_config=ObservedConfiguration(http_status=403)))
        self.assertEqual(result.service, "http")
        self.assertEqual(result.skill_id, "web-api-inventory-and-replay")
        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.specialist, "cops-pentest-specialist")
        self.assertIsNotNone(result.plan)

    def test_independent_responses_route_all_seven_specialist_families(self) -> None:
        cases = (
            (ObservedConfiguration(http_status=200), "http", "web-api-inventory-and-replay"),
            (ObservedConfiguration(raw_banner="SSH-2.0-Lab\r\n"), "ssh", "network-remote-and-file-services"),
            (ObservedConfiguration(raw_banner="-ERR Redis 5.0.0\r\n"), "redis", "network-data-services"),
            (ObservedConfiguration(raw_banner="220 lab ESMTP\r\n"), "smtp", "network-messaging-services"),
            (
                ObservedConfiguration(raw_banner='{"ApiVersion":"1.44"}'),
                "docker-api",
                "network-developer-interfaces",
            ),
            (ObservedConfiguration(raw_banner="DNS response NOERROR\r\n"), "dns", "network-infrastructure-services"),
            (ObservedConfiguration(raw_banner="SOCKS5 method selected\r\n"), "socks", "network-legacy-and-proxy-services"),
        )
        for observed_config, service, skill_id in cases:
            with self.subTest(service=service):
                result = self.handoff(assessment(observed_config=observed_config))
                self.assertEqual(result.status, "candidate")
                self.assertEqual(result.service, service)
                self.assertEqual(result.skill_id, skill_id)
                self.assertIn(skill_id, get_specialist("cops-pentest-specialist").skills)

    def test_missing_specialist_catalog_fails_closed(self) -> None:
        with patch("cops.discovery.service_entry_validation.get_specialist", side_effect=OSError("offline")):
            result = self.handoff()
        self.assertEqual(result.status, "unsupported_route")
        self.assertIsNone(result.plan)

    def test_conflicting_protocol_evidence_fails_closed(self) -> None:
        result = self.handoff(
            assessment(observed_config=ObservedConfiguration(raw_banner="SSH-2.0-server", http_status=200))
        )
        self.assertEqual(result.status, "conflicting_evidence")
        self.assertIsNone(result.plan)

    def test_malformed_endpoint_cannot_be_approved(self) -> None:
        for host in ("*.example", "lab.example\nInjected", " lab.example"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                ApprovedEndpoint(host, "192.0.2.10", 2222, "tcp", "internal")

    def test_plan_identity_binds_evidence_session_and_scope(self) -> None:
        original = scan_session(assessment())
        baseline = prepare_session_service_handoffs(original, approved_endpoints={self.endpoint})[0].plan.plan_id
        changed = scan_session(assessment(observed_config=ObservedConfiguration(raw_banner="SSH-2.0-Other")))
        changed_session = scan_session(assessment())
        changed_session.session_id = "different-session"
        changed_session.assessments[0].provenance.source_id = "different-session"
        changed_scope = scan_session(assessment())
        changed_scope.scope_reference = "different-scope"
        changed_scope.assessments[0].provenance.path_or_uri = "different-scope"
        for session in (changed, changed_session, changed_scope):
            with self.subTest(session=session):
                plan = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0].plan
                self.assertNotEqual(baseline, plan.plan_id)

    def test_invalid_probe_metadata_cannot_create_plan(self) -> None:
        for changes in ({"probe_id": ""}, {"timestamp_utc": "not-a-timestamp"}):
            with self.subTest(changes=changes):
                result = self.handoff(assessment(**changes))
                self.assertEqual(result.status, "invalid_evidence")
                self.assertIsNone(result.plan)

    def test_failed_probe_cannot_create_plan(self) -> None:
        result = self.handoff(assessment(error_message="probe failed"))
        self.assertEqual(result.status, "invalid_evidence")
        self.assertIsNone(result.plan)

    def test_quarantined_host_cannot_create_plan(self) -> None:
        session = scan_session(assessment())
        session.quarantined_targets.append(
            TargetShiftQuarantine("LAB.EXAMPLE", "192.0.2.10", "192.0.2.11", "resolution changed")
        )
        result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
        self.assertEqual(result.status, "blocked_scope")
        self.assertIsNone(result.plan)

    def test_ipv6_quarantine_alias_cannot_create_plan(self) -> None:
        endpoint = ApprovedEndpoint("2001:db8::1", "2001:db8::1", 2222, "tcp", "internal")
        session = scan_session(assessment(target_host="2001:0db8:0:0:0:0:0:1", resolved_ip="2001:db8::1"))
        session.quarantined_targets.append(
            TargetShiftQuarantine("2001:0DB8:0:0:0:0:0:1", "2001:db8::1", "2001:db8::2", "shifted")
        )
        result = prepare_session_service_handoffs(session, approved_endpoints={endpoint})[0]
        self.assertEqual(result.status, "blocked_scope")
        self.assertIsNone(result.plan)

    def test_scan_checkpoint_cannot_grant_external_scope(self) -> None:
        session = scan_session(assessment())
        result = prepare_session_service_handoffs(session, approved_endpoints=[])[0]
        self.assertEqual(result.status, "blocked_scope")
        self.assertIsNone(result.plan)

    def test_session_identity_status_membership_and_probe_ledger_are_required(self) -> None:
        def variants():
            for field, value in (
                ("session_id", ""),
                ("scope_reference", ""),
                ("status", "invented"),
                ("vantage", "external"),
                ("approved_targets", ["other.example"]),
                ("approved_ports", [22]),
                ("completed_probe_keys", set()),
            ):
                session = scan_session(assessment())
                setattr(session, field, value)
                yield field, session

        for field, session in variants():
            with self.subTest(field=field):
                result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
                self.assertEqual(result.status, "invalid_session")
                self.assertIsNone(result.plan)

    def test_duplicate_assessments_for_one_completed_probe_fail_closed(self) -> None:
        session = scan_session(assessment())
        duplicate = assessment(
            probe_id="probe-duplicate",
            observed_config=ObservedConfiguration(raw_banner="220 FTP server\r\n"),
        )
        probe_key = ActiveScanSession.make_probe_key(
            duplicate.vantage,
            duplicate.protocol,
            duplicate.target_host,
            duplicate.port,
        )
        duplicate.provenance = EvidenceProvenance(
            source_id=session.session_id,
            source_type="active_scan",
            sha256=active_assessment_digest(duplicate),
            timestamp=duplicate.timestamp_utc,
            path_or_uri=session.scope_reference,
            raw_record_ref=probe_key,
        )
        session.assessments.append(duplicate)

        results = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})

        self.assertEqual([result.status for result in results], ["invalid_session", "invalid_session"])
        self.assertTrue(all(result.plan is None for result in results))
        self.assertTrue(all("multiple assessment records" in result.reason for result in results))

    def test_imported_or_absent_provenance_requires_revalidation(self) -> None:
        session = scan_session(assessment(), with_provenance=False)
        result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
        self.assertEqual(result.status, "unverified_source")
        session.assessments[0].provenance = EvidenceProvenance(
            "nmap-import", "nmap", "0" * 64, "2026-10-14T12:00:00Z", "import.xml", "host-1"
        )
        result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
        self.assertEqual(result.status, "unverified_source")

    def test_modified_evidence_or_mismatched_provenance_fails_closed(self) -> None:
        for field, value in (("source_id", "other-session"), ("raw_record_ref", "other-probe")):
            with self.subTest(field=field):
                session = scan_session(assessment())
                setattr(session.assessments[0].provenance, field, value)
                result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
                self.assertEqual(result.status, "invalid_evidence")
                self.assertIsNone(result.plan)
        session = scan_session(assessment())
        session.assessments[0].observed_config.raw_banner = "SSH-2.0-tampered"
        result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
        self.assertEqual(result.status, "invalid_evidence")

    def test_checkpoint_roundtrip_preserves_plan_identity(self) -> None:
        session = scan_session(assessment())
        before = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
        restored = ActiveScanSession.from_dict(session.to_dict())
        after = prepare_session_service_handoffs(restored, approved_endpoints={self.endpoint})[0]
        self.assertEqual(after.status, "candidate")
        self.assertEqual(before.plan.plan_id, after.plan.plan_id)

    def test_udp_banner_does_not_route_to_tcp_specialist(self) -> None:
        udp_endpoint = ApprovedEndpoint("lab.example", "192.0.2.10", 2222, "udp", "internal")
        result = self.handoff(assessment(protocol="udp"), approved_endpoints={udp_endpoint})
        self.assertEqual(result.status, "unverified_protocol")
        self.assertIsNone(result.plan)


if __name__ == "__main__":
    unittest.main()
