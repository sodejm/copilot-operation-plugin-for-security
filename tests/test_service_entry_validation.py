"""Offline service handoff: evidence, endpoint scope, and claim boundaries."""

from __future__ import annotations

import unittest

from cops.discovery.active_models import (
    ActiveScanSession,
    ActiveServiceAssessment,
    InferredFingerprint,
    ObservedConfiguration,
    TargetShiftQuarantine,
)
from cops.discovery.service_entry_validation import (
    ApprovedEndpoint,
    prepare_service_entry_handoff,
    prepare_session_service_handoffs,
)


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


class ServiceEntryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoint = ApprovedEndpoint("lab.example", "192.0.2.10", 2222, "tcp", "internal")

    def test_nonstandard_ssh_port_preserved_with_separate_authorization(self) -> None:
        result = prepare_service_entry_handoff(assessment(), approved_endpoints={self.endpoint})
        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.specialist, "network-remote-and-file-services")
        self.assertEqual(result.plan.endpoint, self.endpoint)
        self.assertEqual(
            result.plan.action, "Validate SSH configuration and authentication boundaries on the exact endpoint"
        )
        self.assertTrue(result.plan.requires_execution_authorization)
        self.assertTrue(result.plan.requires_budget)
        self.assertIsNone(result.verified_finding)
        self.assertIsNone(result.authorized_use)
        self.assertEqual(
            result.plan.plan_id,
            prepare_service_entry_handoff(assessment(), approved_endpoints={self.endpoint}).plan.plan_id,
        )

    def test_port_only_fingerprint_and_tls_are_not_service_evidence(self) -> None:
        web_endpoint = ApprovedEndpoint("lab.example", "192.0.2.10", 443, "tcp", "internal")
        result = prepare_service_entry_handoff(
            assessment(
                port=443,
                observed_config=ObservedConfiguration(),
                inferred_fingerprint=InferredFingerprint(service_name="http", confidence="high"),
            ),
            approved_endpoints={web_endpoint},
        )
        self.assertEqual(result.status, "unverified_protocol")
        self.assertIsNone(result.plan)
        self.assertIsNone(result.specialist)

    def test_scope_is_exact_including_ip_port_transport_and_vantage(self) -> None:
        for changes in (
            {"resolved_ip": "192.0.2.11"},
            {"port": 22},
            {"protocol": "udp"},
            {"vantage": "external"},
            {"target_host": "elsewhere.example"},
        ):
            with self.subTest(changes=changes):
                result = prepare_service_entry_handoff(assessment(**changes), approved_endpoints={self.endpoint})
                self.assertEqual(result.status, "blocked_scope")
                self.assertIsNone(result.plan)

    def test_closed_or_unreachable_has_no_candidate(self) -> None:
        for changes in ({"port_state": "closed"}, {"reachability": "unreachable"}):
            with self.subTest(changes=changes):
                result = prepare_service_entry_handoff(assessment(**changes), approved_endpoints={self.endpoint})
                self.assertEqual(result.status, "unavailable")
                self.assertIsNone(result.plan)

    def test_unknown_banner_has_no_specialist_or_finding(self) -> None:
        result = prepare_service_entry_handoff(
            assessment(observed_config=ObservedConfiguration(raw_banner="unrecognized protocol")),
            approved_endpoints={self.endpoint},
        )
        self.assertEqual(result.status, "unverified_protocol")
        self.assertIsNone(result.plan)
        self.assertIsNone(result.verified_finding)

    def test_http_response_routes_on_nonstandard_port_without_finding(self) -> None:
        result = prepare_service_entry_handoff(
            assessment(observed_config=ObservedConfiguration(http_status=403)),
            approved_endpoints={self.endpoint},
        )
        self.assertEqual(result.service, "http")
        self.assertEqual(result.specialist, "web-api-inventory-and-replay")
        self.assertEqual(result.status, "candidate")
        self.assertIsNone(result.verified_finding)

    def test_conflicting_protocol_evidence_fails_closed(self) -> None:
        result = prepare_service_entry_handoff(
            assessment(observed_config=ObservedConfiguration(raw_banner="SSH-2.0-server", http_status=200)),
            approved_endpoints={self.endpoint},
        )
        self.assertEqual(result.status, "conflicting_evidence")
        self.assertIsNone(result.plan)

    def test_malformed_endpoint_cannot_be_approved(self) -> None:
        for host in ("*.example", "lab.example\nInjected", " lab.example"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                ApprovedEndpoint(host, "192.0.2.10", 2222, "tcp", "internal")

    def test_plan_identity_changes_with_observed_evidence(self) -> None:
        first = prepare_service_entry_handoff(assessment(), approved_endpoints={self.endpoint})
        changed = prepare_service_entry_handoff(
            assessment(observed_config=ObservedConfiguration(raw_banner="SSH-2.0-OtherSSH_1.0\r\n")),
            approved_endpoints={self.endpoint},
        )
        self.assertNotEqual(first.plan.plan_id, changed.plan.plan_id)

    def test_failed_or_unattributed_probe_cannot_create_plan(self) -> None:
        for changes in (
            {"probe_id": ""},
            {"error_message": "probe failed"},
            {"timestamp_utc": "not-a-timestamp"},
        ):
            with self.subTest(changes=changes):
                result = prepare_service_entry_handoff(assessment(**changes), approved_endpoints={self.endpoint})
                self.assertEqual(result.status, "invalid_evidence")
                self.assertIsNone(result.plan)

    def test_quarantined_host_cannot_create_plan(self) -> None:
        result = prepare_service_entry_handoff(
            assessment(),
            approved_endpoints={self.endpoint},
            quarantined_hosts={"LAB.EXAMPLE"},
        )
        self.assertEqual(result.status, "blocked_scope")
        self.assertIsNone(result.plan)

    def test_ipv6_quarantine_alias_cannot_create_plan(self) -> None:
        endpoint = ApprovedEndpoint("2001:db8::1", "2001:db8::1", 2222, "tcp", "internal")
        result = prepare_service_entry_handoff(
            assessment(target_host="2001:0db8:0:0:0:0:0:1", resolved_ip="2001:db8::1"),
            approved_endpoints={endpoint},
            quarantined_hosts={"2001:0DB8:0:0:0:0:0:1"},
        )
        self.assertEqual(result.status, "blocked_scope")
        self.assertIsNone(result.plan)

    def test_session_handoff_carries_quarantine_and_requires_external_scope(self) -> None:
        session = ActiveScanSession(
            session_id="session-285",
            scope_reference="scope-285",
            approved_targets=["lab.example"],
            approved_ports=[2222],
            assessments=[assessment()],
        )
        self.assertEqual(
            prepare_session_service_handoffs(session, approved_endpoints=[])[0].status,
            "blocked_scope",
        )
        session.quarantined_targets.append(
            TargetShiftQuarantine("LAB.EXAMPLE", "192.0.2.10", "192.0.2.11", "resolution changed")
        )
        result = prepare_session_service_handoffs(session, approved_endpoints={self.endpoint})[0]
        self.assertEqual(result.status, "blocked_scope")
        self.assertIsNone(result.plan)

    def test_udp_banner_does_not_route_to_tcp_specialist(self) -> None:
        udp_endpoint = ApprovedEndpoint("lab.example", "192.0.2.10", 2222, "udp", "internal")
        result = prepare_service_entry_handoff(
            assessment(protocol="udp"),
            approved_endpoints={udp_endpoint},
        )
        self.assertEqual(result.status, "unverified_protocol")
        self.assertIsNone(result.plan)


if __name__ == "__main__":
    unittest.main()
