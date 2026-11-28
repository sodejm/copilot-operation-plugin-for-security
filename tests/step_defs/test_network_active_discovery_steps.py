# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Step definitions for Network Active Discovery BDD scenarios."""

from __future__ import annotations

import argparse
import os
import ssl
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    ActiveScanError,
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
    infer_service_fingerprint,
)
from cops.discovery.active_scanner import StandardSocketDispatcher, _create_tls_context, _live_checkpoint_lock
from cops.discovery.cli import command_active_discovery

scenarios("../../specs/features/network_active_discovery.feature")


@given("an active scan session plan")
def given_live_scan_plan(bdd_ctx):
    bdd_ctx["live_args"] = argparse.Namespace(active_command="scan", mode="live")


@when("the operator requests live execution")
def when_live_execution_requested(bdd_ctx):
    try:
        with patch("cops.discovery.cli.StandardSocketDispatcher") as dispatcher:
            command_active_discovery(bdd_ctx["live_args"])
    except ValueError as error:
        bdd_ctx["live_error"] = str(error)
    else:
        bdd_ctx["live_error"] = ""
    bdd_ctx["live_dispatcher_constructed"] = dispatcher.called


@then("the command refuses before constructing a live dispatcher")
def then_live_dispatcher_not_constructed(bdd_ctx):
    assert bdd_ctx["live_error"].startswith("Unauthenticated live discovery is unavailable")
    assert not bdd_ctx["live_dispatcher_constructed"]


@then("the refusal directs the operator to the plan-bound service-validation laboratory")
def then_live_refusal_points_to_lab(bdd_ctx):
    assert "plan-bound service-validation laboratory" in bdd_ctx["live_error"]


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["app.corp.internal"],
        "ports": [80, 443, 22],
        "vantage": "external",
        "budget": ScanBudget(rate_limit_pps=50.0, timeout_seconds=2.0),
        "session": None,
        "dispatcher": None,
        "scanner": None,
        "completed": None,
        "delta": None,
        "tls_context": None,
        "scope": {
            "domains": ["corp.internal"],
            "ip_ranges": ["198.51.100.0/24"],
        },
        "mock_targets": {
            "app.corp.internal": {
                "ports": {
                    80: {
                        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
                        "headers": {"Server": "nginx/1.18.0"},
                        "http_status": 200,
                    },
                    443: {
                        "tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal", "sans": ["app.corp.internal"]},
                        "headers": {"Server": "nginx/1.18.0"},
                        "http_status": 200,
                    },
                    22: {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"},
                }
            }
        },
        "dns_map": {
            "app.corp.internal": "198.51.100.10",
        },
        "fingerprints": {},
    }


# Scenario 1: Bounded active port and TLS assessment


@given("an approved target list and port range with external vantage")
def given_targets_ports(bdd_ctx):
    bdd_ctx["session"] = ActiveScanSession(
        session_id="bdd-sess-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=bdd_ctx["targets"],
        approved_ports=bdd_ctx["ports"],
        vantage=ScanVantage.EXTERNAL.value,
        budget=bdd_ctx["budget"],
    )
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"])


@given("an explicit rate limit of 50 probes per second and 2 second timeout")
def given_rate_limit(bdd_ctx):
    bdd_ctx["session"].budget.rate_limit_pps = 50.0
    bdd_ctx["session"].budget.timeout_seconds = 2.0


@when("the active scanner executes against the target inventory")
def when_scanner_executes(bdd_ctx):
    scanner = ActiveScanner(
        session=bdd_ctx["session"],
        dispatcher=bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
    )
    bdd_ctx["completed"] = scanner.run()


@then("discrete assessment records are generated for each approved port")
def then_discrete_records(bdd_ctx):
    completed = bdd_ctx["completed"]
    assert completed.status == "completed"
    assert len(completed.assessments) == len(bdd_ctx["ports"])


@then("each assessment specifies vantage, reachability, latency, and observed configuration")
def then_assessment_fields(bdd_ctx):
    for a in bdd_ctx["completed"].assessments:
        assert a.vantage == ScanVantage.EXTERNAL.value
        assert a.reachability in (
            ServiceReachability.REACHABLE.value,
            ServiceReachability.UNREACHABLE.value,
            ServiceReachability.FILTERED.value,
        )
        assert a.observed_config is not None


# Scenario 2: Resuming active scan without repeating completed side effects


@given("an interrupted active scan session with pre-recorded completed probe keys")
def given_interrupted_session(bdd_ctx):
    session = ActiveScanSession(
        session_id="bdd-resume-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80, 443, 22],
        vantage=ScanVantage.EXTERNAL.value,
    )
    # Pre-record completed port 80 and 443
    key_80 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 80)
    key_443 = ActiveScanSession.make_probe_key(ScanVantage.EXTERNAL.value, "tcp", "app.corp.internal", 443)
    session.completed_probe_keys.update([key_80, key_443])
    session.assessments.extend(
        ActiveServiceAssessment(
            probe_id=f"prior-{port}",
            target_host="app.corp.internal",
            resolved_ip=bdd_ctx["dns_map"]["app.corp.internal"],
            port=port,
            vantage=ScanVantage.EXTERNAL.value,
        )
        for port in (80, 443)
    )

    bdd_ctx["session"] = session
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"])


@when("the active scanner resumes execution from the session checkpoint")
def when_scanner_resumes(bdd_ctx):
    scanner = ActiveScanner(
        session=bdd_ctx["session"],
        dispatcher=bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
    )
    bdd_ctx["completed"] = scanner.run()


@then("previously completed probes are skipped")
def then_probes_skipped(bdd_ctx):
    completed = bdd_ctx["completed"]
    # Only 1 remaining probe (port 22) should have been added
    assert [assessment.port for assessment in completed.assessments] == [80, 443, 22]


@then("zero redundant probe side effects are dispatched to already assessed ports")
def then_zero_redundant_side_effects(bdd_ctx):
    assert bdd_ctx["dispatcher"].side_effect_count == 1


@given("an approved two-port scan with explicit serial concurrency")
def given_serial_cancellable_scan(bdd_ctx):
    bdd_ctx["session"] = ActiveScanSession(
        session_id="bdd-cancel-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80, 443],
        budget=ScanBudget(rate_limit_pps=0, max_concurrency=1),
    )
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"])


@when("cancellation is requested after the first durable result")
def when_cancelled_after_first_durable_result(bdd_ctx):
    partial = ActiveScanner(
        session=bdd_ctx["session"],
        dispatcher=bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
        cancel_requested=lambda: bdd_ctx["dispatcher"].side_effect_count >= 1,
    ).run()
    bdd_ctx["partial"] = ActiveScanSession.from_dict(partial.to_dict())
    resume_session = ActiveScanSession.from_dict(partial.to_dict())
    resume_dispatcher = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"])
    bdd_ctx["resume_dispatcher"] = resume_dispatcher
    bdd_ctx["completed"] = ActiveScanner(
        session=resume_session, dispatcher=resume_dispatcher, scope=bdd_ctx["scope"]
    ).run()


@then("the checkpoint reports one attempted probe and one unassessed probe")
def then_partial_coverage_is_explicit(bdd_ctx):
    assert bdd_ctx["partial"].status == "cancelled"
    assert bdd_ctx["partial"].coverage_summary() == {
        "planned": 2,
        "attempted": 1,
        "completed": 1,
        "pending_reconciliation": 0,
        "skipped": {"total": 0, "quarantined": 0},
        "unassessed": 1,
        "port_states": {"open": 1},
        "timed_out": 0,
    }


@then("resuming completes only the remaining probe")
def then_resume_completes_remaining_probe(bdd_ctx):
    assert bdd_ctx["resume_dispatcher"].side_effect_count == 1
    assert bdd_ctx["completed"].status == "completed"
    assert bdd_ctx["completed"].coverage_summary()["attempted"] == 2
    assert bdd_ctx["completed"].coverage_summary()["unassessed"] == 0


class RecordingLiveDispatcher(StandardSocketDispatcher):
    """Observe live admission and reservations without opening a socket."""

    def __init__(self, resolved_ip="198.51.100.10", checkpoint=None, fail=False):
        self.resolved_ip = resolved_ip
        self.checkpoint = checkpoint
        self.fail = fail
        self.resolutions = 0
        self.probes = 0
        self.reservation_seen = False

    def resolve_target(self, target_host):
        self.resolutions += 1
        return self.resolved_ip

    def dispatch_probe(self, target_host, resolved_ip, port, protocol="tcp", timeout=2.0, vantage="external"):
        self.probes += 1
        if self.checkpoint is not None:
            reserved = ActiveScanSession.load_checkpoint(self.checkpoint)
            self.reservation_seen = (
                ActiveScanSession.make_probe_key(vantage, protocol, target_host, port) in reserved.pending_probe_keys
            )
        if self.fail:
            raise OSError("uncertain probe outcome")
        return ActiveServiceAssessment(
            probe_id=f"recorded-{port}",
            target_host=target_host,
            resolved_ip=resolved_ip,
            port=port,
            protocol=protocol,
            vantage=vantage,
        )


def live_session(targets=None, ports=None):
    return ActiveScanSession(
        session_id="bdd-live-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=targets or ["app.corp.internal"],
        approved_ports=ports or [80],
        budget=ScanBudget(rate_limit_pps=10, max_probes=2, max_total_seconds=30),
    )


@given("a live TCP assessment of approved hosts and ports")
def given_live_assessment(bdd_ctx, tmp_path):
    bdd_ctx["checkpoint"] = tmp_path / "live-checkpoint.json"


@when("the operator omits the approved IP ranges, a positive rate limit, or a checkpoint path")
def when_live_boundary_missing(bdd_ctx):
    outcomes = []
    for missing in ("IP ranges", "rate limit", "checkpoint"):
        session = live_session()
        scope = dict(bdd_ctx["scope"])
        checkpoint = bdd_ctx["checkpoint"]
        if missing == "IP ranges":
            scope.pop("ip_ranges")
        elif missing == "rate limit":
            session.budget.rate_limit_pps = 0
        else:
            checkpoint = None
        dispatcher = RecordingLiveDispatcher()
        with pytest.raises(ActiveScanError) as exc:
            ActiveScanner(session, dispatcher, scope=scope, checkpoint=checkpoint).run()
        outcomes.append((missing, str(exc.value), dispatcher.probes))
    bdd_ctx["admission_outcomes"] = outcomes


@then("the scanner refuses admission before dispatching a probe")
def then_live_refused(bdd_ctx):
    for missing, error, probes in bdd_ctx["admission_outcomes"]:
        assert missing.split()[0].lower() in error.lower()
        assert probes == 0


@then(
    "literal IPv4 and IPv6 targets are evaluated against their approved IP ranges even when domain limits are present"
)
def then_literal_addresses_obey_cidr(bdd_ctx, tmp_path):
    for address, cidr in (("198.51.101.10", "198.51.100.0/24"), ("2001:db8:2::10", "2001:db8:1::/64")):
        dispatcher = RecordingLiveDispatcher(resolved_ip=address)
        result = ActiveScanner(
            live_session(targets=[address]),
            dispatcher,
            scope={"domains": ["corp.internal"], "ip_ranges": [cidr]},
            checkpoint=tmp_path / f"literal-{address.replace(':', '_')}.json",
        ).run()
        assert result.status == "partial"
        assert result.quarantined_targets[0].reason == "outside_scope"
        assert dispatcher.resolutions == dispatcher.probes == 0


@given("an operator selects all 65,535 TCP ports")
def given_full_tcp_selection(bdd_ctx, tmp_path):
    bdd_ctx["full_plan"] = tmp_path / "full-tcp-plan.json"


@when("the operator has not explicitly allowed a full TCP selection and budgeted every target-port pair")
def when_full_tcp_unbounded(bdd_ctx):
    args = argparse.Namespace(
        active_command="plan",
        targets="198.51.100.10",
        ports="all",
        vantage="external",
        rate_limit=10,
        timeout=2,
        max_total_seconds=300,
        scope_ref="BDD-SCOPE-01",
        output=bdd_ctx["full_plan"],
        allow_full_tcp=False,
        max_probes=65535,
    )
    with pytest.raises(ValueError, match="--allow-full-tcp"):
        command_active_discovery(args)
    args.allow_full_tcp = True
    args.max_probes = 65534
    with pytest.raises(ValueError, match="--max-probes"):
        command_active_discovery(args)
    bdd_ctx["full_plan_args"] = args


@then("planning rejects the request")
def then_full_tcp_rejected(bdd_ctx):
    assert not bdd_ctx["full_plan"].exists()


@then("a separately scoped UDP assessment is not implied by TCP selection")
def then_full_tcp_does_not_imply_udp(bdd_ctx):
    args = bdd_ctx["full_plan_args"]
    args.max_probes = 65535
    assert command_active_discovery(args) == 0
    plan = ActiveScanSession.load_checkpoint(bdd_ctx["full_plan"])
    assert len(plan.approved_ports) == 65535
    assert "udp" not in plan.to_dict()


@given("a live probe reserved in a durable checkpoint before network dispatch")
def given_reserved_live_probe(bdd_ctx, tmp_path):
    bdd_ctx["checkpoint"] = tmp_path / "uncertain-live.json"
    bdd_ctx["dispatcher"] = RecordingLiveDispatcher(checkpoint=bdd_ctx["checkpoint"], fail=True)


@when("execution crashes or returns an uncertain error")
def when_live_probe_uncertain(bdd_ctx):
    first = ActiveScanner(
        live_session(),
        bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
        checkpoint=bdd_ctx["checkpoint"],
    ).run()
    bdd_ctx["first_live"] = first
    resumed = ActiveScanSession.load_checkpoint(bdd_ctx["checkpoint"])
    next_dispatcher = RecordingLiveDispatcher()
    bdd_ctx["resumed_live"] = ActiveScanner(
        resumed,
        next_dispatcher,
        scope=bdd_ctx["scope"],
        checkpoint=bdd_ctx["checkpoint"],
    ).run()
    bdd_ctx["resume_dispatcher"] = next_dispatcher


@then("the probe remains pending and restart does not dispatch it again")
def then_uncertain_probe_pending(bdd_ctx):
    assert bdd_ctx["dispatcher"].reservation_seen
    assert bdd_ctx["first_live"].status == "requires_reconciliation"
    assert bdd_ctx["resumed_live"].status == "requires_reconciliation"
    assert len(bdd_ctx["resumed_live"].pending_probe_keys) == 1
    assert bdd_ctx["resumed_live"].total_probes_dispatched == 1
    assert bdd_ctx["resume_dispatcher"].resolutions == bdd_ctx["resume_dispatcher"].probes == 0


@then("a changed plan or scope cannot resume under the old checkpoint")
def then_changed_plan_scope_rejected(bdd_ctx):
    for changed_scope, changed_ports in (
        ({"domains": ["corp.internal"], "ip_ranges": ["198.51.100.0/25"]}, [80]),
        (bdd_ctx["scope"], [80, 443]),
    ):
        resumed = ActiveScanSession.load_checkpoint(bdd_ctx["checkpoint"])
        resumed.approved_ports = changed_ports
        dispatcher = RecordingLiveDispatcher()
        with pytest.raises(ActiveScanError, match="plan or scope changed"):
            ActiveScanner(
                resumed,
                dispatcher,
                scope=changed_scope,
                checkpoint=bdd_ctx["checkpoint"],
            ).run()
        assert dispatcher.resolutions == dispatcher.probes == 0


# Scenario 3: Distinguishing reachable services, inferred fingerprints, and observed configuration


@given("target endpoints with varying service configurations and reverse proxies")
def given_various_endpoints(bdd_ctx):
    pass


@when("the service identification engine evaluates observed response banners and TLS handshakes")
def when_fingerprints_evaluated(bdd_ctx):
    ssh_obs = ObservedConfiguration(raw_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    bdd_ctx["fingerprints"]["ssh"] = infer_service_fingerprint("app.corp.internal", 22, "tcp", ssh_obs)

    http_proxy_obs = ObservedConfiguration(
        http_status=200,
        http_headers={"Server": "nginx/1.18.0", "via": "1.1 varnish"},
    )
    bdd_ctx["fingerprints"]["http"] = infer_service_fingerprint("app.corp.internal", 80, "tcp", http_proxy_obs)

    tls_mismatch = ObservedTLS(
        version="TLSv1.3",
        subject_cn="different.domain.internal",
        sans=["different.domain.internal"],
    )
    tls_obs = ObservedConfiguration(tls=tls_mismatch, http_status=200)
    bdd_ctx["fingerprints"]["tls"] = infer_service_fingerprint("app.corp.internal", 443, "tcp", tls_obs)


@then("SSH banners identify a self-reported product and version without inferring the host OS")
def then_ssh_banner_uncertainty(bdd_ctx):
    fp = bdd_ctx["fingerprints"]["ssh"]
    assert fp.product == "OpenSSH"
    assert fp.version == "8.9p1"
    assert fp.os_inferred is None
    assert fp.confidence == ConfidenceLevel.MEDIUM.value
    assert any("self-reported" in reason for reason in fp.uncertainty_reasons)


@then("HTTP server headers fronted by reverse proxies record explicit uncertainty reasons")
def then_http_uncertainty_reasons(bdd_ctx):
    fp = bdd_ctx["fingerprints"]["http"]
    assert len(fp.uncertainty_reasons) > 0
    assert any("Server header can be masked" in r for r in fp.uncertainty_reasons)


@then("mismatched TLS certificate subjects lower inference confidence")
def then_tls_mismatch_lowers_confidence(bdd_ctx):
    fp = bdd_ctx["fingerprints"]["tls"]
    assert fp.confidence == ConfidenceLevel.LOW.value
    assert any("does not match target host" in r for r in fp.uncertainty_reasons)


# Scenario 4: Quarantining targets upon dynamic DNS shift or rebind detection


@given("an approved target hostname configured in scope")
def given_approved_target_host(bdd_ctx):
    bdd_ctx["session"] = ActiveScanSession(
        session_id="bdd-rebind-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80],
    )


@when("the hostname resolves to an IP address outside authorized CIDR boundaries")
def when_host_resolves_out_of_scope(bdd_ctx):
    bad_dns = {"app.corp.internal": "10.0.0.1"}
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bad_dns)
    scanner = ActiveScanner(
        session=bdd_ctx["session"],
        dispatcher=bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
    )
    bdd_ctx["completed"] = scanner.run()


@then("the active scanner halts outbound probes to that target")
def then_halts_outbound_probes(bdd_ctx):
    assert bdd_ctx["dispatcher"].side_effect_count == 0
    assert len(bdd_ctx["completed"].assessments) == 0


@then('records a "dns_rebind_detected" quarantine entry')
def then_records_dns_rebind_quarantine(bdd_ctx):
    completed = bdd_ctx["completed"]
    assert len(completed.quarantined_targets) == 1
    assert completed.quarantined_targets[0].reason == "dns_rebind_detected"


# Scenario 5: Handling unreachable hosts and timed-out probes gracefully


@given("a target host with unreachable network routes and filtered ports")
def given_unreachable_and_filtered(bdd_ctx):
    mock = {
        "unreachable.corp.internal": {"unreachable": True},
        "filtered.corp.internal": {"ports": {8080: {"state": "filtered", "timeout": True}}},
    }
    dns = {
        "unreachable.corp.internal": "198.51.100.50",
        "filtered.corp.internal": "198.51.100.60",
    }
    bdd_ctx["session"] = ActiveScanSession(
        session_id="bdd-unreach-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["unreachable.corp.internal", "filtered.corp.internal"],
        approved_ports=[8080],
    )
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(targets=mock, dns_map=dns)


@when("active probes are dispatched")
def when_active_probes_dispatched(bdd_ctx):
    scanner = ActiveScanner(
        session=bdd_ctx["session"],
        dispatcher=bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
    )
    bdd_ctx["completed"] = scanner.run()


@then('unreachable hosts are classified as reachability "unreachable"')
def then_unreachable_classified(bdd_ctx):
    unreach = next(a for a in bdd_ctx["completed"].assessments if a.target_host == "unreachable.corp.internal")
    assert unreach.reachability == ServiceReachability.UNREACHABLE.value
    assert unreach.port_state == PortState.UNREACHABLE.value


@then('timed-out ports are classified as port state "filtered" without halting overall scan progress')
def then_timed_out_filtered(bdd_ctx):
    filt = next(a for a in bdd_ctx["completed"].assessments if a.target_host == "filtered.corp.internal")
    assert filt.reachability == ServiceReachability.FILTERED.value
    assert filt.port_state == PortState.FILTERED.value
    assert bdd_ctx["completed"].status == "completed"


# Scenario 6: Checkpointing partial results upon execution budget exhaustion


@given("an active scan session with a tight overall execution time budget")
def given_tight_budget(bdd_ctx):
    bdd_ctx["session"] = ActiveScanSession(
        session_id="bdd-budget-01",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80, 443, 22],
        budget=ScanBudget(max_total_seconds=0.0001),
    )
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"])


@when("the allocated time budget expires during execution")
def when_time_budget_expires(bdd_ctx):
    scanner = ActiveScanner(
        session=bdd_ctx["session"],
        dispatcher=bdd_ctx["dispatcher"],
        scope=bdd_ctx["scope"],
    )
    bdd_ctx["completed"] = scanner.run()


@then('the session status is marked "budget_exhausted"')
def then_session_marked_budget_exhausted(bdd_ctx):
    assert bdd_ctx["completed"].status == "budget_exhausted"


@then("partial assessment results up to the cutoff are preserved in the checkpoint")
def then_partial_results_preserved(bdd_ctx):
    # Status is budget_exhausted and checkpoint can be serialized
    chk = bdd_ctx["completed"].to_dict()
    assert chk["status"] == "budget_exhausted"


# Scenario 7: Verifying remediated exposures against baseline active assessment


@given("a baseline active scan session observing open vulnerable ports")
def given_baseline_scan(bdd_ctx):
    sess_base = ActiveScanSession(
        session_id="bdd-baseline",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80, 443, 22],
    )
    disp = OfflineSyntheticDispatcher(targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"])
    scanner = ActiveScanner(session=sess_base, dispatcher=disp, scope=bdd_ctx["scope"])
    bdd_ctx["baseline_session"] = scanner.run()


@given("a subsequent re-test session after security remediation")
def given_retest_scan(bdd_ctx):
    remediated_mock = {
        "app.corp.internal": {
            "ports": {
                80: bdd_ctx["mock_targets"]["app.corp.internal"]["ports"][80],
                443: {"state": "filtered"},
                22: {"state": "closed"},
            }
        }
    }
    sess_retest = ActiveScanSession(
        session_id="bdd-retest",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80, 443, 22],
    )
    disp = OfflineSyntheticDispatcher(targets=remediated_mock, dns_map=bdd_ctx["dns_map"])
    scanner = ActiveScanner(session=sess_retest, dispatcher=disp, scope=bdd_ctx["scope"])
    bdd_ctx["retest_session"] = scanner.run()


@when("the active scan delta comparison is evaluated")
def when_delta_evaluated(bdd_ctx):
    bdd_ctx["delta"] = compare_active_scans(bdd_ctx["baseline_session"], bdd_ctx["retest_session"])


@then("closed ports are remediated and filtered ports remain unverified")
def then_remediated_ports_identified(bdd_ctx):
    delta = bdd_ctx["delta"]
    assert len(delta.remediated_exposures) == 1
    assert delta.remediated_exposures[0]["port"] == 22
    assert len(delta.unverified_exposures) == 1
    assert delta.unverified_exposures[0]["port"] == 443
    assert delta.unverified_exposures[0]["current_state"] == PortState.FILTERED.value


@then("an exact remediation rate percentage is calculated")
def then_exact_remediation_rate(bdd_ctx):
    delta = bdd_ctx["delta"]
    assert delta.remediation_rate == 33.33


@given("the standard socket TLS probe")
def given_standard_socket_tls_probe(bdd_ctx):
    bdd_ctx["dispatcher"] = StandardSocketDispatcher()


@when("it creates a TLS client context")
def when_tls_context_created(bdd_ctx):
    assert isinstance(bdd_ctx["dispatcher"], StandardSocketDispatcher)
    bdd_ctx["tls_context"] = _create_tls_context()


@then("the minimum TLS version is TLS 1.2")
def then_minimum_tls_version(bdd_ctx):
    assert bdd_ctx["tls_context"].minimum_version == ssl.TLSVersion.TLSv1_2


@given("a live checkpoint controller lock path")
def given_live_checkpoint_controller_lock_path(bdd_ctx, tmp_path):
    bdd_ctx["lock_checkpoint"] = tmp_path / "checkpoint.json"
    bdd_ctx["lock_entered"] = False
    bdd_ctx["lock_error"] = None
    bdd_ctx["lock_replaced"] = False


@when("that lock path is replaced during advisory lock acquisition")
def when_lock_path_is_replaced_during_acquisition(bdd_ctx):
    if os.name == "nt":
        pytest.skip("POSIX replacement semantics")

    import fcntl

    checkpoint = bdd_ctx["lock_checkpoint"]
    lock_path = checkpoint.with_name(f"{checkpoint.name}.lock")
    displaced_lock = lock_path.with_name(f"{lock_path.name}.displaced")
    real_flock = fcntl.flock

    def replace_path_before_lock(descriptor, operation):
        if operation == (fcntl.LOCK_EX | fcntl.LOCK_NB) and not bdd_ctx["lock_replaced"]:
            os.replace(lock_path, displaced_lock)
            lock_path.touch(mode=0o600)
            bdd_ctx["lock_replaced"] = True
        return real_flock(descriptor, operation)

    try:
        with patch.object(fcntl, "flock", side_effect=replace_path_before_lock):
            with _live_checkpoint_lock(checkpoint):
                bdd_ctx["lock_entered"] = True
    except ActiveScanError as error:
        bdd_ctx["lock_error"] = error


@then("the protected live-scan section is not entered")
def then_protected_live_scan_section_is_not_entered(bdd_ctx):
    assert bdd_ctx["lock_replaced"]
    assert not bdd_ctx["lock_entered"]
    assert isinstance(bdd_ctx["lock_error"], ActiveScanError)
    assert "unsafe" in str(bdd_ctx["lock_error"])
