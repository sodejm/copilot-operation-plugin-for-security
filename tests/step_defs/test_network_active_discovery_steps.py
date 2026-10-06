# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Step definitions for Network Active Discovery BDD scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    ActiveScanner,
    ActiveScanSession,
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

scenarios("../../specs/features/network_active_discovery.feature")


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
        "scope": {
            "domains": ["corp.internal"],
            "ip_ranges": ["198.51.100.0/24"],
        },
        "mock_targets": {
            "app.corp.internal": {
                "ports": {
                    80: {"banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "headers": {"Server": "nginx/1.18.0"}, "http_status": 200},
                    443: {"tls": {"version": "TLSv1.3", "subject_cn": "app.corp.internal", "sans": ["app.corp.internal"]}, "headers": {"Server": "nginx/1.18.0"}, "http_status": 200},
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
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(
        targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"]
    )


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
        assert a.reachability in (ServiceReachability.REACHABLE.value, ServiceReachability.UNREACHABLE.value, ServiceReachability.FILTERED.value)
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

    bdd_ctx["session"] = session
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(
        targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"]
    )


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
    assert len(completed.assessments) == 1
    assert completed.assessments[0].port == 22


@then("zero redundant probe side effects are dispatched to already assessed ports")
def then_zero_redundant_side_effects(bdd_ctx):
    assert bdd_ctx["dispatcher"].side_effect_count == 1


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


@then("SSH banners produce high-confidence product and OS inferences")
def then_ssh_high_confidence(bdd_ctx):
    fp = bdd_ctx["fingerprints"]["ssh"]
    assert fp.product == "OpenSSH"
    assert fp.version == "8.9p1"
    assert fp.os_inferred == "Ubuntu Linux"
    assert fp.confidence == ConfidenceLevel.HIGH.value


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
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(
        targets=bdd_ctx["mock_targets"], dns_map=bad_dns
    )
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
        "filtered.corp.internal": {
            "ports": {8080: {"state": "filtered", "timeout": True}}
        },
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
    bdd_ctx["dispatcher"] = OfflineSyntheticDispatcher(
        targets=bdd_ctx["mock_targets"], dns_map=bdd_ctx["dns_map"]
    )


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
        approved_ports=[80, 22],
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
                22: {"state": "closed"},
            }
        }
    }
    sess_retest = ActiveScanSession(
        session_id="bdd-retest",
        scope_reference="BDD-SCOPE-01",
        approved_targets=["app.corp.internal"],
        approved_ports=[80, 22],
    )
    disp = OfflineSyntheticDispatcher(targets=remediated_mock, dns_map=bdd_ctx["dns_map"])
    scanner = ActiveScanner(session=sess_retest, dispatcher=disp, scope=bdd_ctx["scope"])
    bdd_ctx["retest_session"] = scanner.run()


@when("the active scan delta comparison is evaluated")
def when_delta_evaluated(bdd_ctx):
    bdd_ctx["delta"] = compare_active_scans(bdd_ctx["baseline_session"], bdd_ctx["retest_session"])


@then("closed or filtered ports are identified as remediated exposures")
def then_remediated_ports_identified(bdd_ctx):
    delta = bdd_ctx["delta"]
    assert len(delta.remediated_exposures) == 1
    assert delta.remediated_exposures[0]["port"] == 22


@then("an exact remediation rate percentage is calculated")
def then_exact_remediation_rate(bdd_ctx):
    delta = bdd_ctx["delta"]
    assert delta.remediation_rate == 50.0
