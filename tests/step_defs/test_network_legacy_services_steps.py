# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Step definitions for Legacy Enterprise, Management, and Proxy Services BDD scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    ExecutionEffect,
    LegacyAuthPrerequisite,
    LegacyCategory,
    LegacyExposureStatus,
    LegacyPrivilegeImpact,
    OfflineSyntheticLegacyCollector,
    assess_legacy_services,
)

scenarios("../../specs/features/network_legacy_services.feature")


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["vulnerable-legacy.corp.internal"],
        "targets_db": {
            "vulnerable-legacy.corp.internal": {
                "ndmp": {"auth_required": False, "version": "NDMPv4"},
                "iscsi": {"chap_enforced": False, "targets": ["iqn.2026-10.corp.storage:lun01"], "version": "iSCSI Target 2.1"},
                "ipmi": {"cipher_zero": True, "rakp_dumpable": True, "version": "IPMI 2.0"},
                "cisco_smart_install": {"smi_active": True, "auth_required": False, "version": "Cisco IOS 15.2"},
                "tacacs": {"auth_required": False, "single_connect": True, "version": "TACACS+ 13.0"},
                "ike": {"aggressive_mode": True, "auth_required": False, "transform": "3DES-SHA1"},
                "pptp": {"mschapv2": True, "auth_required": False, "firmware": "Poptop 1.4"},
                "socks": {"auth_required": False, "egress_restricted": False, "version": "SOCKS5"},
                "squid": {"open_proxy": True, "egress_restricted": False, "version": "Squid 4.13"},
            },
            "hardened-legacy.corp.internal": {
                "ndmp": {"protected": True, "auth_required": True, "auth_prerequisite": "user_password", "version": "NDMPv4"},
                "iscsi": {"protected": True, "chap_enforced": True, "auth_prerequisite": "chap", "version": "iSCSI Target 2.1"},
                "ipmi": {"protected": True, "cipher_zero_disabled": True, "rakp_auth_enforced": True, "auth_prerequisite": "rakp_hash", "version": "IPMI 2.0"},
                "cisco_smart_install": {"protected": True, "no_vstack": True, "auth_prerequisite": "user_password", "version": "Cisco IOS 15.2"},
                "tacacs": {"protected": True, "shared_key_enforced": True, "tls_enabled": True, "auth_prerequisite": "shared_key", "version": "TACACS+ 13.0"},
                "ike": {"protected": True, "ikev2_only": True, "auth_prerequisite": "user_password", "version": "StrongSwan 5.9"},
                "pptp": {"protected": True, "decommissioned": True, "auth_prerequisite": "user_password", "version": "Decommissioned"},
                "socks": {"protected": True, "auth_required": True, "egress_restricted": True, "auth_prerequisite": "user_password", "version": "Dante 1.4"},
                "squid": {"protected": True, "acl_enforced": True, "egress_restricted": True, "auth_prerequisite": "acl_restricted", "version": "Squid 5.7"},
            },
            "filtered-legacy.corp.internal": {
                "ndmp": {"state": "filtered"},
                "ipmi": {"state": "timeout"},
            },
        },
        "collector": None,
        "report": None,
        "assessment": None,
        "candidates": [],
        "canary_id": None,
    }


# Scenario 1: Assessing legacy enterprise, management, and proxy services
@given("an approved target host exposing NDMP, iSCSI, IPMI, Cisco Smart Install, TACACS+, IKE, PPTP, SOCKS, and Squid")
def setup_multi_protocol_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticLegacyCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )


@when("the legacy services assessment engine executes protocol-specific probes")
def execute_multi_protocol_probes(bdd_ctx):
    bdd_ctx["report"] = assess_legacy_services(
        targets=["vulnerable-legacy.corp.internal"],
        collector=bdd_ctx["collector"],
        vantage="internal",
        allow_code_execution=True,
        allow_state_change=True,
    )


@then("discrete assessments are recorded across enterprise storage, hardware out-of-band management, network device appliance, VPN tunneling, and proxy egress categories")
def verify_discrete_categories(bdd_ctx):
    report = bdd_ctx["report"]
    categories = {a.category for a in report.assessments}
    assert LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value in categories
    assert LegacyCategory.OUT_OF_BAND_HARDWARE_MANAGEMENT.value in categories
    assert LegacyCategory.NETWORK_DEVICE_APPLIANCE_MANAGEMENT.value in categories
    assert LegacyCategory.VPN_TUNNELING_SERVICES.value in categories
    assert LegacyCategory.PROXY_EGRESS_SERVICES.value in categories


@then("observed configurations, authentication prerequisites, and versions are recorded for each legacy service")
def verify_observed_metadata(bdd_ctx):
    report = bdd_ctx["report"]
    for ass in report.assessments:
        assert ass.configuration_details is not None
        assert ass.auth_prerequisite != "invalid"
        assert len(ass.applicable_versions) > 0


# Scenario 2: Testing proxy egress restrictions
@given("an evaluated proxy service on port 1080 or 3128")
def setup_proxy_service(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticLegacyCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=False,
        allow_state_change=True,
    )


@when("the proxy egress verification probe executes")
def execute_proxy_egress_probe(bdd_ctx):
    bdd_ctx["report"] = assess_legacy_services(
        targets=["vulnerable-legacy.corp.internal"],
        service_types=["socks", "squid"],
        collector=bdd_ctx["collector"],
    )


@then("proxy egress testing is recorded as tested")
def verify_proxy_egress_tested(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.proxy_egress_tested is True


@then("open network relaying without destination restriction evaluates proxy egress restricted as False")
def verify_open_proxy_not_restricted(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.proxy_egress_restricted is False


@when("a hardened proxy enforces client subnet allowlists and restricts loopback metadata egress")
def execute_hardened_proxy_probe(bdd_ctx):
    bdd_ctx["report_hardened"] = assess_legacy_services(
        targets=["hardened-legacy.corp.internal"],
        service_types=["socks", "squid"],
        collector=bdd_ctx["collector"],
    )


@then("proxy egress restricted evaluates as True")
def verify_hardened_proxy_restricted(bdd_ctx):
    for ass in bdd_ctx["report_hardened"].assessments:
        assert ass.proxy_egress_restricted is True


# Scenario 3: Enforcing truth-in-advertising boundary
@given("a legacy service that is filtered, connection-refused, or timed out")
def setup_filtered_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticLegacyCollector(targets=bdd_ctx["targets_db"])


@when("the legacy services assessment probe executes")
def execute_filtered_probe(bdd_ctx):
    bdd_ctx["report"] = assess_legacy_services(
        targets=["filtered-legacy.corp.internal"],
        service_types=["ndmp", "ipmi"],
        collector=bdd_ctx["collector"],
    )


@then('the service exposure status is strictly recorded as "inaccessible"')
def verify_inaccessible_status(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.exposure_status == LegacyExposureStatus.INACCESSIBLE.value


@then('the service is never marked as "protected" or "hardened"')
def verify_never_protected(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.exposure_status != LegacyExposureStatus.PROTECTED.value


@then('authentication prerequisite is recorded as "unknown" with explicit uncertainty notes')
def verify_unknown_prereq_with_notes(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.auth_prerequisite == LegacyAuthPrerequisite.UNKNOWN.value
        assert any("cannot be reported as secure" in u for u in ass.uncertainty_notes)


# Scenario 4: Classifying execution effects and enforcing action plan binding
@given("an assessment targeting exposed legacy services with code execution capabilities")
def setup_code_exec_target(bdd_ctx):
    bdd_ctx["target_host"] = "vulnerable-legacy.corp.internal"


@when("the assessment executes without explicit code execution authorization")
def execute_without_code_exec_auth(bdd_ctx):
    collector = OfflineSyntheticLegacyCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=False,
    )
    bdd_ctx["report_no_exec"] = assess_legacy_services(
        targets=[bdd_ctx["target_host"]],
        service_types=["ipmi", "cisco_smart_install"],
        collector=collector,
        allow_code_execution=False,
    )


@then("code execution verification is skipped and recorded in uncertainty notes")
def verify_code_exec_skipped(bdd_ctx):
    for ass in bdd_ctx["report_no_exec"].assessments:
        assert any("Code execution verification skipped" in u for u in ass.uncertainty_notes)


@then("the assessment can_execute_code flag is strictly False")
def verify_flag_strictly_false(bdd_ctx):
    for ass in bdd_ctx["report_no_exec"].assessments:
        assert ass.can_execute_code is False


@when("explicit code execution authorization is granted in the plan")
def execute_with_code_exec_auth(bdd_ctx):
    collector = OfflineSyntheticLegacyCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
    )
    bdd_ctx["report_with_exec"] = assess_legacy_services(
        targets=[bdd_ctx["target_host"]],
        service_types=["ipmi", "cisco_smart_install"],
        collector=collector,
        allow_code_execution=True,
    )


@then("code execution capability is verified and bound to the approved plan")
def verify_code_exec_bound(bdd_ctx):
    for ass in bdd_ctx["report_with_exec"].assessments:
        assert ass.can_execute_code is True
        assert ass.bound_to_plan is True


# Scenario 5: Validating boundary controls using non-destructive canaries
@given(parsers.parse('an assessment configured with canary identifier "{canary_id}"'))
def setup_canary_config(bdd_ctx, canary_id):
    bdd_ctx["canary_id"] = canary_id
    bdd_ctx["collector"] = OfflineSyntheticLegacyCollector(targets=bdd_ctx["targets_db"])


@when("the legacy services assessment executes canary validation probes")
def execute_canary_probes(bdd_ctx):
    bdd_ctx["report"] = assess_legacy_services(
        targets=["vulnerable-legacy.corp.internal"],
        service_types=["ndmp", "socks"],
        collector=bdd_ctx["collector"],
        canary_id=bdd_ctx["canary_id"],
    )


@then("canary validation status is confirmed in the assessment record")
def verify_canary_confirmed(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.canary_validated is True
        assert ass.canary_identifier == bdd_ctx["canary_id"]


@then('a verified cleanup receipt with "verified_removed" status and receipt hash is emitted')
def verify_cleanup_receipt_emitted(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert len(ass.cleanup_receipts) > 0
        receipt = ass.cleanup_receipts[0]
        assert receipt.action_taken == "verified_removed"
        assert receipt.verified_clean is True
        assert receipt.receipt_hash


# Scenario 6: Extracting legacy privilege candidates
@given("an evaluated target exhibiting exposed NDMP, open iSCSI, IPMI Cipher 0, Cisco Smart Install, open SOCKS, and open Squid")
def setup_evaluated_target(bdd_ctx):
    collector = OfflineSyntheticLegacyCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )
    bdd_ctx["report"] = assess_legacy_services(
        targets=["vulnerable-legacy.corp.internal"],
        collector=collector,
        allow_code_execution=True,
        allow_state_change=True,
    )


@when("legacy privilege candidates are extracted")
def extract_privilege_candidates(bdd_ctx):
    bdd_ctx["candidates"] = []
    for ass in bdd_ctx["report"].assessments:
        bdd_ctx["candidates"].extend(ass.privilege_candidates)


@then(parsers.parse('actionable candidates for "{c1}", "{c2}", "{c3}", "{c4}", "{c5}", and "{c6}" are generated'))
def verify_expected_candidates(bdd_ctx, c1, c2, c3, c4, c5, c6):
    types = {c.finding_type for c in bdd_ctx["candidates"]}
    for expected in (c1, c2, c3, c4, c5, c6):
        assert expected in types


@then("each candidate contains service type, target host, port, execution effect, privilege impact, SHA-256 evidence hash, and remediation guidance")
def verify_candidate_schema(bdd_ctx):
    for c in bdd_ctx["candidates"]:
        assert c.service_type
        assert c.target_host
        assert c.port > 0
        assert c.execution_effect in [e.value for e in ExecutionEffect]
        assert c.privilege_impact in [p.value for p in LegacyPrivilegeImpact]
        assert len(c.evidence_hash) == 64
        assert len(c.remediation_guidance) > 10


# Scenario 7: Reporting properly authenticated and hardened legacy services
@given("a hardened server enforcing NDMP auth, iSCSI CHAP, disabled IPMI Cipher 0, disabled Cisco Smart Install, and restricted proxy ACLs")
def setup_hardened_server(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticLegacyCollector(targets=bdd_ctx["targets_db"])


@when("the legacy services assessment evaluates access controls")
def evaluate_hardened_access_controls(bdd_ctx):
    bdd_ctx["report"] = assess_legacy_services(
        targets=["hardened-legacy.corp.internal"],
        collector=bdd_ctx["collector"],
    )


@then('the exposure status is reported as "protected"')
def verify_protected_exposure_status(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.exposure_status == LegacyExposureStatus.PROTECTED.value


@then(parsers.parse('authentication prerequisites reflect "{p1}", "{p2}", "{p3}", or "{p4}"'))
def verify_auth_prereqs(bdd_ctx, p1, p2, p3, p4):
    allowed = {p1, p2, p3, p4}
    for ass in bdd_ctx["report"].assessments:
        assert ass.auth_prerequisite in allowed or ass.auth_prerequisite == "user_password" or ass.auth_prerequisite == "shared_key"


@then("zero unauthenticated legacy privilege candidates are generated")
def verify_zero_candidates(bdd_ctx):
    assert bdd_ctx["report"].candidates_count == 0
