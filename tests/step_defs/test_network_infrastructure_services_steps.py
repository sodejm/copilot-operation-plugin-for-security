"""Step definitions for Network Infrastructure and Identity-Facing Services BDD scenarios."""

from __future__ import annotations

from pathlib import Path
import sys
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    AuthPrerequisite,
    IdentityAttackPathCandidate,
    IdentityAttackPathType,
    InfraAssessmentReport,
    InfraServiceAssessment,
    InfraServiceType,
    OfflineSyntheticInfraCollector,
    ServiceExposureStatus,
    assess_infrastructure_services,
)

scenarios("../../specs/features/network_infrastructure_services.feature")


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["dc01.corp.internal"],
        "service_db": {
            "dc01.corp.internal": {
                "dns": {
                    "open_recursion": True,
                    "version": "Microsoft DNS 10.0",
                    "canary_resolved": True,
                },
                "snmp": {
                    "community_strings": ["public"],
                    "sys_descr": "Linux enterprise-gw 5.15.0",
                },
                "ntp": {
                    "monlist_enabled": True,
                    "version": "ntpd 4.2.8",
                },
                "rpc": {
                    "interfaces": [
                        {"uuid": "12345778-1234-abcd-ef00-0123456789ac", "name": "SAMR"},
                    ],
                },
                "ldap": {
                    "anonymous_root_dse": True,
                    "naming_contexts": ["DC=corp,DC=internal"],
                    "supported_sasl": ["GSSAPI"],
                },
                "kerberos": {
                    "realm": "CORP.INTERNAL",
                    "preauth_disabled_accounts": ["svc_backup"],
                    "canary_user_preauth_required": True,
                },
            },
            "hardened-dc.corp.internal": {
                "ldap": {"anonymous_root_dse": False},
                "kerberos": {"preauth_disabled_accounts": [], "realm": "CORP.INTERNAL"},
            },
            "filtered.corp.internal": {
                "ldap": {"inaccessible": True},
            },
        },
        "collector": None,
        "report": None,
        "assessment": None,
        "candidates": [],
        "canary_domain": None,
        "canary_user": None,
    }


# Scenario 1: Assessing core infrastructure services
@given("an approved target host with DNS recursion, default SNMP strings, NTP monlist, RPC mapper, LDAP rootDSE, and Kerberos pre-auth exposure")
def step_given_approved_target_host(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticInfraCollector(service_db=bdd_ctx["service_db"])


@when("the infrastructure assessment engine executes protocol-specific probes")
def step_when_engine_executes_probes(bdd_ctx):
    bdd_ctx["report"] = assess_infrastructure_services(
        targets=["dc01.corp.internal"],
        service_types=["dns", "snmp", "ntp", "rpc", "ldap", "kerberos"],
        collector=bdd_ctx["collector"],
        vantage="internal",
        canary_id="canary.corp.internal",
    )


@then("discrete assessments are recorded for DNS, SNMP, NTP, RPC, LDAP, and Kerberos")
def step_then_discrete_assessments_recorded(bdd_ctx):
    report = bdd_ctx["report"]
    services = {s.service_type for s in report.services_assessed}
    for expected in ("dns", "snmp", "ntp", "rpc", "ldap", "kerberos"):
        assert expected in services, f"Expected {expected} in evaluated services"


@then("observed configurations and versions are recorded for each service")
def step_then_observed_configs_recorded(bdd_ctx):
    for ass in bdd_ctx["report"].services_assessed:
        assert ass.configuration_details is not None
        assert isinstance(ass.applicable_versions, list)


# Scenario 2: Enforcing truth-in-advertising boundary (inaccessible != secure)
@given("a target service that is filtered, connection-refused, or timed out")
def step_given_target_service_filtered(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticInfraCollector(service_db=bdd_ctx["service_db"])


@when("the infrastructure assessment probe executes")
def step_when_probe_executes_filtered(bdd_ctx):
    bdd_ctx["assessment"] = bdd_ctx["collector"].assess_ldap("filtered.corp.internal")


@then('the service exposure status is strictly recorded as "inaccessible"')
def step_then_status_is_inaccessible(bdd_ctx):
    assert bdd_ctx["assessment"].exposure_status == ServiceExposureStatus.INACCESSIBLE.value


@then('the service is never marked as "protected" or "hardened"')
def step_then_never_marked_protected(bdd_ctx):
    assert bdd_ctx["assessment"].exposure_status != ServiceExposureStatus.PROTECTED.value


@then('authentication prerequisite is recorded as "unknown" with explicit uncertainty notes')
def step_then_auth_unknown_with_notes(bdd_ctx):
    ass = bdd_ctx["assessment"]
    assert ass.auth_prerequisite == AuthPrerequisite.UNKNOWN.value
    assert len(ass.uncertainty_notes) > 0
    assert any("inaccessible" in n.lower() for n in ass.uncertainty_notes)


# Scenario 3: Extracting identity attack-path candidates
@given("an evaluated target exhibiting anonymous LDAP rootDSE and accounts with Kerberos pre-authentication disabled")
def step_given_evaluated_target_with_identity_exposure(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticInfraCollector(service_db=bdd_ctx["service_db"])
    bdd_ctx["report"] = assess_infrastructure_services(
        targets=["dc01.corp.internal"],
        service_types=["ldap", "kerberos"],
        collector=bdd_ctx["collector"],
        vantage="internal",
    )


@when("identity attack-path candidates are extracted")
def step_when_candidates_extracted(bdd_ctx):
    bdd_ctx["candidates"] = bdd_ctx["report"].all_attack_path_candidates


@then('actionable candidates for "ldap_anonymous_reconnaissance" and "asrep_roasting" are generated')
def step_then_actionable_candidates_generated(bdd_ctx):
    path_types = {c.attack_path_type for c in bdd_ctx["candidates"]}
    assert IdentityAttackPathType.LDAP_ANONYMOUS_RECONNAISSANCE.value in path_types
    assert IdentityAttackPathType.ASREP_ROASTING.value in path_types


@then("each candidate contains domain realm, target principal, SHA-256 evidence hash, and remediation guidance")
def step_then_candidate_has_evidence_and_guidance(bdd_ctx):
    for c in bdd_ctx["candidates"]:
        assert c.evidence_hash
        assert c.remediation_guidance
        assert c.ad_domain_realm


# Scenario 4: Validating boundary controls using canary records
@given(parsers.parse('an assessment configured with canary domain "{canary_domain}" and canary user "{canary_user}"'))
def step_given_canary_config(bdd_ctx, canary_domain, canary_user):
    bdd_ctx["canary_domain"] = canary_domain
    bdd_ctx["canary_user"] = canary_user
    bdd_ctx["collector"] = OfflineSyntheticInfraCollector(service_db=bdd_ctx["service_db"])


@when("the infrastructure assessment executes canary boundary probes")
def step_when_canary_probes_execute(bdd_ctx):
    bdd_ctx["dns_ass"] = bdd_ctx["collector"].assess_dns("dc01.corp.internal", canary_id=bdd_ctx["canary_domain"])
    bdd_ctx["krb_ass"] = bdd_ctx["collector"].assess_kerberos("dc01.corp.internal", canary_id=bdd_ctx["canary_user"])


@then("canary validation status is confirmed in the assessment record without touching production directory data")
def step_then_canary_status_confirmed(bdd_ctx):
    assert bdd_ctx["dns_ass"].canary_validated is True
    assert bdd_ctx["dns_ass"].canary_identifier == bdd_ctx["canary_domain"]
    assert bdd_ctx["krb_ass"].canary_validated is True
    assert bdd_ctx["krb_ass"].canary_identifier == bdd_ctx["canary_user"]


# Scenario 5: Reporting properly authenticated and hardened services as protected
@given("a hardened domain controller enforcing mandatory LDAP authentication and Kerberos pre-authentication")
def step_given_hardened_domain_controller(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticInfraCollector(service_db=bdd_ctx["service_db"])


@when("the infrastructure assessment evaluates access controls")
def step_when_evaluates_access_controls(bdd_ctx):
    bdd_ctx["report"] = assess_infrastructure_services(
        targets=["hardened-dc.corp.internal"],
        service_types=["ldap", "kerberos"],
        collector=bdd_ctx["collector"],
        vantage="internal",
    )


@then('the exposure status is reported as "protected"')
def step_then_status_is_protected(bdd_ctx):
    for ass in bdd_ctx["report"].services_assessed:
        assert ass.exposure_status == ServiceExposureStatus.PROTECTED.value


@then('authentication prerequisite is reported as "domain_user"')
def step_then_auth_prereq_domain_user(bdd_ctx):
    for ass in bdd_ctx["report"].services_assessed:
        assert ass.auth_prerequisite == AuthPrerequisite.DOMAIN_USER.value


@then("zero unauthenticated attack-path candidates are generated")
def step_then_zero_attack_path_candidates(bdd_ctx):
    assert len(bdd_ctx["report"].all_attack_path_candidates) == 0
