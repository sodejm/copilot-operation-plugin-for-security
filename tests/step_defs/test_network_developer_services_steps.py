# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Step definitions for Developer and Runtime Interfaces BDD scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    DeveloperAuthPrerequisite,
    DeveloperCategory,
    DeveloperExposureStatus,
    DeveloperPrivilegeImpact,
    ExecutionEffect,
    OfflineSyntheticDeveloperCollector,
    assess_developer_services,
)

scenarios("../../specs/features/network_developer_services.feature")


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["vulnerable-dev.corp.internal"],
        "targets_db": {
            "vulnerable-dev.corp.internal": {
                "docker": {"socket_exposed": True, "tls_verify": False, "auth_required": False, "version": "Docker 20.10"},
                "docker_registry": {"catalog_accessible": True, "auth_required": False, "version": "Registry 2.8"},
                "rmi": {"unauthenticated_registry": True, "codebase_only": False, "version": "Java RMI 11"},
                "jdwp": {"debug_agent_exposed": True, "auth_required": False, "version": "JDWP 1.6"},
                "erlang_epmd": {"names_accessible": True, "weak_cookie": True, "version": "EPMD 5.9"},
                "adb": {"wireless_debugging": True, "rsa_key_required": False, "version": "ADB 1.0.41"},
                "distcc": {"allow_cidr_missing": True, "auth_required": False, "version": "distcc 3.3"},
                "svn": {"anon_access": True, "auth_required": False, "version": "svnserve 1.14"},
                "ajp": {"secret_required": False, "ghostcat_vulnerable": True, "version": "Tomcat 9.0"},
                "fastcgi": {"exposed_external": True, "auth_required": False, "version": "PHP-FPM 7.4"},
            },
            "hardened-dev.corp.internal": {
                "docker": {"protected": True, "tls_verify": True, "auth_required": True, "auth_prerequisite": "client_cert", "version": "Docker 24.0"},
                "docker_registry": {"protected": True, "auth_required": True, "auth_prerequisite": "token_or_api_key", "version": "Registry 2.8.2"},
                "jdwp": {"protected": True, "debug_agent_exposed": False, "auth_required": True, "auth_prerequisite": "user_password", "version": "JDWP Disabled"},
                "ajp": {"protected": True, "secret_required": True, "auth_required": True, "auth_prerequisite": "user_password", "version": "Tomcat 9.0.31"},
            },
            "filtered-dev.corp.internal": {
                "docker": {"state": "filtered"},
                "jdwp": {"state": "timeout"},
            },
        },
        "collector": None,
        "report": None,
        "assessment": None,
        "candidates": [],
        "canary_id": None,
    }


# Scenario 1: Assessing developer and runtime interface services
@given("an approved target host exposing Docker, Docker Registry, RMI, JDWP, Erlang EPMD, ADB, distcc, SVN, AJP, and FastCGI")
def setup_multi_protocol_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticDeveloperCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )


@when("the developer services assessment engine executes protocol-specific probes")
def execute_multi_protocol_probes(bdd_ctx):
    bdd_ctx["report"] = assess_developer_services(
        targets=["vulnerable-dev.corp.internal"],
        collector=bdd_ctx["collector"],
        vantage="internal",
        allow_code_execution=True,
        allow_state_change=True,
    )


@then("discrete assessments are recorded across container orchestration, language debug, distributed build SCM, and application gateway categories")
def verify_discrete_categories(bdd_ctx):
    report = bdd_ctx["report"]
    categories = {a.category for a in report.assessments}
    assert DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value in categories
    assert DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value in categories
    assert DeveloperCategory.DISTRIBUTED_BUILD_SCM.value in categories
    assert DeveloperCategory.APPLICATION_SERVER_GATEWAY.value in categories


@then("observed configurations, authentication prerequisites, and versions are recorded for each service")
def verify_observed_metadata(bdd_ctx):
    for a in bdd_ctx["report"].assessments:
        assert a.configuration_details is not None
        assert a.auth_prerequisite is not None
        assert a.applicable_versions is not None


# Scenario 2: Enforcing truth boundary
@given("a developer service that is filtered, connection-refused, or timed out")
def setup_filtered_developer_service(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticDeveloperCollector(targets=bdd_ctx["targets_db"])


@when("the developer services assessment probe executes")
def execute_filtered_probe(bdd_ctx):
    bdd_ctx["assessment"] = bdd_ctx["collector"].assess_docker("filtered-dev.corp.internal")


@then('the service exposure status is strictly recorded as "inaccessible"')
def verify_status_inaccessible(bdd_ctx):
    assert bdd_ctx["assessment"].exposure_status == DeveloperExposureStatus.INACCESSIBLE.value


@then('the service is never marked as "protected" or "hardened"')
def verify_never_protected(bdd_ctx):
    assert bdd_ctx["assessment"].exposure_status != DeveloperExposureStatus.PROTECTED.value


@then('authentication prerequisite is recorded as "unknown" with explicit uncertainty notes')
def verify_uncertainty_notes(bdd_ctx):
    assert bdd_ctx["assessment"].auth_prerequisite == DeveloperAuthPrerequisite.UNKNOWN.value
    assert len(bdd_ctx["assessment"].uncertainty_notes) > 0


# Scenario 3: Execution effects and plan binding
@given("an assessment targeting exposed developer services with code execution capabilities")
def setup_execution_effects_target(bdd_ctx):
    bdd_ctx["targets"] = ["vulnerable-dev.corp.internal"]


@when("the assessment executes without explicit code execution authorization")
def execute_without_code_auth(bdd_ctx):
    collector = OfflineSyntheticDeveloperCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=False,
        allow_state_change=False,
    )
    bdd_ctx["assessment"] = collector.assess_docker("vulnerable-dev.corp.internal", canary_artifact="canary_docker")


@then("code execution verification is skipped and recorded in uncertainty notes")
def verify_code_execution_skipped(bdd_ctx):
    assert any("Code execution verification skipped" in note for note in bdd_ctx["assessment"].uncertainty_notes)


@then("the assessment can_execute_code flag is strictly False")
def verify_can_exec_false(bdd_ctx):
    assert bdd_ctx["assessment"].can_execute_code is False


@when("explicit code execution authorization is granted in the plan")
def execute_with_code_auth(bdd_ctx):
    collector = OfflineSyntheticDeveloperCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )
    bdd_ctx["assessment"] = collector.assess_docker("vulnerable-dev.corp.internal", canary_artifact="canary_docker")


@then("code execution capability is verified and bound to the approved plan")
def verify_code_exec_verified(bdd_ctx):
    assert bdd_ctx["assessment"].can_execute_code is True
    assert bdd_ctx["assessment"].bound_to_plan is True


# Scenario 4: Canary validation and cleanup receipts
@given('an assessment configured with canary identifier "canary_docker_probe"')
def setup_canary_config(bdd_ctx):
    bdd_ctx["canary_id"] = "canary_docker_probe"
    bdd_ctx["collector"] = OfflineSyntheticDeveloperCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )


@when("the developer services assessment executes canary validation probes")
def execute_canary_probes(bdd_ctx):
    bdd_ctx["assessment"] = bdd_ctx["collector"].assess_docker(
        "vulnerable-dev.corp.internal",
        canary_artifact=bdd_ctx["canary_id"],
    )


@then("canary validation status is confirmed in the assessment record")
def verify_canary_validated(bdd_ctx):
    assert bdd_ctx["assessment"].canary_validated is True
    assert bdd_ctx["assessment"].canary_identifier == "canary_docker_probe"


@then('a verified cleanup receipt with "verified_removed" status and receipt hash is emitted')
def verify_cleanup_receipt_emitted(bdd_ctx):
    receipts = bdd_ctx["assessment"].cleanup_receipts
    assert len(receipts) > 0
    receipt = receipts[0]
    assert receipt.action_taken == "verified_removed"
    assert receipt.verified_clean is True
    assert len(receipt.receipt_hash) == 64


# Scenario 5: Extracting developer privilege candidates
@given("an evaluated target exhibiting open Docker socket, unauthenticated JDWP, open distcc, and FastCGI exposure")
def setup_privilege_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticDeveloperCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )
    bdd_ctx["report"] = assess_developer_services(
        targets=["vulnerable-dev.corp.internal"],
        service_types=["docker", "jdwp", "distcc", "fastcgi"],
        collector=bdd_ctx["collector"],
        allow_code_execution=True,
        allow_state_change=True,
    )


@when("developer privilege candidates are extracted")
def extract_candidates(bdd_ctx):
    candidates = []
    for ass in bdd_ctx["report"].assessments:
        candidates.extend(ass.privilege_candidates)
    bdd_ctx["candidates"] = candidates


@then('actionable candidates for "docker_socket_rce", "jdwp_code_execution", "distcc_rce", and "fastcgi_rce" are generated')
def verify_expected_candidates(bdd_ctx):
    types = [c.finding_type for c in bdd_ctx["candidates"]]
    assert "docker_socket_rce" in types
    assert "jdwp_code_execution" in types
    assert "distcc_rce" in types
    assert "fastcgi_rce" in types


@then("each candidate contains service type, target host, port, execution effect, privilege impact, SHA-256 evidence hash, and remediation guidance")
def verify_candidate_integrity(bdd_ctx):
    for c in bdd_ctx["candidates"]:
        assert c.service_type
        assert c.target_host
        assert c.port > 0
        assert c.execution_effect in [e.value for e in ExecutionEffect]
        assert c.privilege_impact in [i.value for i in DeveloperPrivilegeImpact]
        assert len(c.evidence_hash) == 64
        assert len(c.remediation_guidance) > 10


# Scenario 6: Protected services
@given("a hardened server enforcing Docker mutual TLS, Docker Registry auth, disabled JDWP, and secret-configured AJP")
def setup_hardened_target(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticDeveloperCollector(
        targets=bdd_ctx["targets_db"],
        allow_code_execution=True,
        allow_state_change=True,
    )


@when("the developer services assessment evaluates access controls")
def evaluate_hardened_controls(bdd_ctx):
    bdd_ctx["report"] = assess_developer_services(
        targets=["hardened-dev.corp.internal"],
        service_types=["docker", "docker_registry", "jdwp", "ajp"],
        collector=bdd_ctx["collector"],
    )


@then('the exposure status is reported as "protected"')
def verify_hardened_protected(bdd_ctx):
    for ass in bdd_ctx["report"].assessments:
        assert ass.exposure_status == DeveloperExposureStatus.PROTECTED.value


@then('authentication prerequisites reflect "client_cert", "token_or_api_key", or "user_password"')
def verify_auth_prerequisites(bdd_ctx):
    allowed_prereqs = {
        DeveloperAuthPrerequisite.CLIENT_CERT.value,
        DeveloperAuthPrerequisite.TOKEN_OR_API_KEY.value,
        DeveloperAuthPrerequisite.USER_PASSWORD.value,
    }
    for ass in bdd_ctx["report"].assessments:
        assert ass.auth_prerequisite in allowed_prereqs


@then("zero unauthenticated developer privilege candidates are generated")
def verify_zero_candidates(bdd_ctx):
    assert bdd_ctx["report"].candidates_count == 0
