"""Step definitions for Database, Cache, and Search Services BDD scenarios."""

from __future__ import annotations

from pathlib import Path
import sys
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    CleanupReceipt,
    DataAuthPrerequisite,
    DataExposureStatus,
    DataPrivilegeCandidate,
    DataPrivilegeImpact,
    DataServiceAssessment,
    DataServiceCategory,
    DataServicesReport,
    DataServiceType,
    OfflineSyntheticDataCollector,
    assess_data_services,
)

scenarios("../../specs/features/network_data_services.feature")


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["vulnerable-db.corp.internal"],
        "targets_db": {
            "vulnerable-db.corp.internal": {
                "mysql": {"auth_required": False, "password_required": False, "version": "8.0.30"},
                "postgres": {"auth_required": False, "auth_method": "trust", "version": "14.2"},
                "mssql": {"auth_required": False, "blank_sa": True, "xp_cmdshell": True, "version": "SQL Server 2019"},
                "oracle": {"auth_required": False, "default_credentials": True, "sid": "ORCL", "version": "19c"},
                "mongodb": {"auth_required": False, "auth_enabled": False, "version": "5.0.6"},
                "couchdb": {"auth_required": False, "admin_party": True, "version": "3.2.1"},
                "cassandra": {"auth_required": False, "default_creds": True, "version": "4.0.1"},
                "redis": {"auth_required": False, "requirepass": False, "config_set_enabled": True, "version": "6.2.6"},
                "memcached": {"auth_required": False, "sasl_enabled": False, "version": "1.6.9"},
                "elasticsearch": {"auth_required": False, "security_enabled": False, "version": "7.17.0"},
                "influxdb": {"auth_required": False, "auth_enabled": False, "version": "1.8.10"},
                "kibana": {"auth_required": False, "auth_enabled": False, "version": "7.17.0"},
                "splunk": {"auth_required": False, "default_creds": True, "version": "9.0.1"},
            },
            "hardened-db.corp.internal": {
                "redis": {"protected": True, "auth_required": True, "auth_prerequisite": "token_or_api_key", "version": "7.2.3"},
                "postgres": {"protected": True, "auth_required": True, "auth_prerequisite": "user_password", "version": "16.1"},
                "elasticsearch": {"protected": True, "auth_required": True, "auth_prerequisite": "user_password", "version": "8.11.0"},
            },
            "filtered-db.corp.internal": {
                "postgres": {"state": "filtered"},
                "redis": {"state": "timeout"},
                "elasticsearch": {"inaccessible": True},
            },
        },
        "report": None,
        "query_budget": 5,
        "canary_id": "canary_audit_table",
    }


# Scenario 1: Assessing database, cache, and search services with protocol-specific collectors

@given("an approved target host exposing MySQL, Postgres, MSSQL, Oracle, MongoDB, CouchDB, Cassandra, Redis, Memcached, Elasticsearch, InfluxDB, Kibana, and Splunk")
def given_target_with_all_13_services(bdd_ctx):
    bdd_ctx["targets"] = ["vulnerable-db.corp.internal"]


@when("the data services assessment engine executes protocol-specific probes")
def when_engine_executes_all_probes(bdd_ctx):
    collector = OfflineSyntheticDataCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_data_services(
        targets=bdd_ctx["targets"],
        collector=collector,
        vantage="internal",
        canary_artifact=bdd_ctx["canary_id"],
        query_budget_rows=bdd_ctx["query_budget"],
    )


@then("discrete assessments are recorded across relational database, NoSQL document, cache, and search analytics categories")
def then_categories_recorded(bdd_ctx):
    report = bdd_ctx["report"]
    categories = {s.category for s in report.services_assessed}
    assert DataServiceCategory.RELATIONAL_DB.value in categories
    assert DataServiceCategory.NOSQL_DOCUMENT.value in categories
    assert DataServiceCategory.CACHE_INMEMORY.value in categories
    assert DataServiceCategory.SEARCH_ANALYTICS.value in categories
    assert len(report.services_assessed) == 13


@then("observed configurations, authentication prerequisites, and versions are recorded for each service")
def then_configurations_recorded(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.applicable_versions
        assert s.auth_prerequisite is not None
        assert s.exposure_status == DataExposureStatus.EXPOSED.value


# Scenario 2: Enforcing truth-in-advertising boundary where inaccessible services are never reported as secure

@given("a data service that is filtered, connection-refused, or timed out")
def given_inaccessible_service(bdd_ctx):
    bdd_ctx["targets"] = ["filtered-db.corp.internal"]


@when("the data services assessment probe executes")
def when_probe_executes(bdd_ctx):
    collector = OfflineSyntheticDataCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_data_services(
        targets=bdd_ctx["targets"],
        service_types=["postgres", "redis", "elasticsearch"],
        collector=collector,
        vantage="external",
    )


@then('the service exposure status is strictly recorded as "inaccessible"')
def then_status_is_inaccessible(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.exposure_status == DataExposureStatus.INACCESSIBLE.value


@then('the service is never marked as "protected" or "hardened"')
def then_never_protected(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.exposure_status != DataExposureStatus.PROTECTED.value
        assert s.exposure_status != DataExposureStatus.REMEDIATED.value


@then('authentication prerequisite is recorded as "unknown" with explicit uncertainty notes')
def then_auth_unknown_with_uncertainty(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.auth_prerequisite == DataAuthPrerequisite.UNKNOWN.value
        assert len(s.uncertainty_notes) > 0
        assert "cannot be reported as secure" in s.uncertainty_notes[0].lower()


# Scenario 3: Enforcing bounded query budget and preventing bulk data extraction

@given(parsers.parse("an assessment targeting database and search services with query budget {budget:d}"))
def given_assessment_with_query_budget(bdd_ctx, budget):
    bdd_ctx["targets"] = ["vulnerable-db.corp.internal"]
    bdd_ctx["query_budget"] = budget


@when("data service assessment probes execute against candidate databases")
def when_probes_execute_with_budget(bdd_ctx):
    collector = OfflineSyntheticDataCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_data_services(
        targets=bdd_ctx["targets"],
        service_types=["mysql", "elasticsearch"],
        collector=collector,
        query_budget_rows=bdd_ctx["query_budget"],
    )


@then(parsers.parse("each assessment enforces a query budget of {budget:d} rows or documents"))
def then_enforces_budget(bdd_ctx, budget):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.query_budget_rows == budget


@then("bulk extraction is prohibited and zero bulk tables or collections are extracted")
def then_zero_bulk_extraction(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        # Configuration details must not contain raw table records or document bulk payloads
        assert "bulk_records" not in s.configuration_details
        assert "dump_data" not in s.configuration_details


# Scenario 4: Validating boundary controls using canary records and generating verified cleanup receipts

@given(parsers.parse('an assessment configured with canary identifier "{canary_id}"'))
def given_canary_config(bdd_ctx, canary_id):
    bdd_ctx["targets"] = ["vulnerable-db.corp.internal"]
    bdd_ctx["canary_id"] = canary_id


@when("the data services assessment executes canary validation probes")
def when_canary_probes_execute(bdd_ctx):
    collector = OfflineSyntheticDataCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_data_services(
        targets=bdd_ctx["targets"],
        service_types=["redis", "postgres"],
        collector=collector,
        canary_artifact=bdd_ctx["canary_id"],
    )


@then("canary validation status is confirmed in the assessment record")
def then_canary_validated(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.canary_validated is True
        assert s.canary_identifier == bdd_ctx["canary_id"]


@then('a verified cleanup receipt with "verified_removed" status and receipt hash is emitted')
def then_receipts_emitted(bdd_ctx):
    report = bdd_ctx["report"]
    assert len(report.cleanup_receipts) >= 2
    for r in report.cleanup_receipts:
        assert r.verified_clean is True
        assert r.action_taken == "verified_removed"
        assert r.receipt_hash is not None
        assert len(r.receipt_hash) == 64


# Scenario 5: Extracting data privilege candidates for lateral movement and database takeover

@given("an evaluated target exhibiting unauthenticated Redis, trust Postgres, open Elasticsearch, and blank sa MSSQL")
def given_target_with_critical_vulns(bdd_ctx):
    bdd_ctx["targets"] = ["vulnerable-db.corp.internal"]


@when("data privilege candidates are extracted")
def when_candidates_extracted(bdd_ctx):
    collector = OfflineSyntheticDataCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_data_services(
        targets=bdd_ctx["targets"],
        service_types=["redis", "postgres", "elasticsearch", "mssql"],
        collector=collector,
        vantage="internal",
    )


@then(parsers.parse('actionable candidates for "{c1}", "{c2}", "{c3}", "{c4}", and "{c5}" are generated'))
def then_actionable_candidates_generated(bdd_ctx, c1, c2, c3, c4, c5):
    report = bdd_ctx["report"]
    candidate_types = {c.finding_type for c in report.privilege_candidates}
    for expected in [c1, c2, c3, c4, c5]:
        assert expected in candidate_types


@then("each candidate contains service type, target host, port, privilege impact, SHA-256 evidence hash, and remediation guidance")
def then_candidate_structure_verified(bdd_ctx):
    report = bdd_ctx["report"]
    for c in report.privilege_candidates:
        assert c.service_type is not None
        assert c.target_host == "vulnerable-db.corp.internal"
        assert c.port > 0
        assert c.privilege_impact is not None
        assert len(c.evidence_hash) == 64
        assert len(c.remediation_guidance) > 10


# Scenario 6: Reporting properly authenticated and hardened services as protected or remediated

@given("a hardened server enforcing Redis requirepass, Postgres scram-sha-256, and Elasticsearch security")
def given_hardened_server(bdd_ctx):
    bdd_ctx["targets"] = ["hardened-db.corp.internal"]


@when("the data services assessment evaluates access controls")
def when_evaluates_access_controls(bdd_ctx):
    collector = OfflineSyntheticDataCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_data_services(
        targets=bdd_ctx["targets"],
        service_types=["redis", "postgres", "elasticsearch"],
        collector=collector,
        vantage="internal",
    )


@then('the exposure status is reported as "protected"')
def then_status_is_protected(bdd_ctx):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.exposure_status == DataExposureStatus.PROTECTED.value


@then(parsers.parse('authentication prerequisites reflect "{p1}" or "{p2}"'))
def then_auth_prerequisites_hardened(bdd_ctx, p1, p2):
    report = bdd_ctx["report"]
    for s in report.services_assessed:
        assert s.auth_prerequisite in (p1, p2)


@then("zero unauthenticated data privilege candidates are generated")
def then_zero_candidates_on_hardened(bdd_ctx):
    report = bdd_ctx["report"]
    assert len(report.privilege_candidates) == 0
