# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Unit, contract, and CLI tests for database, cache, and search/analytics services assessment."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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
    StandardSocketDataCollector,
    assess_data_services,
)
from cops.discovery.cli import (
    command_data_discovery,
)


class TestDataModelsAndSerialization(unittest.TestCase):
    def test_data_privilege_candidate_post_init_and_serialization(self):
        cand = DataPrivilegeCandidate(
            candidate_id="cand-redis-01",
            service_type="redis",
            category="cache_inmemory",
            target_host="cache01.corp.internal",
            port=6379,
            vantage="internal",
            finding_type="redis_no_auth",
            auth_prerequisites=DataAuthPrerequisite.NONE.value,
            privilege_impact=DataPrivilegeImpact.CACHE_POISONING.value,
        )
        self.assertTrue(cand.evidence_hash)
        self.assertIn("requirepass", cand.remediation_guidance)
        d = cand.to_dict()
        reconstructed = DataPrivilegeCandidate.from_dict(d)
        self.assertEqual(reconstructed.candidate_id, cand.candidate_id)
        self.assertEqual(reconstructed.evidence_hash, cand.evidence_hash)
        self.assertEqual(reconstructed.remediation_guidance, cand.remediation_guidance)
        self.assertEqual(reconstructed.privilege_impact, DataPrivilegeImpact.CACHE_POISONING.value)

    def test_cleanup_receipt_post_init_and_serialization(self):
        receipt = CleanupReceipt(
            receipt_id="rec-data-001",
            target_host="db01.corp.internal",
            service_type="postgres",
            artifact_type="canary_audit_table",
            artifact_identifier="canary_audit_probe",
            action_taken="verified_removed",
            verified_clean=True,
        )
        self.assertTrue(receipt.receipt_hash)
        d = receipt.to_dict()
        reconstructed = CleanupReceipt.from_dict(d)
        self.assertEqual(reconstructed.receipt_id, receipt.receipt_id)
        self.assertEqual(reconstructed.receipt_hash, receipt.receipt_hash)
        self.assertTrue(reconstructed.verified_clean)

    def test_data_service_assessment_serialization_roundtrip(self):
        cand = DataPrivilegeCandidate(
            candidate_id="cand-pg-01",
            service_type="postgres",
            category="relational_db",
            target_host="db01.corp.internal",
            port=5432,
            vantage="internal",
            finding_type="postgres_trust_auth",
            auth_prerequisites=DataAuthPrerequisite.NONE.value,
            privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
        )
        receipt = CleanupReceipt(
            receipt_id="rec-002",
            target_host="db01.corp.internal",
            service_type="postgres",
            artifact_type="canary_table",
            artifact_identifier="canary_audit",
            action_taken="verified_removed",
            verified_clean=True,
        )
        assessment = DataServiceAssessment(
            target_host="db01.corp.internal",
            resolved_ip="198.51.100.35",
            service_type=DataServiceType.POSTGRES.value,
            category=DataServiceCategory.RELATIONAL_DB.value,
            port=5432,
            protocol="tcp",
            vantage="internal",
            exposure_status=DataExposureStatus.EXPOSED.value,
            canary_validated=True,
            canary_identifier="canary_audit",
            authentication_required=False,
            auth_prerequisite=DataAuthPrerequisite.NONE.value,
            assigned_role="postgres",
            query_budget_rows=5,
            applicable_versions=["14.2"],
            configuration_details={"auth_method": "trust"},
            observed_vulnerabilities=["pg_hba.conf configured with 'trust' authentication"],
            privilege_candidates=[cand],
            cleanup_receipts=[receipt],
        )

        d = assessment.to_dict()
        reconstructed = DataServiceAssessment.from_dict(d)
        self.assertEqual(reconstructed.target_host, "db01.corp.internal")
        self.assertEqual(reconstructed.exposure_status, DataExposureStatus.EXPOSED.value)
        self.assertEqual(reconstructed.query_budget_rows, 5)
        self.assertEqual(len(reconstructed.privilege_candidates), 1)
        self.assertEqual(len(reconstructed.cleanup_receipts), 1)

    def test_data_services_report_save_and_load(self):
        report = DataServicesReport(
            report_id="test-report-01",
            scope_reference="scope-db-001",
            vantage="internal",
            services_assessed=[],
            privilege_candidates=[],
            cleanup_receipts=[],
            summary={"total_services": 0, "exposed": 0, "protected": 0, "inaccessible": 0},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "report.json"
            report.save_to_file(file_path)
            self.assertTrue(file_path.is_file())

            loaded = DataServicesReport.load_from_file(file_path)
            self.assertEqual(loaded.report_id, report.report_id)
            self.assertEqual(loaded.scope_reference, report.scope_reference)


class TestOfflineSyntheticDataCollector(unittest.TestCase):
    def setUp(self):
        self.mock_targets = {
            "vulnerable-data.corp.internal": {
                "mysql": {"auth_required": False, "password_required": False, "version": "8.0.28"},
                "postgres": {"auth_required": False, "auth_method": "trust", "version": "14.1"},
                "mssql": {"auth_required": False, "blank_sa": True, "xp_cmdshell": True, "version": "2019"},
                "oracle": {"auth_required": False, "default_credentials": True, "sid": "ORCL", "version": "19c"},
                "mongodb": {"auth_required": False, "auth_enabled": False, "version": "5.0"},
                "couchdb": {"auth_required": False, "admin_party": True, "version": "3.2"},
                "cassandra": {"auth_required": False, "default_creds": True, "version": "4.0"},
                "redis": {"auth_required": False, "requirepass": False, "config_set_enabled": True, "version": "6.2"},
                "memcached": {"auth_required": False, "sasl_enabled": False, "version": "1.6"},
                "elasticsearch": {"auth_required": False, "security_enabled": False, "version": "7.17"},
                "influxdb": {"auth_required": False, "auth_enabled": False, "version": "1.8"},
                "kibana": {"auth_required": False, "auth_enabled": False, "version": "7.17"},
                "splunk": {"auth_required": False, "default_creds": True, "version": "9.0"},
            },
            "hardened-data.corp.internal": {
                "mysql": {"protected": True, "auth_required": True, "auth_prerequisite": "user_password"},
                "postgres": {"protected": True, "auth_required": True, "auth_prerequisite": "client_cert"},
                "redis": {"protected": True, "auth_required": True, "auth_prerequisite": "token_or_api_key"},
                "elasticsearch": {"protected": True, "auth_required": True, "auth_prerequisite": "user_password"},
            },
            "remediated-data.corp.internal": {
                "redis": {"remediated": True, "auth_prerequisite": "token_or_api_key", "version": "7.0 (requirepass enabled)"},
                "postgres": {"remediated": True, "auth_prerequisite": "user_password", "version": "15 (scram-sha-256 enabled)"},
            },
            "filtered-data.corp.internal": {
                "mysql": {"state": "filtered"},
                "redis": {"state": "timeout"},
                "elasticsearch": {"inaccessible": True},
            },
        }
        self.collector = OfflineSyntheticDataCollector(targets=self.mock_targets)

    def test_positive_exposures_all_13_services(self):
        report = assess_data_services(
            targets=["vulnerable-data.corp.internal"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_audit_table",
        )
        self.assertEqual(len(report.services_assessed), 13)
        self.assertEqual(report.summary["exposed"], 13)

        finding_types = {c.finding_type for c in report.privilege_candidates}
        self.assertIn("mysql_no_auth", finding_types)
        self.assertIn("postgres_trust_auth", finding_types)
        self.assertIn("mssql_blank_sa", finding_types)
        self.assertIn("oracle_default_credentials", finding_types)
        self.assertIn("mongodb_no_auth", finding_types)
        self.assertIn("couchdb_admin_party", finding_types)
        self.assertIn("cassandra_default_superuser", finding_types)
        self.assertIn("redis_no_auth", finding_types)
        self.assertIn("redis_config_set", finding_types)
        self.assertIn("memcached_no_auth", finding_types)
        self.assertIn("elasticsearch_open_cluster", finding_types)
        self.assertIn("influxdb_no_auth", finding_types)
        self.assertIn("kibana_no_auth", finding_types)
        self.assertIn("splunk_default_creds", finding_types)

    def test_canary_validation_and_cleanup_receipt_generation(self):
        report = assess_data_services(
            targets=["vulnerable-data.corp.internal"],
            service_types=["redis", "mysql", "mongodb"],
            collector=self.collector,
            canary_artifact="canary_audit_table",
        )
        self.assertEqual(len(report.cleanup_receipts), 3)
        for r in report.cleanup_receipts:
            self.assertTrue(r.verified_clean)
            self.assertEqual(r.action_taken, "verified_removed")
            self.assertTrue(r.receipt_hash)

    def test_query_budget_enforcement(self):
        report = assess_data_services(
            targets=["vulnerable-data.corp.internal"],
            service_types=["mysql", "elasticsearch"],
            collector=self.collector,
            query_budget_rows=5,
        )
        for s in report.services_assessed:
            self.assertEqual(s.query_budget_rows, 5)

    def test_crucial_truth_boundary_inaccessible_not_secure(self):
        report = assess_data_services(
            targets=["filtered-data.corp.internal"],
            service_types=["mysql", "redis", "elasticsearch"],
            collector=self.collector,
        )
        for s in report.services_assessed:
            self.assertEqual(s.exposure_status, DataExposureStatus.INACCESSIBLE.value)
            self.assertEqual(s.auth_prerequisite, DataAuthPrerequisite.UNKNOWN.value)
            self.assertFalse(s.canary_validated)
            self.assertIn("cannot be reported as secure", s.uncertainty_notes[0].lower())

    def test_protected_and_remediated_status(self):
        report = assess_data_services(
            targets=["hardened-data.corp.internal", "remediated-data.corp.internal"],
            service_types=["redis", "postgres"],
            collector=self.collector,
        )
        status_map = {}
        for s in report.services_assessed:
            status_map.setdefault(s.target_host, {})[s.service_type] = s.exposure_status

        self.assertEqual(status_map["hardened-data.corp.internal"]["redis"], DataExposureStatus.PROTECTED.value)
        self.assertEqual(status_map["hardened-data.corp.internal"]["postgres"], DataExposureStatus.PROTECTED.value)
        self.assertEqual(status_map["remediated-data.corp.internal"]["redis"], DataExposureStatus.REMEDIATED.value)
        self.assertEqual(status_map["remediated-data.corp.internal"]["postgres"], DataExposureStatus.REMEDIATED.value)

    def test_direct_assess_helper_methods(self):
        t = "vulnerable-data.corp.internal"
        self.assertEqual(self.collector.assess_mysql(t).service_type, DataServiceType.MYSQL.value)
        self.assertEqual(self.collector.assess_postgres(t).service_type, DataServiceType.POSTGRES.value)
        self.assertEqual(self.collector.assess_mssql(t).service_type, DataServiceType.MSSQL.value)
        self.assertEqual(self.collector.assess_oracle(t).service_type, DataServiceType.ORACLE.value)
        self.assertEqual(self.collector.assess_mongodb(t).service_type, DataServiceType.MONGODB.value)
        self.assertEqual(self.collector.assess_couchdb(t).service_type, DataServiceType.COUCHDB.value)
        self.assertEqual(self.collector.assess_cassandra(t).service_type, DataServiceType.CASSANDRA.value)
        self.assertEqual(self.collector.assess_redis(t).service_type, DataServiceType.REDIS.value)
        self.assertEqual(self.collector.assess_memcached(t).service_type, DataServiceType.MEMCACHED.value)
        self.assertEqual(self.collector.assess_elasticsearch(t).service_type, DataServiceType.ELASTICSEARCH.value)
        self.assertEqual(self.collector.assess_influxdb(t).service_type, DataServiceType.INFLUXDB.value)
        self.assertEqual(self.collector.assess_kibana(t).service_type, DataServiceType.KIBANA.value)
        self.assertEqual(self.collector.assess_splunk(t).service_type, DataServiceType.SPLUNK.value)


class TestStandardSocketDataCollector(unittest.TestCase):
    def test_closed_port_inaccessible_not_secure(self):
        collector = StandardSocketDataCollector()
        assessment = collector.probe_service(
            target_host="127.0.0.1",
            resolved_ip="127.0.0.1",
            service_type="redis",
            port=65432,  # Unused port
            protocol="tcp",
            category="cache_inmemory",
            timeout=0.2,
        )
        self.assertEqual(assessment.exposure_status, DataExposureStatus.INACCESSIBLE.value)
        self.assertEqual(assessment.auth_prerequisite, DataAuthPrerequisite.UNKNOWN.value)
        self.assertIn("cannot be reported as secure", assessment.uncertainty_notes[0].lower())


class TestDataDiscoveryCLI(unittest.TestCase):
    def setUp(self):
        self.mock_targets = {
            "db-srv01.corp.internal": {
                "redis": {"auth_required": False, "requirepass": False, "version": "6.2"},
                "postgres": {"auth_required": False, "auth_method": "trust", "version": "14.2"},
            }
        }

    def test_cli_assess_candidates_cleanup_inspect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.json"
            targets_file.write_text(json.dumps(self.mock_targets), encoding="utf-8")

            report_file = Path(tmpdir) / "report.json"
            candidates_file = Path(tmpdir) / "candidates.json"
            cleanup_file = Path(tmpdir) / "cleanup.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                data_command="assess",
                targets="db-srv01.corp.internal",
                services="redis,postgres",
                vantage="internal",
                scope_ref="scope-db-cli",
                canary_id="canary_audit_table",
                query_budget=5,
                mode="synthetic",
                offline_targets=str(targets_file),
                output=str(report_file),
            )
            self.assertEqual(command_data_discovery(args_assess), 0)
            self.assertTrue(report_file.is_file())

            # 2. Candidates
            args_cand = argparse.Namespace(
                data_command="candidates",
                report=str(report_file),
                output=str(candidates_file),
            )
            self.assertEqual(command_data_discovery(args_cand), 0)
            self.assertTrue(candidates_file.is_file())

            # 3. Cleanup
            args_clean = argparse.Namespace(
                data_command="cleanup",
                report=str(report_file),
                output=str(cleanup_file),
            )
            self.assertEqual(command_data_discovery(args_clean), 0)
            self.assertTrue(cleanup_file.is_file())

            # 4. Inspect text
            args_inspect = argparse.Namespace(
                data_command="inspect",
                report=str(report_file),
                json=False,
            )
            self.assertEqual(command_data_discovery(args_inspect), 0)

            # 5. Inspect json
            args_inspect_json = argparse.Namespace(
                data_command="inspect",
                report=str(report_file),
                json=True,
            )
            self.assertEqual(command_data_discovery(args_inspect_json), 0)


if __name__ == "__main__":
    unittest.main()
