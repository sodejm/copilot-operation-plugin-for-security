# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Tests for network-data-services contributor skill."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    DataAuthPrerequisite,
    DataExposureStatus,
    DataPrivilegeImpact,
    DataServicesReport,
    OfflineSyntheticDataCollector,
    assess_data_services,
)
from cops.discovery.cli import (
    command_data_discovery,
)


class TestNetworkDataServicesSkill(unittest.TestCase):
    def setUp(self):
        self.mock_services = {
            "vulnerable-db.corp.internal": {
                "mysql": {
                    "auth_required": False,
                    "empty_password": True,
                    "bind_address": "0.0.0.0",
                    "version": "8.0.32",
                },
                "postgres": {
                    "auth_method": "trust",
                    "auth_required": False,
                    "superuser": "postgres",
                    "version": "14.2",
                },
                "mssql": {
                    "blank_sa_password": True,
                    "auth_required": False,
                    "xp_cmdshell_enabled": True,
                    "version": "SQL Server 2019",
                },
                "oracle": {
                    "default_credentials": True,
                    "sid": "ORCL",
                    "user": "SYS",
                    "version": "19c",
                },
                "mongodb": {
                    "auth_enabled": False,
                    "auth_required": False,
                    "open_cluster": True,
                    "version": "5.0.6",
                },
                "couchdb": {
                    "admin_party": True,
                    "auth_required": False,
                    "version": "3.2.1",
                },
                "cassandra": {
                    "default_creds": True,
                    "auth_required": False,
                    "version": "4.0.1",
                },
                "redis": {
                    "requirepass_set": False,
                    "config_command_enabled": True,
                    "auth_required": False,
                    "version": "6.2.6",
                },
                "memcached": {
                    "sasl_enabled": False,
                    "auth_required": False,
                    "version": "1.6.9",
                },
                "elasticsearch": {
                    "security_enabled": False,
                    "auth_required": False,
                    "open_cluster": True,
                    "cluster_name": "corp-es-cluster",
                    "version": "7.17.0",
                },
                "influxdb": {
                    "auth_enabled": False,
                    "auth_required": False,
                    "version": "1.8.10",
                },
                "kibana": {
                    "auth_enabled": False,
                    "auth_required": False,
                    "version": "7.17.0",
                },
                "splunk": {
                    "default_creds": True,
                    "auth_required": False,
                    "version": "9.0.1",
                },
            },
            "hardened-db.corp.internal": {
                "mysql": {
                    "protected": True,
                    "auth_required": True,
                    "auth_prerequisite": "user_password",
                    "version": "8.0.35",
                },
                "postgres": {
                    "protected": True,
                    "auth_required": True,
                    "auth_prerequisite": "user_password",
                    "version": "16.1",
                },
                "redis": {
                    "protected": True,
                    "auth_required": True,
                    "auth_prerequisite": "token_or_api_key",
                    "version": "7.2.3",
                },
                "elasticsearch": {
                    "protected": True,
                    "auth_required": True,
                    "auth_prerequisite": "user_password",
                    "version": "8.11.0",
                },
                "mongodb": {
                    "protected": True,
                    "auth_required": True,
                    "auth_prerequisite": "client_cert",
                    "version": "7.0.2",
                },
            },
            "remediated-db.corp.internal": {
                "redis": {
                    "remediated": True,
                    "auth_prerequisite": "user_password",
                    "version": "7.2.3 (requirepass configured)",
                },
                "elasticsearch": {
                    "remediated": True,
                    "auth_prerequisite": "token_or_api_key",
                    "version": "8.11.0 (xpack.security enabled)",
                },
            },
            "filtered-db.corp.internal": {
                "postgres": {"state": "filtered"},
                "redis": {"state": "closed"},
                "elasticsearch": {"inaccessible": True},
            },
        }
        self.collector = OfflineSyntheticDataCollector(targets=self.mock_services)

    def test_positive_exposure_and_data_privilege_candidates(self):
        """Test assessment identifies vulnerabilities and generates DataPrivilegeCandidates."""
        report = assess_data_services(
            targets=["vulnerable-db.corp.internal"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_audit_table",
        )

        self.assertIsInstance(report, DataServicesReport)
        self.assertGreater(len(report.services_assessed), 0)
        self.assertGreater(len(report.privilege_candidates), 0)

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

        # Check privilege impact classifications
        mssql_cand = next(c for c in report.privilege_candidates if c.finding_type == "mssql_blank_sa")
        self.assertEqual(mssql_cand.privilege_impact, DataPrivilegeImpact.REMOTE_CODE_EXECUTION.value)

        redis_cfg = next(c for c in report.privilege_candidates if c.finding_type == "redis_config_set")
        self.assertEqual(redis_cfg.privilege_impact, DataPrivilegeImpact.REMOTE_CODE_EXECUTION.value)

        pg_cand = next(c for c in report.privilege_candidates if c.finding_type == "postgres_trust_auth")
        self.assertEqual(pg_cand.privilege_impact, DataPrivilegeImpact.DATABASE_TAKEOVER.value)

        es_cand = next(c for c in report.privilege_candidates if c.finding_type == "elasticsearch_open_cluster")
        self.assertEqual(es_cand.privilege_impact, DataPrivilegeImpact.DATA_EXFILTRATION.value)

        mem_cand = next(c for c in report.privilege_candidates if c.finding_type == "memcached_no_auth")
        self.assertEqual(mem_cand.privilege_impact, DataPrivilegeImpact.DATA_EXFILTRATION.value)

    def test_canary_validation_and_cleanup_receipts(self):
        """Test canary queries generate verifiable CleanupReceipts."""
        report = assess_data_services(
            targets=["vulnerable-db.corp.internal"],
            service_types=["redis", "postgres"],
            collector=self.collector,
            vantage="internal",
            canary_artifact="canary_audit_table",
        )

        self.assertGreaterEqual(len(report.cleanup_receipts), 2)
        for receipt in report.cleanup_receipts:
            self.assertTrue(receipt.verified_clean)
            self.assertEqual(receipt.action_taken, "verified_removed")
            self.assertIsNotNone(receipt.receipt_hash)

    def test_bounded_query_budget(self):
        """Test query budget is bounded and prevents bulk extraction."""
        report = assess_data_services(
            targets=["vulnerable-db.corp.internal"],
            service_types=["mysql", "elasticsearch"],
            collector=self.collector,
            query_budget_rows=5,
        )
        for s in report.services_assessed:
            self.assertEqual(s.query_budget_rows, 5)

    def test_crucial_truth_boundary_inaccessible_not_secure(self):
        """Test filtered/timed out services are strictly reported as inaccessible, not secure."""
        report = assess_data_services(
            targets=["filtered-db.corp.internal"],
            service_types=["postgres", "redis", "elasticsearch"],
            collector=self.collector,
            vantage="external",
        )

        for s in report.services_assessed:
            self.assertEqual(s.exposure_status, DataExposureStatus.INACCESSIBLE.value)
            self.assertEqual(s.auth_prerequisite, DataAuthPrerequisite.UNKNOWN.value)
            self.assertFalse(s.canary_validated)
            self.assertIn("cannot be reported as secure", s.uncertainty_notes[0].lower())

    def test_protected_and_remediated_services(self):
        """Test protected and remediated services are accurately classified."""
        report = assess_data_services(
            targets=["hardened-db.corp.internal", "remediated-db.corp.internal"],
            service_types=["redis", "elasticsearch"],
            collector=self.collector,
            vantage="internal",
        )

        status_by_target = {}
        for s in report.services_assessed:
            status_by_target.setdefault(s.target_host, {})[s.service_type] = s.exposure_status

        self.assertEqual(status_by_target["hardened-db.corp.internal"]["redis"], DataExposureStatus.PROTECTED.value)
        self.assertEqual(status_by_target["hardened-db.corp.internal"]["elasticsearch"], DataExposureStatus.PROTECTED.value)
        self.assertEqual(status_by_target["remediated-db.corp.internal"]["redis"], DataExposureStatus.REMEDIATED.value)
        self.assertEqual(status_by_target["remediated-db.corp.internal"]["elasticsearch"], DataExposureStatus.REMEDIATED.value)

    def test_cli_subcommands(self):
        """Test CLI assess, candidates, cleanup, and inspect workflows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.json"
            targets_file.write_text(json.dumps(self.mock_services), encoding="utf-8")

            report_file = Path(tmpdir) / "report.json"
            candidates_file = Path(tmpdir) / "candidates.json"
            cleanup_file = Path(tmpdir) / "cleanup.json"

            # 1. Assess
            args_assess = argparse.Namespace(
                data_command="assess",
                targets="vulnerable-db.corp.internal",
                services="redis,postgres,elasticsearch",
                vantage="internal",
                scope_ref="scope-db-001",
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
            cand_data = json.loads(candidates_file.read_text(encoding="utf-8"))
            self.assertGreater(len(cand_data), 0)

            # 3. Cleanup
            args_clean = argparse.Namespace(
                data_command="cleanup",
                report=str(report_file),
                output=str(cleanup_file),
            )
            self.assertEqual(command_data_discovery(args_clean), 0)
            self.assertTrue(cleanup_file.is_file())
            clean_data = json.loads(cleanup_file.read_text(encoding="utf-8"))
            self.assertGreater(len(clean_data), 0)

            # 4. Inspect
            args_inspect = argparse.Namespace(
                data_command="inspect",
                report=str(report_file),
                json=False,
            )
            self.assertEqual(command_data_discovery(args_inspect), 0)


if __name__ == "__main__":
    unittest.main()
