"""Unit and contract tests for the scenario laboratory harness runtime."""

from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cops.execution.scope_guard import ScopeDefinition, ScopeGuard
from cops.execution.store import ApprovalStore
from cops.laboratory import (
    CanaryVerificationError,
    IsolationVerificationError,
    LaboratoryGateError,
    LaboratoryHarness,
    PrerequisiteMismatchError,
    ResetError,
    make_inert_action_plan,
    make_inert_container_environment,
    make_inert_execution_authorization,
    make_inert_vm_environment,
    parse_version_tuple,
    verify_platform_matrix,
    verify_tool_prerequisites,
    version_ge,
)
from cops.laboratory.cli import command_laboratory
from tests.auth_testkit import (
    authorization_secret_environment,
    make_test_authorization_context,
    worker_inventory_for_plan,
    write_test_authorization_trust_store,
    write_test_worker_inventory,
)

ROOT = Path(__file__).resolve().parents[1]


class TestLaboratoryHarness(unittest.TestCase):
    """Test suite for laboratory environment management, verification, reset, and execution gates."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cops-lab-test-")
        self.temp_path = Path(self.temp_dir.name)
        self.store = ApprovalStore(self.temp_path / "approvals.sqlite3")
        self.harness = LaboratoryHarness(store=self.store)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _authorization_context(plan):
        signer, trust_store, engagement = make_test_authorization_context(plan)
        authorization = make_inert_execution_authorization(
            plan,
            signer=signer,
            engagement=engagement,
        )
        return authorization, trust_store, engagement

    def test_version_parsing_and_comparison(self) -> None:
        """Verify semantic and dotted version comparison logic."""
        self.assertEqual(parse_version_tuple("1.28.0"), (1, 28, 0))
        self.assertEqual(parse_version_tuple("v0.6.0-rc1"), (0, 6, 0))
        self.assertEqual(parse_version_tuple("7.80"), (7, 80, 0))
        self.assertTrue(version_ge("1.28.0", "1.24.0"))
        self.assertTrue(version_ge("1.24.0", "1.24.0"))
        self.assertFalse(version_ge("1.23.9", "1.24.0"))

    def test_register_valid_container_and_vm_environments(self) -> None:
        """Verify registration of compliant container and VM laboratory environment contracts."""
        c_env = make_inert_container_environment()
        reg_c = self.harness.register_environment(c_env)
        self.assertEqual(reg_c.environment_id, "env-lab-container-01")
        self.assertEqual(reg_c.environment_type, "container")
        self.assertEqual(reg_c.status, "registered")

        vm_env = make_inert_vm_environment()
        reg_vm = self.harness.register_environment(vm_env)
        self.assertEqual(reg_vm.environment_id, "env-lab-vm-01")
        self.assertEqual(reg_vm.environment_type, "vm")
        self.assertEqual(reg_vm.status, "registered")

    def test_platform_matrix_rejection(self) -> None:
        """Verify rejection of platforms with unsupported OS, distribution, or runtime."""
        # Unsupported OS
        with self.assertRaises(PrerequisiteMismatchError) as ctx:
            verify_platform_matrix({"os": "solaris", "distribution": "solaris", "architecture": "x86_64", "runtime": "container"})
        self.assertIn("Unsupported operating system 'solaris'", str(ctx.exception))

        # Unsupported distribution
        with self.assertRaises(PrerequisiteMismatchError) as ctx:
            verify_platform_matrix({"os": "linux", "distribution": "archlinux", "architecture": "x86_64", "runtime": "container"})
        self.assertIn("Unsupported distribution 'archlinux'", str(ctx.exception))

        # Unsupported runtime
        with self.assertRaises(PrerequisiteMismatchError) as ctx:
            verify_platform_matrix({"os": "linux", "distribution": "ubuntu", "architecture": "x86_64", "runtime": "baremetal"})
        self.assertIn("Unsupported laboratory runtime 'baremetal'", str(ctx.exception))

    def test_tool_prerequisites_rejection(self) -> None:
        """Verify rejection when tools are missing or versions fall below tested minimums."""
        # Tool version mismatch
        bad_tools = {"kubectl": "1.20.0"}  # requires >=1.24.0
        with self.assertRaises(PrerequisiteMismatchError) as ctx:
            verify_tool_prerequisites(bad_tools)
        self.assertIn("below tested minimum '1.24.0'", str(ctx.exception))

        # Missing required tool
        with self.assertRaises(PrerequisiteMismatchError) as ctx:
            verify_tool_prerequisites({"kubectl": "1.28.0"}, required_tools=["kube-bench"])
        self.assertIn("Required tool 'kube-bench' is missing", str(ctx.exception))

    def test_environment_verification_positive(self) -> None:
        """Verify successful verification of compliant environment with isolation and canary."""
        c_env = make_inert_container_environment()
        self.assertEqual(c_env.status, "registered")
        verified_env = self.harness.verify_environment(c_env, required_tools=["kubectl", "kube-bench"])
        self.assertEqual(verified_env.status, "verified")
        self.assertEqual(verified_env.isolation["verification_status"], "verified")
        self.assertTrue(verified_env.canary["verified"])

    def test_environment_verification_rejects_missing_isolation(self) -> None:
        """Verify rejection when network isolation or egress restriction is disabled."""
        c_env = make_inert_container_environment()
        c_env.isolation["network_isolated"] = False
        with self.assertRaises(IsolationVerificationError):
            self.harness.verify_environment(c_env)
        self.assertEqual(c_env.status, "failed")

        c_env2 = make_inert_container_environment()
        c_env2.isolation["egress_restricted"] = False
        with self.assertRaises(IsolationVerificationError):
            self.harness.verify_environment(c_env2)
        self.assertEqual(c_env2.status, "failed")

    def test_environment_verification_rejects_missing_canary(self) -> None:
        """Verify rejection when canary token or location is missing."""
        c_env = make_inert_container_environment()
        c_env.canary["canary_token"] = ""
        with self.assertRaises(CanaryVerificationError):
            self.harness.verify_environment(c_env)
        self.assertEqual(c_env.status, "failed")

    def test_reproducible_reset(self) -> None:
        """Verify reproducible reset restores verified state and updates timestamp."""
        c_env = make_inert_container_environment()
        verified_env = self.harness.verify_environment(c_env)
        self.assertEqual(verified_env.status, "verified")

        reset_env = self.harness.reproducible_reset(verified_env, mock_reset=True)
        self.assertEqual(reset_env.status, "verified")
        self.assertIsNotNone(reset_env.reset_configuration["last_reset_timestamp"])
        self.assertTrue(reset_env.canary["verified"])

    def test_reproducible_reset_rejects_non_reproducible(self) -> None:
        """Verify rejection if reset configuration is not marked reproducible."""
        c_env = make_inert_container_environment()
        c_env.reset_configuration["reproducible"] = False
        with self.assertRaises(ResetError):
            self.harness.reproducible_reset(c_env)

    def test_execution_gate_rejects_unverified_environment(self) -> None:
        """Execution gate must reject environment that has not been verified."""
        c_env = make_inert_container_environment()  # status: registered
        plan = make_inert_action_plan()
        auth, trust_store, engagement = self._authorization_context(plan)
        worker_inventory = worker_inventory_for_plan(plan, worker_identity=c_env.owner)

        with self.assertRaises(LaboratoryGateError) as ctx:
            self.harness.execute_case(
                c_env,
                plan,
                auth,
                case_type="positive",
                trust_store=trust_store,
                engagement=engagement,
                worker_inventory=worker_inventory,
            )
        self.assertIn("must be 'verified' or 'active' before execution", str(ctx.exception))

    def test_positive_case_execution_and_cleanup(self) -> None:
        """Verify end-to-end positive case execution, canary verification, and cleanup receipt."""
        c_env = make_inert_container_environment()
        self.harness.verify_environment(c_env)
        plan = make_inert_action_plan()
        auth, trust_store, engagement = self._authorization_context(plan)
        worker_inventory = worker_inventory_for_plan(plan, worker_identity=c_env.owner)

        result = self.harness.execute_case(
            environment=c_env,
            action_plan=plan,
            authorization=auth,
            case_type="positive",
            trust_store=trust_store,
            engagement=engagement,
            worker_inventory=worker_inventory,
        )
        self.assertEqual(result.case_type, "positive")
        self.assertEqual(result.status, "success")
        self.assertTrue(result.canary_verified)
        self.assertGreater(len(result.evidence_records), 0)
        self.assertIsNotNone(result.cleanup_receipt)
        self.assertEqual(result.cleanup_receipt.status, "completed")
        self.assertEqual(result.run_result.status, "success")

    def test_remediated_case_execution(self) -> None:
        """Verify remediated case execution confirming security control mitigated technique."""
        c_env = make_inert_container_environment()
        self.harness.verify_environment(c_env)
        plan = make_inert_action_plan()
        auth, trust_store, engagement = self._authorization_context(plan)
        worker_inventory = worker_inventory_for_plan(plan, worker_identity=c_env.owner)

        result = self.harness.execute_case(
            environment=c_env,
            action_plan=plan,
            authorization=auth,
            case_type="remediated",
            trust_store=trust_store,
            engagement=engagement,
            worker_inventory=worker_inventory,
        )
        self.assertEqual(result.case_type, "remediated")
        self.assertEqual(result.status, "remediated")
        self.assertIn("mitigated", result.run_result.status_details["reason"].lower())
        self.assertIsNotNone(result.cleanup_receipt)
        self.assertEqual(result.cleanup_receipt.status, "completed")

    def test_negative_case_controlled_rejection(self) -> None:
        """Verify negative test case correctly produces a failed RunResult without false claims."""
        c_env = make_inert_container_environment()
        self.harness.verify_environment(c_env)
        plan = make_inert_action_plan()
        auth, trust_store, engagement = self._authorization_context(plan)
        worker_inventory = worker_inventory_for_plan(plan, worker_identity=c_env.owner)

        result = self.harness.execute_case(
            environment=c_env,
            action_plan=plan,
            authorization=auth,
            case_type="negative",
            trust_store=trust_store,
            engagement=engagement,
            worker_inventory=worker_inventory,
        )
        self.assertEqual(result.case_type, "negative")
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.run_result.status, "failed")

    def test_egress_and_scope_guard_enforcement(self) -> None:
        """Verify scope guard prevents execution against unauthorized targets or metadata IMDS."""
        c_env = make_inert_container_environment()
        self.harness.verify_environment(c_env)

        scope_def = ScopeDefinition()
        from cops.execution.scope_guard import parse_ip_or_network
        scope_def.included_networks.append(parse_ip_or_network("10.200.0.0/24"))
        scope_def.excluded_networks.append(parse_ip_or_network("169.254.169.254/32"))
        guard = ScopeGuard(scope_def)

        # Unauthorized target
        bad_plan = make_inert_action_plan(target="192.168.1.50")
        bad_auth, trust_store, engagement = self._authorization_context(bad_plan)
        worker_inventory = worker_inventory_for_plan(bad_plan, worker_identity=c_env.owner)

        with self.assertRaises(LaboratoryGateError) as ctx:
            self.harness.execute_case(
                c_env,
                bad_plan,
                bad_auth,
                case_type="positive",
                scope_guard=guard,
                trust_store=trust_store,
                engagement=engagement,
                worker_inventory=worker_inventory,
            )
        self.assertIn("scope guard violation", str(ctx.exception))

    def test_cli_laboratory_commands(self) -> None:
        """Verify CLI cops lab <register|verify|reset|matrix|run> subcommands."""
        c_env = make_inert_container_environment()
        env_json = json.dumps(c_env.to_dict())

        # 1. Matrix command
        matrix_args = argparse.Namespace(lab_command="matrix", output=None)
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = command_laboratory(matrix_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        self.assertIn("supported_os", out)

        # 2. Register command
        reg_args = argparse.Namespace(lab_command="register", environment=env_json, output=None)
        sys.stdout = io.StringIO()
        try:
            rc = command_laboratory(reg_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        reg_doc = json.loads(out)
        self.assertEqual(reg_doc["status"], "registered")

        # 3. Verify command
        ver_args = argparse.Namespace(
            lab_command="verify",
            environment=out,
            tools="kubectl,nmap",
            mock=True,
            output=None,
        )
        sys.stdout = io.StringIO()
        try:
            rc = command_laboratory(ver_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        ver_doc = json.loads(out)
        self.assertEqual(ver_doc["status"], "verified")

        # 4. Reset command
        res_args = argparse.Namespace(lab_command="reset", environment=out, mock=True, output=None)
        sys.stdout = io.StringIO()
        try:
            rc = command_laboratory(res_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        res_doc = json.loads(out)
        self.assertEqual(res_doc["status"], "verified")

        # 5. Run command
        plan = make_inert_action_plan()
        auth, _, engagement = self._authorization_context(plan)
        trust_path = write_test_authorization_trust_store(self.temp_path / "authorization-trust.json")
        worker_inventory_path = write_test_worker_inventory(
            self.temp_path / "worker-inventory.json",
            worker_inventory_for_plan(plan, worker_identity=c_env.owner),
        )
        engagement_path = self.temp_path / "engagement.json"
        engagement_path.write_text(json.dumps(engagement.to_dict()), encoding="utf-8")
        run_args = argparse.Namespace(
            lab_command="run",
            environment=json.dumps(ver_doc),
            plan=json.dumps(plan.to_dict()),
            authorization=json.dumps(auth.to_dict()),
            case_type="positive",
            store=str(self.temp_path / "approvals.sqlite3"),
            allowed_cidr=None,
            authorization_trust_store=str(trust_path),
            engagement=str(engagement_path),
            worker_inventory=str(worker_inventory_path),
            worker_id=None,
            expectation=None,
            case_id=None,
            output=None,
        )
        sys.stdout = io.StringIO()
        try:
            with patch.dict("os.environ", authorization_secret_environment()):
                rc = command_laboratory(run_args, root=ROOT)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        run_doc = json.loads(out)
        self.assertEqual(run_doc["case_type"], "positive")
        self.assertEqual(run_doc["status"], "success")
        self.assertTrue(run_doc["canary_verified"])


if __name__ == "__main__":
    unittest.main()
