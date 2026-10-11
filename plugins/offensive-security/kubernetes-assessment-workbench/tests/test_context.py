"""Offline Kubernetes context gate regression tests."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from kubernetes_assessment_context import GateError, assess, load_record  # noqa: E402


class ContextTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = PACKAGE / "fixtures/synthetic/context.json"
        self.record = json.loads(fixture.read_text(encoding="utf-8"))

    def test_synthetic_reconciliation_is_deterministic_and_never_authorizes_execution(self) -> None:
        first = assess(self.record)
        self.assertEqual(first, assess(self.record))
        self.assertEqual(first["cluster_identity"]["status"], "matched_sanitized_export")
        self.assertEqual(first["namespaces"], [{"namespace": "payments", "status": "accessible"}])
        self.assertFalse(first["live_execution_ready"])
        self.assertEqual(first["network_requests"], 0)

    def test_selected_context_must_match_current_and_inventory(self) -> None:
        self.record["observation"]["current_context"]["cluster"] = "switched"
        self._reject("context_mismatch")

    def test_duplicate_display_name_is_ambiguous(self) -> None:
        self.record["observation"]["contexts"].append({"name": "lab-east", "cluster": "other", "user": "reader"})
        self._reject("duplicate_context_name")

    def test_identity_anchor_mismatch_rejected(self) -> None:
        self.record["observation"]["identity_anchor"]["uid"] = "another-uid"
        self._reject("identity_anchor_mismatch")

    def test_missing_anchor_and_namespace_denial_visible(self) -> None:
        del self.record["observation"]["identity_anchor"]
        self.record["observation"]["namespace_access"] = [{"namespace": "payments", "status": "denied"}]
        report = assess(self.record)
        self.assertIn("stable_identity_unresolved", report["blockers"])
        self.assertIn("namespace_access_incomplete", report["blockers"])
        self.assertEqual(report["namespaces"][0]["status"], "denied")

    def test_unknown_scope_never_expands(self) -> None:
        self.record["observation"]["namespace_access"].append({"namespace": "secret", "status": "accessible"})
        self.assertEqual(len(assess(self.record)["namespaces"]), 1)
        self.record["plan"]["namespaces"] = ["*"]
        self._reject("wildcard_namespace")

    def test_requires_explicit_plan_and_known_surface(self) -> None:
        del self.record["plan"]["context"]
        self._reject("invalid_context")
        self.setUp()
        self.record["plan"]["surfaces"] = ["arbitrary_command"]
        self._reject("unknown_surface")

    def test_rejects_live_mode_and_credential_fields(self) -> None:
        self.record["mode"] = "live"
        self._reject("unsupported_mode")
        self.setUp()
        self.record["observation"]["token"] = "placeholder"
        self._reject("credential_field")

    def test_missing_facts_are_unknown(self) -> None:
        self.record["observation"]["cluster_facts"] = {}
        report = assess(self.record)
        self.assertEqual(report["cluster_facts"]["server_version"], "unknown")
        self.assertIn("node_access_unavailable", report["limitations"])

    def test_access_facts_cannot_hide_limitations_in_unrecognized_values(self) -> None:
        self.record["observation"]["cluster_facts"]["control_plane_access"] = "fully_secure"
        self._reject("invalid_cluster_facts")
        self.setUp()
        self.record["observation"]["cluster_facts"]["node_access"] = "denied"
        self.assertIn("node_access_unavailable", assess(self.record)["limitations"])

    def test_rejects_duplicate_keys_and_oversized_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "record.json"
            path.write_text('{"mode":"offline","mode":"live"}', encoding="utf-8")
            with self.assertRaisesRegex(GateError, "duplicate_json_key"):
                load_record(path)
            path.write_bytes(b" " * (131_072 + 1))
            with self.assertRaisesRegex(GateError, "input_too_large"):
                load_record(path)

    def test_rejects_invalid_status_type_and_nonfinite_json(self) -> None:
        self.record["observation"]["namespace_access"][0]["status"] = ["accessible"]
        self._reject("invalid_namespace_access")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "record.json"
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(GateError, "invalid_json"):
                load_record(path)

    @unittest.skipUnless(hasattr(sys, "get_int_max_str_digits"), "Python has no integer digit limit")
    def test_large_json_integer_has_stable_error(self) -> None:
        limit = sys.get_int_max_str_digits()
        if limit == 0:
            self.skipTest("Python integer digit limit is disabled")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "record.json"
            path.write_text("9" * (limit + 1), encoding="utf-8")
            with self.assertRaisesRegex(GateError, "invalid_json"):
                load_record(path)

    def _reject(self, code: str) -> None:
        with self.assertRaisesRegex(GateError, code):
            assess(copy.deepcopy(self.record))


if __name__ == "__main__":
    unittest.main()
