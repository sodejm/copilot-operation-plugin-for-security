"""Integrity checks for the pinned historical protocol-topic reconciliation."""

from __future__ import annotations

import ast
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from cops.discovery import (
    DataServiceType,
    DeveloperServiceType,
    InfraServiceType,
    LegacyServiceType,
    MessagingServiceType,
    RemoteServiceType,
)

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "catalog" / "protocol-topics.json"
COLLECTOR_TYPES = {
    "data": DataServiceType,
    "developer": DeveloperServiceType,
    "infra": InfraServiceType,
    "legacy": LegacyServiceType,
    "messaging": MessagingServiceType,
    "remote": RemoteServiceType,
}


class TestProtocolTopicReconciliation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_pinned_inventory_is_complete_and_stable(self) -> None:
        source = self.manifest["source"]
        self.assertEqual(source["repository"], "https://github.com/gunyakit/command-cheatsheet")
        self.assertEqual(source["revision"], "4c118399602212f205c91e8f01e418e226fa320c")
        self.assertEqual(source["topic_directory"], "1.Scanning/IT-Ports")
        paths = [topic["source_path"] for topic in self.manifest["topics"]]
        self.assertEqual(len(paths), 70)
        self.assertEqual(paths, sorted(set(paths)))
        self.assertTrue(all(path.startswith("1.Scanning/IT-Ports/") and path.endswith(".md") for path in paths))
        digest = hashlib.sha256(("\n".join(paths) + "\n").encode("utf-8")).hexdigest()
        self.assertEqual(digest, source["sorted_paths_sha256"])
        self.assertEqual(digest, "cec7246d3a2117680b3f550d40a0ac659a12b24597262f275ca82c5c7bf86c9e")

    def test_coverage_and_applicability_are_separate_from_tool_maintenance(self) -> None:
        counts = Counter(topic["coverage_status"] for topic in self.manifest["topics"])
        self.assertEqual(counts, {"offline_model": 62, "environment_limit": 8})
        for topic in self.manifest["topics"]:
            with self.subTest(topic=topic["source_path"]):
                self.assertEqual(topic["technique_applicability"], "conditional_requires_lab")
                self.assertEqual(topic["source_tool_maintenance"], "not_assessed")
                if topic["coverage_status"] == "environment_limit":
                    self.assertTrue(topic["limitation"])
                    self.assertNotIn("evidence_test", topic)
                elif "limitation" in topic:
                    self.assertTrue(topic["limitation"])

    def test_offline_mappings_point_to_service_types_and_existing_tests(self) -> None:
        for topic in self.manifest["topics"]:
            if topic["coverage_status"] != "offline_model":
                continue
            with self.subTest(topic=topic["source_path"]):
                enum_type = COLLECTOR_TYPES[topic["collector"]]
                self.assertIn(topic["service_type"], {item.value for item in enum_type})
                file_name, class_name, method_name = topic["evidence_test"].split("::")
                test_path = (ROOT / file_name).resolve()
                self.assertTrue(test_path.is_relative_to(ROOT / "tests"))
                tree = ast.parse(test_path.read_text(encoding="utf-8"))
                classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
                self.assertEqual(len(classes), 1)
                self.assertTrue(
                    any(isinstance(node, ast.FunctionDef) and node.name == method_name for node in classes[0].body)
                )


if __name__ == "__main__":
    unittest.main()
