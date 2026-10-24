"""Executable traceability checks for the native Windows E01.1 collector."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "plugins" / "offensive-security" / "host-assessment-workbench"
SOURCE_MAP = PACKAGE / "docs" / "windows-native-source-map.json"
COLLECTOR = PACKAGE / "scripts" / "collect-windows.ps1"
PROVENANCE = ROOT / "catalog" / "provenance.json"

EXPECTED_PROBES = {
    "windows_build_token_context",
    "token_privileges",
    "always_install_elevated",
    "autologon_default_password_presence",
    "unattend_file_presence",
    "unquoted_service_path",
    "service_dacl",
    "scheduled_task_acl",
    "path_directory_acl",
}
EXPECTED_SOURCES = {
    "s01-120",
    "s01-121",
    "s01-122",
    "s01-123",
    "s01-124",
    "s01-125",
    "s01-126",
    "s01-127",
    "s01-128",
    "s01-129",
    "s02-016",
}
EXPECTED_EXCLUSIONS = {"s01-123", "s01-126"}


def test_e01_1_source_map_matches_collector_and_pinned_provenance() -> None:
    source_map = json.loads(SOURCE_MAP.read_text())
    provenance = json.loads(PROVENANCE.read_text())
    collector = COLLECTOR.read_text()

    assert source_map["schema_version"] == "windows-native-source-map-1.0"
    assert source_map["target"] == "E01.1"
    assert source_map["status"] == "partial"
    assert source_map["collector"] == "scripts/collect-windows.ps1"

    mapped_ids = {entry["probe_id"] for entry in source_map["mapped_probes"]}
    unmapped_ids = {entry["probe_id"] for entry in source_map["unmapped_probes"]}
    assert mapped_ids.isdisjoint(unmapped_ids)
    assert mapped_ids | unmapped_ids == EXPECTED_PROBES
    for probe_id in EXPECTED_PROBES:
        assert collector.count(f"# E01.1 section: {probe_id}") == 1

    inventory = {item["item_id"]: item for source in provenance["sources"] for item in source.get("inventory", [])}
    mapped_source_ids: set[str] = set()
    for entry in source_map["mapped_probes"]:
        assert entry["relationship"] in {"direct", "supporting"}
        assert entry["sources"]
        for reference in entry["sources"]:
            item_id = reference["item_id"]
            mapped_source_ids.add(item_id)
            assert item_id in inventory
            assert reference["path_or_section"] == inventory[item_id]["path_or_section"]

    for entry in source_map["unmapped_probes"]:
        assert entry["reason"].strip()

    excluded_ids = {entry["item_id"] for entry in source_map["excluded_sources"]}
    assert excluded_ids == EXPECTED_EXCLUSIONS
    for entry in source_map["excluded_sources"]:
        item_id = entry["item_id"]
        assert item_id in inventory
        assert entry["path_or_section"] == inventory[item_id]["path_or_section"]
        assert entry["reason"].strip()

    assert mapped_source_ids.isdisjoint(excluded_ids)
    assert mapped_source_ids | excluded_ids == EXPECTED_SOURCES
