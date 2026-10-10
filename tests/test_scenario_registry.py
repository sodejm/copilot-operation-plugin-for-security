"""Unit tests for the scenario and provenance registry system."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops.cli import (
    command_scenario_info,
    command_scenario_list,
    command_scenario_provenance,
    command_scenario_validate,
)
from cops.scenarios import (
    RegistryError,
    get_provenance_source,
    get_scenario,
    list_provenance_sources,
    list_scenarios,
    load_provenance_registry,
    load_scenario_registry,
    validate_scenario_and_provenance_integrity,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_registry_fixture(target_root: Path) -> tuple[dict, dict]:
    """Copy the two registry documents and their schemas into a temporary root."""
    catalog = target_root / "catalog"
    schemas = catalog / "schemas"
    schemas.mkdir(parents=True)
    for schema_file in (ROOT / "catalog" / "schemas").glob("*.json"):
        (schemas / schema_file.name).write_text(schema_file.read_text(encoding="utf-8"), encoding="utf-8")
    provenance = json.loads((ROOT / "catalog" / "provenance.json").read_text(encoding="utf-8"))
    scenarios = json.loads((ROOT / "catalog" / "scenarios.json").read_text(encoding="utf-8"))
    (catalog / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
    (catalog / "scenarios.json").write_text(json.dumps(scenarios), encoding="utf-8")
    docs = target_root / "docs"
    docs.mkdir()
    (docs / "SUPPORTING_GUIDANCE.md").write_text(
        (ROOT / "docs" / "SUPPORTING_GUIDANCE.md").read_text(encoding="utf-8"), encoding="utf-8"
    )
    return provenance, scenarios


def test_load_registries_success():
    """Verify loading and schema validation of both registries."""
    prov = load_provenance_registry(ROOT)
    assert prov["schema_version"] == "cops.provenance/v1"
    assert len(prov["sources"]) == 13
    assert len(prov["guidance"]) == 7
    assert len(prov["decisions"]) == 1

    scen = load_scenario_registry(ROOT)
    assert scen["schema_version"] == "cops.scenario-registry/v1"
    assert len(scen["scenarios"]) == 37


def test_validate_scenario_and_provenance_integrity():
    """Verify clean pass of cross-registry integrity check."""
    res = validate_scenario_and_provenance_integrity(ROOT)
    assert res["status"] == "valid"
    assert res["sources_count"] == 13
    assert res["inventory_items_count"] == 238
    assert res["scenarios_count"] == 37
    assert res["decision_count"] == 1


def test_list_scenarios_filtering():
    """Verify list_scenarios with family, tactic, and mode filters."""
    by_family = list_scenarios(ROOT, family_id="COPS-E07.02")
    assert len(by_family) == 1
    assert by_family[0]["scenario_id"] == "COPS-E07.02-S01"

    by_tactic = list_scenarios(ROOT, tactic="privilege-escalation")
    assert len(by_tactic) >= 5

    by_mode = list_scenarios(ROOT, coverage_mode="laboratory")
    assert len(by_mode) >= 5


def test_get_scenario_found_and_not_found():
    """Verify retrieval of existing and non-existing scenarios."""
    scen = get_scenario("COPS-E10.07-S01", ROOT)
    assert "Bad Pods" in scen["title"]

    with pytest.raises(RegistryError) as exc_info:
        get_scenario("NON-EXISTENT-SCENARIO", ROOT)
    assert exc_info.value.code == "scenario_not_found"


def test_get_provenance_source_found_and_not_found():
    """Verify retrieval of existing and non-existing provenance sources."""
    src = get_provenance_source("S01", ROOT)
    assert src["name"] == "command-cheatsheet"
    assert src["license"] == "MIT"
    assert src["licensing_review"] == {
        "disposition": "reuse_with_attribution",
        "rationale": "MIT license record: preserve required copyright and license notices when reusing eligible material.",
        "reviewed_license": "MIT",
        "reviewed_source_id": "S01",
    }

    with pytest.raises(RegistryError) as exc_info:
        get_provenance_source("S99", ROOT)
    assert exc_info.value.code == "source_not_found"


def test_list_provenance_sources():
    """Verify list_provenance_sources returns all 13 sources."""
    sources = list_provenance_sources(ROOT)
    assert len(sources) == 13
    ids = [s["source_id"] for s in sources]
    for i in range(1, 14):
        assert f"S{i:02d}" in ids


def test_cli_scenario_commands(capsys):
    """Verify CLI command handlers for scenario subcommands."""
    # List scenarios text and json
    assert command_scenario_list(root=ROOT) == 0
    captured = capsys.readouterr().out
    assert "Registered Scenarios" in captured
    assert "COPS-E01.01-S01" in captured

    assert command_scenario_list(as_json=True, root=ROOT) == 0
    json_out = json.loads(capsys.readouterr().out)
    assert len(json_out) == 37

    # Info text and json
    assert command_scenario_info("COPS-E01.01-S01", root=ROOT) == 0
    info_out = capsys.readouterr().out
    assert "Network Port and Service Discovery" in info_out

    assert command_scenario_info("COPS-E01.01-S01", as_json=True, root=ROOT) == 0
    scen_dict = json.loads(capsys.readouterr().out)
    assert scen_dict["scenario_id"] == "COPS-E01.01-S01"

    # Validate
    assert command_scenario_validate(root=ROOT) == 0
    val_out = capsys.readouterr().out
    assert "Scenario and Provenance Registry valid" in val_out

    # Provenance list and detail
    assert command_scenario_provenance(root=ROOT) == 0
    prov_out = capsys.readouterr().out
    assert "Registered Provenance Sources (13)" in prov_out

    assert command_scenario_provenance(source_id="S07", root=ROOT) == 0
    s07_out = capsys.readouterr().out
    assert "Bishop Fox: Kubernetes Bad Pods" in s07_out


def test_duplicate_item_id_detection(tmp_path):
    """Verify that duplicate item_id across provenance raises RegistryError."""
    prov_data, _ = _write_registry_fixture(tmp_path)
    catalog = tmp_path / "catalog"
    # Duplicate first item
    prov_data["sources"][1]["inventory"].append(dict(prov_data["sources"][0]["inventory"][0]))
    (catalog / "provenance.json").write_text(json.dumps(prov_data))

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(tmp_path)
    assert exc_info.value.code == "duplicate_item_id"


def test_orphan_supporting_guidance_mapping_is_rejected(tmp_path):
    """A non-empty target must still name registered COPS guidance."""
    prov_data, _ = _write_registry_fixture(tmp_path)
    prov_data["sources"][0]["inventory"].append(
        {
            "item_id": "orphan-guidance-test",
            "path_or_section": "test/guidance",
            "resolution": "supporting_guidance",
            "target_id": "COPS-UNKNOWN-GUIDE",
            "notes": "Test-only orphan guidance mapping.",
        }
    )
    (tmp_path / "catalog" / "provenance.json").write_text(json.dumps(prov_data), encoding="utf-8")

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(tmp_path)
    assert exc_info.value.code == "orphan_guidance_mapping"


def test_duplicate_guidance_identifier_is_rejected(tmp_path):
    """Guidance identifiers form a stable, unique mapping namespace."""
    prov_data, _ = _write_registry_fixture(tmp_path)
    prov_data["guidance"].append(dict(prov_data["guidance"][0]))
    (tmp_path / "catalog" / "provenance.json").write_text(json.dumps(prov_data), encoding="utf-8")

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(tmp_path)
    assert exc_info.value.code == "duplicate_guidance_id"


def test_missing_guidance_document_is_rejected(tmp_path):
    """Guidance must resolve to a document inside the registry root."""
    prov_data, _ = _write_registry_fixture(tmp_path)
    prov_data["guidance"][0]["document_path"] = "docs/does-not-exist.md"
    (tmp_path / "catalog" / "provenance.json").write_text(json.dumps(prov_data), encoding="utf-8")

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(tmp_path)
    assert exc_info.value.code == "missing_guidance_document"


def test_guidance_identifier_missing_from_document_is_rejected(tmp_path):
    """The registered guidance ID must be represented in its declared document."""
    prov_data, _ = _write_registry_fixture(tmp_path)
    guidance_id = prov_data["guidance"][0]["guidance_id"]
    document = tmp_path / "docs" / "SUPPORTING_GUIDANCE.md"
    document.write_text(f"This prose mentions {guidance_id}, but has no registry table row.\n", encoding="utf-8")

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(tmp_path)
    assert exc_info.value.code == "unregistered_guidance_document"


def test_registered_applicability_decision_remains_a_valid_resolution(tmp_path):
    """An applicability mapping must name a registered engineering decision."""
    prov_data, _ = _write_registry_fixture(tmp_path)
    item = prov_data["sources"][0]["inventory"][0]
    item["resolution"] = "applicability_decision"
    item["target_id"] = "COPS-DECISION-REFERENCE-ONLY"
    (tmp_path / "catalog" / "provenance.json").write_text(json.dumps(prov_data), encoding="utf-8")

    assert validate_scenario_and_provenance_integrity(tmp_path)["status"] == "valid"


def test_orphan_applicability_decision_is_rejected(tmp_path):
    prov_data, _ = _write_registry_fixture(tmp_path)
    root = tmp_path
    provenance_path = root / "catalog" / "provenance.json"
    prov_data = json.loads(provenance_path.read_text(encoding="utf-8"))
    item = prov_data["sources"][0]["inventory"][0]
    item["resolution"] = "applicability_decision"
    item["target_id"] = "COPS-DECISION-UNKNOWN"
    provenance_path.write_text(json.dumps(prov_data), encoding="utf-8")

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(root)

    assert exc_info.value.code == "orphan_decision_mapping"


def test_duplicate_decision_identifier_is_rejected(tmp_path):
    prov_data, _ = _write_registry_fixture(tmp_path)
    root = tmp_path
    provenance_path = root / "catalog" / "provenance.json"
    prov_data = json.loads(provenance_path.read_text(encoding="utf-8"))
    prov_data["decisions"].append(dict(prov_data["decisions"][0]))
    provenance_path.write_text(json.dumps(prov_data), encoding="utf-8")

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(root)

    assert exc_info.value.code == "duplicate_decision_id"


def test_missing_registry_files(tmp_path):
    """Verify handling when registry files are missing."""
    with pytest.raises(RegistryError) as exc_info:
        load_provenance_registry(tmp_path)
    assert exc_info.value.code == "missing_registry"

    with pytest.raises(RegistryError) as exc_info:
        load_scenario_registry(tmp_path)
    assert exc_info.value.code == "missing_registry"
