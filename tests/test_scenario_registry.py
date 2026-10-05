"""Unit tests for the scenario and provenance registry system."""

from __future__ import annotations

import io
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


def test_load_registries_success():
    """Verify loading and schema validation of both registries."""
    prov = load_provenance_registry(ROOT)
    assert prov["schema_version"] == "cops.provenance/v1"
    assert len(prov["sources"]) == 13

    scen = load_scenario_registry(ROOT)
    assert scen["schema_version"] == "cops.scenario-registry/v1"
    assert len(scen["scenarios"]) == 36


def test_validate_scenario_and_provenance_integrity():
    """Verify clean pass of cross-registry integrity check."""
    res = validate_scenario_and_provenance_integrity(ROOT)
    assert res["status"] == "valid"
    assert res["sources_count"] == 13
    assert res["inventory_items_count"] == 238
    assert res["scenarios_count"] == 36


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
    assert len(json_out) == 36

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
    catalog = tmp_path / "catalog"
    catalog.mkdir(parents=True)
    schemas = catalog / "schemas"
    schemas.mkdir(parents=True)
    for sf in (ROOT / "catalog" / "schemas").glob("*.json"):
        (schemas / sf.name).write_text(sf.read_text(encoding="utf-8"), encoding="utf-8")
    (catalog / "scenarios.json").write_text((ROOT / "catalog" / "scenarios.json").read_text(encoding="utf-8"))

    prov_data = json.loads((ROOT / "catalog" / "provenance.json").read_text(encoding="utf-8"))
    # Duplicate first item
    prov_data["sources"][1]["inventory"].append(dict(prov_data["sources"][0]["inventory"][0]))
    (catalog / "provenance.json").write_text(json.dumps(prov_data))

    with pytest.raises(RegistryError) as exc_info:
        validate_scenario_and_provenance_integrity(tmp_path)
    assert exc_info.value.code == "duplicate_item_id"


def test_missing_registry_files(tmp_path):
    """Verify handling when registry files are missing."""
    with pytest.raises(RegistryError) as exc_info:
        load_provenance_registry(tmp_path)
    assert exc_info.value.code == "missing_registry"

    with pytest.raises(RegistryError) as exc_info:
        load_scenario_registry(tmp_path)
    assert exc_info.value.code == "missing_registry"
