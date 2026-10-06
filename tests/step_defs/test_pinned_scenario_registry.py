"""Acceptance test step definitions for the pinned scenario and provenance registry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.scenarios import (
    RegistryError,
    get_provenance_source,
    get_scenario,
    list_scenarios,
    load_provenance_registry,
    load_scenario_registry,
    validate_scenario_and_provenance_integrity,
)

ROOT = Path(__file__).resolve().parents[2]

scenarios("../../specs/features/pinned_scenario_registry.feature")


@pytest.fixture
def registry_context():
    return {}


@given("the canonical scenario registry and provenance registry files")
def canonical_registry_files(registry_context):
    registry_context["root"] = ROOT


@when("the registry integrity validator is executed")
def execute_integrity_validator(registry_context):
    try:
        registry_context["result"] = validate_scenario_and_provenance_integrity(registry_context["root"])
        registry_context["error"] = None
    except RegistryError as err:
        registry_context["result"] = None
        registry_context["error"] = err


@then(parsers.parse('the validation status is "{expected_status}"'))
def verify_validation_status(registry_context, expected_status):
    assert registry_context["result"]["status"] == expected_status


@then(parsers.parse("exactly {count:d} provenance sources are loaded"))
def verify_source_count(registry_context, count):
    assert registry_context["result"]["sources_count"] == count


@then(parsers.parse("at least {count:d} inventoried items are verified"))
def verify_item_count(registry_context, count):
    assert registry_context["result"]["inventory_items_count"] >= count


@then(parsers.parse("at least {count:d} canonical scenarios are registered"))
def verify_scenario_count(registry_context, count):
    assert registry_context["result"]["scenarios_count"] >= count


@given("the scenario registry is loaded")
def load_scenarios_into_context(registry_context):
    registry_context["root"] = ROOT
    registry_context["scenarios"] = load_scenario_registry(ROOT)


@when(parsers.parse('querying scenarios with MITRE tactic "{tactic}"'))
def query_by_tactic(registry_context, tactic):
    registry_context["query_results"] = list_scenarios(ROOT, tactic=tactic)


@then(parsers.parse("at least {min_count:d} matching scenarios are returned"))
def verify_matching_count(registry_context, min_count):
    assert len(registry_context["query_results"]) >= min_count


@when(parsers.parse('querying scenarios with family "{family}"'))
def query_by_family(registry_context, family):
    registry_context["family_results"] = list_scenarios(ROOT, family_id=family)


@then(parsers.parse('the scenario "{scenario_id}" is present in the results'))
def verify_scenario_present(registry_context, scenario_id):
    ids = [s["scenario_id"] for s in registry_context["family_results"]]
    assert scenario_id in ids


@given(parsers.parse('the scenario "{scenario_id}"'))
def set_scenario_id(registry_context, scenario_id):
    registry_context["scenario_id"] = scenario_id


@when("its details are retrieved from the registry")
def retrieve_scenario_details(registry_context):
    registry_context["scenario"] = get_scenario(registry_context["scenario_id"], ROOT)


@then(parsers.parse('its title is "{title}"'))
def verify_scenario_title(registry_context, title):
    assert registry_context["scenario"]["title"] == title


@then(parsers.parse('its safety profile declares impact "{impact}"'))
def verify_safety_impact(registry_context, impact):
    assert registry_context["scenario"]["safety_profile"]["impact"] == impact


@then(parsers.parse('its provenance references source "{source_id}" with license "{license}"'))
def verify_scenario_provenance(registry_context, source_id, license):
    prov = registry_context["scenario"]["provenance"]
    assert prov["source_id"] == source_id
    assert prov["license"] == license


@given("the provenance registry is loaded")
def load_provenance_into_context(registry_context):
    registry_context["root"] = ROOT
    registry_context["provenance"] = load_provenance_registry(ROOT)


@when(parsers.parse('inspecting the source "{source_id}"'))
def inspect_source(registry_context, source_id):
    registry_context["source"] = get_provenance_source(source_id, ROOT)


@then(parsers.parse('its name is "{name}"'))
def verify_source_name(registry_context, name):
    assert registry_context["source"]["name"] == name


@then(parsers.parse('its category is "{category}"'))
def verify_source_category(registry_context, category):
    assert registry_context["source"]["category"] == category


@then(parsers.parse("it contains {count:d} inventoried items"))
def verify_source_item_count(registry_context, count):
    assert len(registry_context["source"]["inventory"]) == count


@then("all inventory items resolve to valid scenario targets")
def verify_all_items_resolve(registry_context):
    scenarios_data = load_scenario_registry(ROOT)
    known_sids = {s["scenario_id"] for s in scenarios_data["scenarios"]}
    for item in registry_context["source"]["inventory"]:
        if item["resolution"] == "scenario":
            assert item["target_id"] in known_sids


@given("a scenario registry containing a duplicate scenario identifier")
def setup_duplicate_scenario(tmp_path, registry_context):
    catalog = tmp_path / "catalog"
    catalog.mkdir(parents=True)
    schemas = catalog / "schemas"
    schemas.mkdir(parents=True)

    # Copy real schemas and provenance
    real_schemas = ROOT / "catalog" / "schemas"
    for sfile in real_schemas.glob("*.json"):
        (schemas / sfile.name).write_text(sfile.read_text(encoding="utf-8"), encoding="utf-8")
    (catalog / "provenance.json").write_text(
        (ROOT / "catalog" / "provenance.json").read_text(encoding="utf-8"), encoding="utf-8"
    )

    # Create scenarios with a duplicate scenario_id
    scen_data = json.loads((ROOT / "catalog" / "scenarios.json").read_text(encoding="utf-8"))
    dup = dict(scen_data["scenarios"][0])
    scen_data["scenarios"].append(dup)
    (catalog / "scenarios.json").write_text(json.dumps(scen_data), encoding="utf-8")
    registry_context["target_dir"] = tmp_path


@when("scenario integrity validation is executed")
def run_validation_on_mock(registry_context):
    target = registry_context.get("target_dir", ROOT)
    try:
        registry_context["result"] = validate_scenario_and_provenance_integrity(target)
        registry_context["error"] = None
    except RegistryError as err:
        registry_context["result"] = None
        registry_context["error"] = err


@then(parsers.parse('the validation fails with error code "{code}"'))
def verify_validation_error_code(registry_context, code):
    assert registry_context["error"] is not None
    assert registry_context["error"].code == code


@given("a provenance registry containing an orphan scenario mapping")
def setup_orphan_mapping(tmp_path_factory, registry_context):
    p = tmp_path_factory.mktemp("orphan_dir")
    catalog = p / "catalog"
    catalog.mkdir(parents=True)
    schemas = catalog / "schemas"
    schemas.mkdir(parents=True)

    # Copy real schemas and scenarios
    real_schemas = ROOT / "catalog" / "schemas"
    for sfile in real_schemas.glob("*.json"):
        (schemas / sfile.name).write_text(sfile.read_text(encoding="utf-8"), encoding="utf-8")
    (catalog / "scenarios.json").write_text(
        (ROOT / "catalog" / "scenarios.json").read_text(encoding="utf-8"), encoding="utf-8"
    )

    # Create provenance with an orphan target
    prov_data = json.loads((ROOT / "catalog" / "provenance.json").read_text(encoding="utf-8"))
    prov_data["sources"][0]["inventory"].append({
        "item_id": "orphan-test-999",
        "path_or_section": "test/section",
        "resolution": "scenario",
        "target_id": "COPS-DOES-NOT-EXIST-S99",
        "notes": "Testing orphan mapping detection",
    })
    (catalog / "provenance.json").write_text(json.dumps(prov_data), encoding="utf-8")
    registry_context["target_dir"] = p

