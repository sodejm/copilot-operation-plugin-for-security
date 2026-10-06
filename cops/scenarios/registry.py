"""Scenario and provenance registry reader and validator for COPS."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cops.contracts.validation import validate_identifier
from cops.evidence.canonical import EvidenceError, canonical
from cops.evidence.validation import _check

ROOT: Path = Path(__file__).resolve().parents[2]
CATALOG: Path = ROOT / "catalog"
SCHEMAS: Path = CATALOG / "schemas"


class RegistryError(ValueError):
    """Exception raised for scenario or provenance registry violations."""

    def __init__(self, code: str = "invalid_registry", message: str | None = None):
        self.code = code
        self.message = message or code
        super().__init__(self.message)


def load_provenance_registry(root: Path = ROOT) -> dict[str, Any]:
    """Load and validate the provenance registry from catalog/provenance.json."""
    path = root / "catalog" / "provenance.json"
    if not path.is_file():
        raise RegistryError("missing_registry", f"provenance registry missing at {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise RegistryError("invalid_json", f"provenance registry JSON decode error: {err}") from err

    schema_path = root / "catalog" / "schemas" / "provenance-registry.schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        try:
            canonical(data)
            _check(data, schema)
        except EvidenceError as err:
            raise RegistryError(err.code, f"provenance schema validation failed: {err}") from err

    return data


def load_scenario_registry(root: Path = ROOT) -> dict[str, Any]:
    """Load and validate the scenario registry from catalog/scenarios.json."""
    path = root / "catalog" / "scenarios.json"
    if not path.is_file():
        raise RegistryError("missing_registry", f"scenario registry missing at {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise RegistryError("invalid_json", f"scenario registry JSON decode error: {err}") from err

    schema_path = root / "catalog" / "schemas" / "scenario-registry.schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        try:
            canonical(data)
            _check(data, schema)
        except EvidenceError as err:
            raise RegistryError(err.code, f"scenario registry schema validation failed: {err}") from err

    return data


def validate_scenario_and_provenance_integrity(root: Path = ROOT) -> dict[str, Any]:
    """Cross-validate scenario registry and provenance mappings.

    Ensures that:
    1. Every scenario references a known source_id in provenance.json.
    2. No duplicate scenario_id exists.
    3. Every inventoried item in provenance resolves to a valid scenario, supporting guidance, or explicit decision.
    4. No duplicate item_id exists within any source.
    """
    prov_data = load_provenance_registry(root)
    scen_data = load_scenario_registry(root)

    sources_by_id = {s["source_id"]: s for s in prov_data["sources"]}
    if len(sources_by_id) != len(prov_data["sources"]):
        raise RegistryError("duplicate_source_id", "duplicate source_id detected in provenance registry")

    scenarios = scen_data["scenarios"]
    scenarios_by_id: dict[str, dict[str, Any]] = {}
    for scen in scenarios:
        sid = scen["scenario_id"]
        if sid in scenarios_by_id:
            raise RegistryError("duplicate_scenario_id", f"duplicate scenario_id: {sid}")
        validate_identifier(sid, "scenario")

        # Verify source reference exists
        src_id = scen["provenance"]["source_id"]
        if src_id not in sources_by_id:
            raise RegistryError(
                "orphan_scenario_provenance",
                f"scenario '{sid}' references unknown source_id '{src_id}'"
            )
        scenarios_by_id[sid] = scen

    # Validate that every inventoried item in provenance resolves
    all_item_ids: set[str] = set()
    total_inventory_items = 0
    for src in prov_data["sources"]:
        for item in src["inventory"]:
            item_id = item["item_id"]
            if item_id in all_item_ids:
                raise RegistryError("duplicate_item_id", f"duplicate inventory item_id: {item_id}")
            all_item_ids.add(item_id)
            total_inventory_items += 1

            res = item["resolution"]
            target = item["target_id"]
            if res == "scenario":
                if target not in scenarios_by_id:
                    raise RegistryError(
                        "orphan_inventory_mapping",
                        f"inventory item '{item_id}' targets non-existent scenario '{target}'"
                    )
            elif res in ("supporting_guidance", "applicability_decision"):
                if not target:
                    raise RegistryError(
                        "orphan_inventory_mapping",
                        f"inventory item '{item_id}' missing target reference for {res}"
                    )

    return {
        "sources_count": len(sources_by_id),
        "inventory_items_count": total_inventory_items,
        "scenarios_count": len(scenarios_by_id),
        "status": "valid",
    }


def list_scenarios(
    root: Path = ROOT,
    *,
    family_id: str | None = None,
    tactic: str | None = None,
    coverage_mode: str | None = None,
) -> list[dict[str, Any]]:
    """List scenarios from catalog/scenarios.json, optionally filtered."""
    data = load_scenario_registry(root)
    scenarios = data["scenarios"]
    if family_id:
        scenarios = [s for s in scenarios if s.get("family_id") == family_id]
    if coverage_mode:
        scenarios = [s for s in scenarios if s.get("coverage_mode") == coverage_mode]
    if tactic:
        scenarios = [
            s for s in scenarios
            if tactic in s.get("mitre_attack", {}).get("tactics", [])
        ]
    return scenarios



def get_scenario(scenario_id: str, root: Path = ROOT) -> dict[str, Any]:
    """Retrieve a single scenario definition by scenario_id."""
    data = load_scenario_registry(root)
    for scen in data["scenarios"]:
        if scen.get("scenario_id") == scenario_id:
            return scen
    raise RegistryError("scenario_not_found", f"scenario not found: {scenario_id}")


def list_provenance_sources(root: Path = ROOT) -> list[dict[str, Any]]:
    """List all registered provenance sources from catalog/provenance.json."""
    data = load_provenance_registry(root)
    return data["sources"]


def get_provenance_source(source_id: str, root: Path = ROOT) -> dict[str, Any]:
    """Retrieve a provenance source entry by source_id."""
    data = load_provenance_registry(root)
    for src in data["sources"]:
        if src.get("source_id") == source_id:
            return src
    raise RegistryError("source_not_found", f"provenance source not found: {source_id}")

