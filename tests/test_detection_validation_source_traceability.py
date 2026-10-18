"""Contract tests for the E17.02 pinned-source traceability catalog."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog/detection_validation_source_traceability.json"
SCHEMA_PATH = ROOT / "catalog/schemas/detection-validation-source-traceability.schema.json"
PROVENANCE_PATH = ROOT / "catalog/provenance.json"
SCENARIOS_PATH = ROOT / "catalog/scenarios.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_source_traceability_catalog_matches_schema_and_pinned_provenance() -> None:
    schema = _load(SCHEMA_PATH)
    catalog = _load(CATALOG_PATH)
    provenance = _load(PROVENANCE_PATH)

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(catalog)

    assert catalog["provenance_snapshot"] == {
        "path": "catalog/provenance.json",
        "schema_version": provenance["schema_version"],
        "updated_at": provenance["updated_at"],
    }

    mappings = {mapping["source_id"]: mapping for mapping in catalog["source_mappings"]}
    assert set(mappings) == {f"S{index:02d}" for index in range(1, 14)}

    for source_index, source in enumerate(provenance["sources"]):
        mapping = mappings[source["source_id"]]
        assert mapping["pinned_revision"] == source["pinned_revision"]
        assert mapping["inventory_reference"] == (f"catalog/provenance.json#/sources/{source_index}/inventory")
        assert mapping["canonical_ids"] == sorted({item["target_id"] for item in source["inventory"]})

    assert {
        source_id for source_id, mapping in mappings.items() if mapping["relationship"] == "direct_detection_guidance"
    } == {"S02"}
    assert all(
        mapping["relationship"] == ("direct_detection_guidance" if source_id == "S02" else "action_context")
        for source_id, mapping in mappings.items()
    )


def test_source_traceability_uses_registered_canonical_identifiers() -> None:
    catalog = _load(CATALOG_PATH)
    provenance = _load(PROVENANCE_PATH)
    scenarios = _load(SCENARIOS_PATH)

    registered_ids = (
        {scenario["scenario_id"] for scenario in scenarios["scenarios"]}
        | {guidance["guidance_id"] for guidance in provenance["guidance"]}
        | {decision["decision_id"] for decision in provenance["decisions"]}
    )
    mapped_ids = {canonical_id for mapping in catalog["source_mappings"] for canonical_id in mapping["canonical_ids"]}

    assert mapped_ids <= registered_ids


def test_native_soc_evidence_remains_explicitly_external() -> None:
    native_status = _load(CATALOG_PATH)["native_soc_validation"]

    assert native_status["status"] == "pending_external_execution"
    evidence = " ".join(native_status["required_evidence"]).lower()
    assert len(native_status["required_evidence"]) == 4
    for required_term in (
        "action identifiers",
        "time windows",
        "telemetry",
        "alert",
        "clock skew",
        "ingest lag",
        "collection completeness",
        "correlation",
    ):
        assert required_term in evidence

    limitations = " ".join(native_status["limitations"]).lower()
    assert "theoretical" in limitations
    assert "measured detection outcome" in limitations
    assert "missing telemetry" in limitations
    assert "prevented" in limitations
