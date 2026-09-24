"""Deterministic contract and surface-profile validation.

The validator deliberately checks authored artifacts rather than inferring
compatibility from syntactic similarity. Passing these checks is offline
evidence only; this module has no network or tenant access.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import date
from typing import Any, Iterable

from .errors import ContentError
from .paths import FIXTURES_DIR, HUNTS_DIR, PROFILES_DIR, load_json


EXPECTED_HUNT_IDS = tuple(f"H{number:02d}" for number in range(1, 13))
SURFACES = (
    "sentinel_analytics",
    "sentinel_data_lake",
    "defender_advanced_hunting",
)
SUPPORT_STATES = {"supported", "unsupported", "unverified"}
QUALIFICATION_STATES = {
    "draft",
    "schema_checked",
    "static_checked",
    "fixture_executed",
    "emulator_executed",
    "human_reviewed",
    "offline_qualified",
    "deprecated",
    "withdrawn",
}
PROHIBITED_ASSURANCE_TERMS = (
    "target verified",
    "tenant validated",
    "sentinel validated",
    "production ready",
    "production proven",
    "effective detection",
)
REQUIRED_PARAMETERS = {
    "start_time",
    "end_time",
    "tenant_id",
    "workspace_id",
    "correlation_window",
}
REQUIRED_QUERY_MARKERS = (
    "// huntwb:time-scope",
    "// huntwb:tenant-scope",
    "// huntwb:workspace-scope",
    "// huntwb:order=ascending",
    "// huntwb:join-key=typed",
    "// huntwb:entity-discriminator=immutable",
    "// huntwb:dedup",
    "// huntwb:aggregate-after-correlation",
    "// huntwb:typed-identifiers",
    "// huntwb:correlation-window=bounded",
    "// huntwb:validity-check",
    "// huntwb:missing-is-unknown",
    "// huntwb:language=correlation",
)
EXPECTED_CURATED_COUNTS = {
    "true_positive": 8,
    "benign_counterfactual": 10,
    "entity_integrity": 8,
    "temporal_data_quality": 8,
    "schema_surface": 4,
    "scale_resource": 4,
    "hostile_privacy": 3,
    "mutation_metamorphic": 3,
}
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PLACEHOLDER_RE = re.compile(r"\{\{([a-z][a-z0-9_]*)\}\}")
TABLE_REFERENCE_RE = re.compile(
    r"workspace\(workspace_id\)\.([A-Za-z_][A-Za-z0-9_]*)"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContentError(message)


def _require_keys(value: dict[str, Any], keys: Iterable[str], context: str) -> None:
    missing = sorted(set(keys) - set(value))
    _require(not missing, f"{context}: missing required keys: {', '.join(missing)}")


def _validate_version(value: Any, context: str) -> None:
    _require(
        isinstance(value, str) and bool(SEMVER_RE.fullmatch(value)),
        f"{context}: invalid semantic version",
    )


def _validate_date(value: Any, context: str) -> None:
    _require(isinstance(value, str), f"{context}: date must be an ISO string")
    try:
        date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ContentError(f"{context}: invalid ISO date") from exc


def _validate_https_url(value: Any, context: str) -> None:
    _require(
        isinstance(value, str) and value.startswith("https://"),
        f"{context}: HTTPS URL required",
    )


def _normalized_claim_text(value: Any) -> str:
    text = str(value).lower().replace("_", " ").replace("-", " ")
    return " ".join(text.split())


def _reject_prohibited_claims(value: Any, context: str) -> None:
    text = _normalized_claim_text(value)
    for term in PROHIBITED_ASSURANCE_TERMS:
        if term in text:
            raise ContentError(f"{context}: prohibited assurance term: {term}")


def load_profiles() -> dict[str, dict[str, Any]]:
    """Load every profile keyed by its declared identifier."""

    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(PROFILES_DIR.glob("*.json")):
        profile = load_json(path)
        profile_id = profile.get("id")
        _require(isinstance(profile_id, str), f"{path}: profile id must be a string")
        _require(profile_id not in profiles, f"duplicate profile id: {profile_id}")
        profiles[profile_id] = profile
    return profiles


def load_hunts() -> dict[str, dict[str, Any]]:
    """Load every hunt keyed by its declared identifier."""

    hunts: dict[str, dict[str, Any]] = {}
    for path in sorted(HUNTS_DIR.glob("*.json")):
        hunt = load_json(path)
        hunt_id = hunt.get("id")
        _require(isinstance(hunt_id, str), f"{path}: hunt id must be a string")
        _require(hunt_id not in hunts, f"duplicate hunt id: {hunt_id}")
        hunts[hunt_id] = hunt
    return hunts


def validate_profile(profile: dict[str, Any]) -> None:
    """Validate a versioned offline execution-surface profile."""

    context = f"profile {profile.get('id', '<unknown>')}"
    _require_keys(
        profile,
        {
            "id",
            "version",
            "as_of",
            "display_name",
            "support_state",
            "scope_contract",
            "profile_provenance",
            "allowed_operators",
            "allowed_functions",
            "unsupported_functions",
            "limitations",
            "tables",
        },
        context,
    )
    _require(profile["id"] in SURFACES, f"{context}: unknown surface identifier")
    _validate_version(profile["version"], f"{context}.version")
    _validate_date(profile["as_of"], f"{context}.as_of")
    _require(profile["support_state"] in SUPPORT_STATES, f"{context}: invalid support state")
    _require(
        isinstance(profile["scope_contract"], dict),
        f"{context}: scope_contract must be an object",
    )
    _require(isinstance(profile["tables"], dict), f"{context}: tables must be an object")
    _require(
        bool(profile["tables"]) or profile["support_state"] != "supported",
        f"{context}: supported profile requires tables",
    )

    for key in (
        "allowed_operators",
        "allowed_functions",
        "unsupported_functions",
        "limitations",
    ):
        _require(isinstance(profile[key], list), f"{context}.{key}: expected a list")

    provenance = profile["profile_provenance"]
    _require(
        isinstance(provenance, list) and provenance,
        f"{context}: profile provenance is required",
    )
    for index, source in enumerate(provenance):
        source_context = f"{context}.profile_provenance[{index}]"
        _require(isinstance(source, dict), f"{source_context}: expected an object")
        _require_keys(source, {"url", "accessed"}, source_context)
        _validate_https_url(source["url"], f"{source_context}.url")
        _validate_date(source["accessed"], f"{source_context}.accessed")

    for table_name, table in profile["tables"].items():
        table_context = f"{context}.tables.{table_name}"
        _require(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table_name) is not None,
            f"{table_context}: invalid table name",
        )
        _require(isinstance(table, dict), f"{table_context}: expected an object")
        _require_keys(
            table,
            {"columns", "schema_source", "schema_as_of", "notes"},
            table_context,
        )
        _require(
            isinstance(table["columns"], dict) and table["columns"],
            f"{table_context}: columns required",
        )
        for column_name, column_type in table["columns"].items():
            _require(
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", column_name) is not None,
                f"{table_context}: invalid column {column_name!r}",
            )
            _require(
                isinstance(column_type, str) and column_type,
                f"{table_context}.{column_name}: type required",
            )
        _validate_https_url(table["schema_source"], f"{table_context}.schema_source")
        _validate_date(table["schema_as_of"], f"{table_context}.schema_as_of")

    _reject_prohibited_claims(profile, context)


def _validate_stage(stage: dict[str, Any], profile: dict[str, Any], context: str) -> None:
    _require_keys(
        stage,
        {
            "id",
            "order",
            "stream",
            "table",
            "event_time",
            "event_id_fields",
            "required_fields",
            "entity_extractors",
            "join_in",
            "join_out",
            "evidence_output",
        },
        context,
    )
    table_name = stage["table"]
    _require(
        table_name in profile["tables"],
        f"{context}: table {table_name!r} absent from selected profile",
    )
    columns = profile["tables"][table_name]["columns"]

    explicit_fields: set[str] = set(stage["required_fields"])
    explicit_fields.add(stage["event_time"])
    explicit_fields.update(stage["event_id_fields"])
    aad_tenant_field = stage.get("aad_tenant_field")
    if aad_tenant_field:
        explicit_fields.add(aad_tenant_field)
    for validity_field in stage.get("validity_fields", []):
        explicit_fields.add(validity_field)
    missing_fields = sorted(field for field in explicit_fields if field not in columns)
    _require(
        not missing_fields,
        f"{context}: fields absent from {table_name}: {', '.join(missing_fields)}",
    )

    _require(
        isinstance(stage["order"], int) and stage["order"] > 0,
        f"{context}: order must be positive",
    )
    _require(
        isinstance(stage["event_id_fields"], list) and stage["event_id_fields"],
        f"{context}: event_id_fields required",
    )
    _require(
        isinstance(stage["required_fields"], list) and stage["required_fields"],
        f"{context}: required_fields required",
    )
    _require(
        isinstance(stage["entity_extractors"], dict) and stage["entity_extractors"],
        f"{context}: entity_extractors required",
    )
    _require(
        isinstance(stage["evidence_output"], list) and stage["evidence_output"],
        f"{context}: evidence_output required",
    )


def _validate_query(
    hunt: dict[str, Any],
    surface: str,
    query: dict[str, Any],
    profile: dict[str, Any],
) -> None:
    context = f"hunt {hunt['id']}.queries.{surface}"
    _require_keys(query, {"language", "content", "stage_contract"}, context)
    _require(query["language"] == "KQL", f"{context}: language must be KQL")
    content = query["content"]
    _require(
        isinstance(content, str) and content.strip(),
        f"{context}: query content required",
    )

    parameter_names = {parameter["name"] for parameter in hunt["parameters"]}
    placeholders = set(PLACEHOLDER_RE.findall(content))
    unknown_placeholders = sorted(placeholders - parameter_names)
    _require(
        not unknown_placeholders,
        f"{context}: unknown parameters: {', '.join(unknown_placeholders)}",
    )
    missing_parameters = sorted(REQUIRED_PARAMETERS - placeholders)
    _require(
        not missing_parameters,
        f"{context}: missing required parameter use: {', '.join(missing_parameters)}",
    )

    for marker in REQUIRED_QUERY_MARKERS:
        _require(marker in content, f"{context}: missing semantic marker {marker}")

    stages = hunt["stages"]
    _require(
        query["stage_contract"] == [stage["id"] for stage in stages],
        f"{context}: stage_contract must preserve every ordered stage",
    )
    stage_tables = {stage["table"] for stage in stages}
    referenced_tables = set(TABLE_REFERENCE_RE.findall(content))
    missing_tables = sorted(stage_tables - referenced_tables)
    _require(
        not missing_tables,
        f"{context}: stages not represented in query: {', '.join(missing_tables)}",
    )
    unknown_tables = sorted(referenced_tables - set(profile["tables"]))
    _require(
        not unknown_tables,
        f"{context}: tables absent from profile: {', '.join(unknown_tables)}",
    )

    time_filter_count = content.count("between (start_time .. end_time)")
    _require(
        time_filter_count >= len(stages),
        f"{context}: every source requires an explicit event-time bound",
    )
    _require(
        content.count("join kind=inner") >= len(stages) - 1,
        f"{context}: query does not preserve required correlation hops",
    )

    lowered = content.lower()
    for function in profile["unsupported_functions"]:
        _require(
            f"{str(function).lower()}(" not in lowered,
            f"{context}: unsupported function {function}",
        )
    _reject_prohibited_claims(content, context)


def validate_hunt(hunt: dict[str, Any], profiles: dict[str, dict[str, Any]]) -> None:
    """Validate one hunt against its declared surface profiles."""

    context = f"hunt {hunt.get('id', '<unknown>')}"
    _require_keys(
        hunt,
        {
            "id",
            "version",
            "title",
            "hypothesis",
            "defensive_objective",
            "authorized_use",
            "qualification_state",
            "surface_support",
            "telemetry",
            "entities",
            "parameters",
            "stages",
            "joins",
            "expected_evidence",
            "disconfirming_evidence",
            "confounders",
            "stopping_rules",
            "analyst_guidance",
            "attck_mappings",
            "queries",
            "tests",
            "references",
            "provenance",
            "offline_assurance_disclaimer",
        },
        context,
    )
    _require(hunt["id"] in EXPECTED_HUNT_IDS, f"{context}: unexpected hunt id")
    _validate_version(hunt["version"], f"{context}.version")
    _require(
        hunt["authorized_use"] == "defensive_only",
        f"{context}: defensive_only authorization required",
    )
    _require(
        hunt["qualification_state"] in QUALIFICATION_STATES,
        f"{context}: invalid qualification state",
    )

    surface_support = hunt["surface_support"]
    _require(
        isinstance(surface_support, dict),
        f"{context}: surface_support must be an object",
    )
    _require(
        set(surface_support) == set(SURFACES),
        f"{context}: all execution surfaces must be declared",
    )
    for surface, support in surface_support.items():
        _require(
            support in SUPPORT_STATES,
            f"{context}: invalid support state for {surface}",
        )
        _require(surface in profiles, f"{context}: missing profile {surface}")
        if support == "supported":
            _require(
                surface in hunt["queries"],
                f"{context}: supported surface {surface} lacks a query",
            )
            _require(
                profiles[surface]["support_state"] == "supported",
                f"{context}: profile does not authorize support for {surface}",
            )
        else:
            _require(
                surface not in hunt["queries"],
                f"{context}: non-supported surface {surface} must not contain a query",
            )

    telemetry = hunt["telemetry"]
    _require_keys(
        telemetry,
        {"required", "optional", "timestamps", "latency_assumptions"},
        f"{context}.telemetry",
    )
    _require(
        isinstance(telemetry["required"], list) and len(telemetry["required"]) >= 3,
        f"{context}: at least three required telemetry streams",
    )
    _require(
        len(set(telemetry["required"])) == len(telemetry["required"]),
        f"{context}: telemetry stream names must be unique",
    )
    _require(
        isinstance(telemetry["timestamps"], list)
        and len(telemetry["timestamps"]) >= 3,
        f"{context}: timestamp semantics required per stream",
    )
    _require(
        isinstance(telemetry["latency_assumptions"], list)
        and telemetry["latency_assumptions"],
        f"{context}: latency assumptions required",
    )

    entities = hunt["entities"]
    _require(
        isinstance(entities, list) and len(entities) >= 2,
        f"{context}: at least two entity classes required",
    )
    entity_classes = [
        entity.get("class") for entity in entities if isinstance(entity, dict)
    ]
    _require(
        len(set(entity_classes)) >= 2 and None not in entity_classes,
        f"{context}: entity classes must be explicit and distinct",
    )
    for entity in entities:
        _require_keys(
            entity,
            {"class", "identifier", "normalization", "collision_risk"},
            f"{context}.entities",
        )

    parameters = hunt["parameters"]
    _require(isinstance(parameters, list), f"{context}: parameters must be a list")
    parameter_names = [
        parameter.get("name")
        for parameter in parameters
        if isinstance(parameter, dict)
    ]
    _require(
        len(parameter_names) == len(set(parameter_names)),
        f"{context}: duplicate parameter names",
    )
    _require(
        REQUIRED_PARAMETERS <= set(parameter_names),
        f"{context}: required parameters missing",
    )
    for parameter in parameters:
        _require_keys(
            parameter,
            {"name", "type", "required"},
            f"{context}.parameters",
        )

    stages = hunt["stages"]
    _require(
        isinstance(stages, list) and len(stages) >= 3,
        f"{context}: at least three correlation stages required",
    )
    _require(
        [stage.get("order") for stage in stages]
        == list(range(1, len(stages) + 1)),
        f"{context}: stage order must be contiguous",
    )
    stream_names = [stage.get("stream") for stage in stages]
    _require(
        set(telemetry["required"]) <= set(stream_names),
        f"{context}: every required telemetry stream must map to a stage",
    )
    for stage in stages:
        _validate_stage(
            stage,
            profiles["sentinel_analytics"],
            f"{context}.stages.{stage.get('id', '<unknown>')}",
        )

    joins = hunt["joins"]
    _require(
        isinstance(joins, list) and len(joins) >= 2,
        f"{context}: at least two joins required",
    )
    _require(
        len(joins) == len(stages) - 1,
        f"{context}: joins must connect every adjacent stage",
    )
    stage_ids = [stage["id"] for stage in stages]
    for index, join in enumerate(joins):
        join_context = f"{context}.joins[{index}]"
        _require_keys(
            join,
            {
                "from",
                "to",
                "key",
                "type",
                "cardinality",
                "collision_risk",
                "time_window",
            },
            join_context,
        )
        _require(
            join["from"] == stage_ids[index]
            and join["to"] == stage_ids[index + 1],
            f"{join_context}: join must connect adjacent ordered stages",
        )
        _require(
            "bounded" in str(join["cardinality"]).lower(),
            f"{join_context}: join cardinality must be explicitly bounded",
        )
        _require(
            join["time_window"] == "correlation_window",
            f"{join_context}: bounded correlation_window required",
        )

    for field_name in (
        "expected_evidence",
        "disconfirming_evidence",
        "confounders",
        "stopping_rules",
        "analyst_guidance",
        "attck_mappings",
        "references",
    ):
        _require(
            isinstance(hunt[field_name], list) and hunt[field_name],
            f"{context}: {field_name} must be non-empty",
        )

    for mapping in hunt["attck_mappings"]:
        _require_keys(
            mapping,
            {"id", "name", "version", "rationale"},
            f"{context}.attck_mappings",
        )
        _require(
            bool(mapping["rationale"]),
            f"{context}: ATT&CK mapping rationale required",
        )

    for index, reference in enumerate(hunt["references"]):
        reference_context = f"{context}.references[{index}]"
        _require(isinstance(reference, dict), f"{reference_context}: expected an object")
        _require_keys(reference, {"title", "url", "kind"}, reference_context)
        _validate_https_url(reference["url"], f"{reference_context}.url")

    tests = hunt["tests"]
    _require_keys(
        tests,
        {"curated_scenarios", "generated_perturbations", "semantic_mutations"},
        f"{context}.tests",
    )
    _require(
        tests["curated_scenarios"] == 48,
        f"{context}: exactly 48 curated scenarios required",
    )
    _require(
        tests["generated_perturbations"] >= 250,
        f"{context}: at least 250 generated perturbations required",
    )
    _require(
        tests["semantic_mutations"] >= 12,
        f"{context}: at least 12 semantic mutations required",
    )

    for surface, query in hunt["queries"].items():
        _require(surface in SURFACES, f"{context}: unknown query surface {surface}")
        _validate_query(hunt, surface, query, profiles[surface])

    disclaimer = hunt["offline_assurance_disclaimer"]
    _require(
        isinstance(disclaimer, str) and "offline" in disclaimer.lower(),
        f"{context}: offline assurance disclaimer required",
    )
    _require(
        "unverified" in disclaimer.lower(),
        f"{context}: disclaimer must state unverified operational behavior",
    )
    _reject_prohibited_claims(hunt, context)


def validate_fixture(fixture: dict[str, Any], hunt: dict[str, Any]) -> None:
    """Validate the curated fixture contract for one hunt."""

    context = f"fixture {fixture.get('hunt_id', '<unknown>')}"
    _require_keys(
        fixture,
        {
            "hunt_id",
            "version",
            "synthetic_only",
            "scenario_count",
            "category_counts",
            "scenarios",
        },
        context,
    )
    _require(fixture["hunt_id"] == hunt["id"], f"{context}: hunt id mismatch")
    _validate_version(fixture["version"], f"{context}.version")
    _require(
        fixture["synthetic_only"] is True,
        f"{context}: fixtures must be synthetic-only",
    )
    scenarios = fixture["scenarios"]
    _require(isinstance(scenarios, list), f"{context}: scenarios must be a list")
    _require(
        fixture["scenario_count"] == 48 == len(scenarios),
        f"{context}: exactly 48 scenarios required",
    )
    _require(
        fixture["category_counts"] == EXPECTED_CURATED_COUNTS,
        f"{context}: category-count contract mismatch",
    )
    observed_counts = Counter(scenario.get("category") for scenario in scenarios)
    _require(
        dict(observed_counts) == EXPECTED_CURATED_COUNTS,
        f"{context}: observed category counts differ",
    )

    scenario_ids: set[str] = set()
    supported_surfaces = {
        surface
        for surface, state in hunt["surface_support"].items()
        if state == "supported"
    }
    stage_ids = {stage["id"] for stage in hunt["stages"]}
    for scenario in scenarios:
        scenario_context = f"{context}.{scenario.get('id', '<unknown>')}"
        _require_keys(
            scenario,
            {
                "id",
                "purpose",
                "category",
                "input",
                "expected_stage_counts",
                "expected_matches",
                "expected_entities",
                "expected_relationships",
                "prohibited_conclusions",
                "expected_qualification_outcome",
                "applicable_surfaces",
                "rationale",
            },
            scenario_context,
        )
        _require(
            scenario["id"] not in scenario_ids,
            f"{scenario_context}: duplicate scenario id",
        )
        scenario_ids.add(scenario["id"])
        _require(
            scenario["category"] in EXPECTED_CURATED_COUNTS,
            f"{scenario_context}: invalid category",
        )
        _require(
            set(scenario["expected_stage_counts"]) == stage_ids,
            f"{scenario_context}: stage-count keys must be complete",
        )
        _require(
            set(scenario["applicable_surfaces"]) <= supported_surfaces,
            f"{scenario_context}: unsupported applicable surface",
        )
        _require(
            isinstance(scenario["prohibited_conclusions"], list)
            and scenario["prohibited_conclusions"],
            f"{scenario_context}: prohibited conclusions required",
        )
        _require(
            isinstance(scenario["rationale"], str) and scenario["rationale"],
            f"{scenario_context}: rationale required",
        )
        input_data = scenario["input"]
        _require(
            isinstance(input_data, dict),
            f"{scenario_context}: input must be an object",
        )
        if "events" in input_data:
            _require(
                isinstance(input_data["events"], list),
                f"{scenario_context}: events must be a list",
            )
            for event in input_data["events"]:
                _require(
                    isinstance(event, dict),
                    f"{scenario_context}: every event must be an object",
                )

    _reject_prohibited_claims(fixture, context)


def validate_library() -> dict[str, Any]:
    """Validate the complete twelve-hunt library and return a compact report."""

    profiles = load_profiles()
    _require(
        set(profiles) == set(SURFACES),
        "profile registry must contain exactly the three declared surfaces",
    )
    for profile in profiles.values():
        validate_profile(profile)

    hunts = load_hunts()
    _require(
        tuple(sorted(hunts)) == EXPECTED_HUNT_IDS,
        "hunt registry must contain exactly H01 through H12",
    )

    for hunt_id, hunt in hunts.items():
        validate_hunt(hunt, profiles)
        fixture_path = FIXTURES_DIR / f"{hunt_id}.json"
        _require(fixture_path.exists(), f"hunt {hunt_id}: curated fixture file missing")
        validate_fixture(load_json(fixture_path), hunt)

    return {
        "status": "passed",
        "offline_only": True,
        "profiles": len(profiles),
        "hunts": len(hunts),
        "curated_scenarios": sum(
            hunt["tests"]["curated_scenarios"] for hunt in hunts.values()
        ),
        "generated_perturbations_declared": sum(
            hunt["tests"]["generated_perturbations"] for hunt in hunts.values()
        ),
        "semantic_mutations_declared": sum(
            hunt["tests"]["semantic_mutations"] for hunt in hunts.values()
        ),
    }


def validate_target(target: str) -> dict[str, Any]:
    """Validate the full library or one hunt with all profiles."""

    if target.lower() == "library":
        return validate_library()

    profiles = load_profiles()
    for profile in profiles.values():
        validate_profile(profile)
    hunts = load_hunts()
    hunt_id = target.upper()
    if hunt_id not in hunts:
        raise ContentError(f"unknown hunt: {target}")
    hunt = hunts[hunt_id]
    validate_hunt(hunt, profiles)
    fixture_path = FIXTURES_DIR / f"{hunt_id}.json"
    if not fixture_path.exists():
        raise ContentError(f"hunt {hunt_id}: curated fixture file missing")
    validate_fixture(load_json(fixture_path), hunt)
    return {
        "status": "passed",
        "offline_only": True,
        "profiles": len(profiles),
        "hunts": 1,
        "hunt_ids": [hunt_id],
        "curated_scenarios": hunt["tests"]["curated_scenarios"],
        "generated_perturbations_declared": hunt["tests"]["generated_perturbations"],
        "semantic_mutations_declared": hunt["tests"]["semantic_mutations"],
    }
