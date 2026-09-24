"""Deterministic hunt rendering and analyst-facing contract views."""

from __future__ import annotations

from typing import Any

from .contracts import validate_target
from .errors import CompatibilityError
from .parameters import bind_parameters
from .paths import canonical_json, load_hunt, load_hunts, load_profile, sha256_text


def list_hunts() -> list[dict[str, Any]]:
    """Return stable, non-executing catalog metadata."""

    return [
        {
            "id": hunt["id"],
            "title": hunt["title"],
            "qualification_state": hunt["qualification_state"],
            "surface_support": hunt["surface_support"],
        }
        for hunt in load_hunts()
    ]


def explain_hunt(hunt_id: str) -> dict[str, Any]:
    """Return the epistemic and operational contract for one hunt."""

    validate_target(hunt_id)
    hunt = load_hunt(hunt_id)
    keys = (
        "id",
        "version",
        "title",
        "authorized_use",
        "defensive_objective",
        "hypothesis",
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
        "references",
        "provenance",
        "offline_assurance_disclaimer",
    )
    return {key: hunt[key] for key in keys}


def compatibility_report(hunt_id: str) -> dict[str, Any]:
    """Describe declared support without inferring cross-surface parity."""

    validate_target(hunt_id)
    hunt = load_hunt(hunt_id)
    surfaces: dict[str, Any] = {}
    for surface_id, state in sorted(hunt["surface_support"].items()):
        profile = load_profile(surface_id)
        query = hunt.get("queries", {}).get(surface_id)
        surfaces[surface_id] = {
            "state": state,
            "profile_version": profile["version"],
            "profile_as_of": profile["as_of"],
            "profile_support_state": profile["support_state"],
            "query_variant_present": query is not None,
            "limitations": profile["limitations"],
            "claim": (
                "offline schema and static compatibility only; not service execution"
                if state == "supported"
                else "not renderable; no compatibility is inferred"
            ),
        }
    return {
        "hunt_id": hunt["id"],
        "surfaces": surfaces,
        "live_sentinel_execution": "unsupported_in_v1",
        "offline_assurance_disclaimer": hunt["offline_assurance_disclaimer"],
    }


def _stage_contracts(hunt: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "stage_id": stage["id"],
            "order": stage["order"],
            "logical_stream": stage["stream"],
            "table": stage["table"],
            "event_time": stage["event_time"],
            "join_input": stage["join_in"],
            "join_output": stage["join_out"],
            "required_fields": stage["required_fields"],
            "evidence_output": stage["evidence_output"],
        }
        for stage in hunt["stages"]
    ]


def _timeline_schema(hunt: dict[str, Any]) -> dict[str, Any]:
    return {
        "ordering": "ascending event time with deterministic event identifiers",
        "time_basis": [
            {
                "stream": item["stream"],
                "event_time": item["event_time"],
                "ingestion_time": item["ingestion_time"],
            }
            for item in hunt["telemetry"]["timestamps"]
        ],
        "required_output_fields": [
            "stage_id",
            "event_time_utc",
            "original_event_id",
            "normalized_entity_id",
            "evidence_type",
            "workspace_scope",
            "tenant_scope",
        ],
    }


def _evidence_graph_schema(hunt: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodes": [
            {
                "entity_class": entity["class"],
                "identifier": entity["identifier"],
                "normalization": entity["normalization"],
                "collision_risk": entity["collision_risk"],
            }
            for entity in hunt["entities"]
        ],
        "edges": [
            {
                "from_stage": join["from"],
                "to_stage": join["to"],
                "typed_key": join["key"],
                "cardinality": join["cardinality"],
                "window_parameter": join["time_window"],
                "collision_risk": join["collision_risk"],
            }
            for join in hunt["joins"]
        ],
        "interpretation": "Edges represent bounded correlations, not causation, attribution, or confirmed compromise.",
    }


def render_hunt(hunt_id: str, surface_id: str, supplied: dict[str, Any]) -> dict[str, Any]:
    """Bind typed parameters and emit a complete, non-executed hunt bundle."""

    validation = validate_target(hunt_id)
    hunt = load_hunt(hunt_id)
    profile = load_profile(surface_id)
    state = hunt["surface_support"].get(surface_id)
    query = hunt.get("queries", {}).get(surface_id)
    if state != "supported" or query is None:
        raise CompatibilityError(
            f"{hunt['id']} is {state or 'undeclared'} on {surface_id}; "
            "unsupported or unverified surfaces cannot be rendered"
        )
    rendered, parameter_manifest = bind_parameters(hunt, query["content"], supplied)
    content_hashes = {
        "hunt_sha256": sha256_text(canonical_json(hunt)),
        "surface_profile_sha256": sha256_text(canonical_json(profile)),
        "rendered_query_sha256": sha256_text(rendered),
    }
    return {
        "artifact_schema": "huntwb.rendered-hunt/v1",
        "artifact_schema_version": 1,
        "assurance": "rendered_not_executed",
        "hunt_brief": {
            "id": hunt["id"],
            "version": hunt["version"],
            "title": hunt["title"],
            "authorized_use": hunt["authorized_use"],
            "defensive_objective": hunt["defensive_objective"],
            "hypothesis": hunt["hypothesis"],
        },
        "surface": {
            "id": surface_id,
            "profile_version": profile["version"],
            "profile_as_of": profile["as_of"],
            "support": state,
            "claim": "offline schema and static compatibility only; query has not been executed",
            "limitations": profile["limitations"],
        },
        "telemetry_prerequisites": hunt["telemetry"],
        "parameter_manifest": parameter_manifest,
        "query": {
            "language": query["language"],
            "kind": query["kind"],
            "stage_contract": query["stage_contract"],
            "sha256": content_hashes["rendered_query_sha256"],
            "content": rendered,
        },
        "stage_contracts": _stage_contracts(hunt),
        "timeline_schema": _timeline_schema(hunt),
        "evidence_graph_schema": _evidence_graph_schema(hunt),
        "evidence_interpretation": {
            "expected": hunt["expected_evidence"],
            "disconfirming": hunt["disconfirming_evidence"],
            "confounders": hunt["confounders"],
            "stopping_rules": hunt["stopping_rules"],
            "analyst_guidance": hunt["analyst_guidance"],
        },
        "validation": validation,
        "attck_mappings": hunt["attck_mappings"],
        "references": hunt["references"],
        "provenance": hunt["provenance"],
        "content_hashes": content_hashes,
        "human_review_required": True,
        "offline_assurance_disclaimer": hunt["offline_assurance_disclaimer"],
    }
