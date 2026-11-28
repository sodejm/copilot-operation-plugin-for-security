import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cops.evidence import (
    InventoryError,
    InventoryRegistry,
    adapt_langsmith_query_runs,
    export_langsmith_inventory,
    import_langsmith_query_runs,
)
from cops.evidence.export_policy import (
    Classification,
    DestinationRule,
    ExportAction,
    ExportBoundary,
    ExportPolicy,
    ExportRefused,
    FieldRule,
    SanitizedExport,
    SinkDescriptor,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "langsmith_query_runs_v2.json"
SCHEMA = ROOT / "cops" / "evidence" / "schemas" / "langsmith-query-runs-v2.schema.json"


def document():
    return json.loads(FIXTURE.read_text())


def test_fixture_matches_pinned_response_envelope_and_maps_graph_provenance():
    source = document()
    Draft202012Validator(json.loads(SCHEMA.read_text())).validate(source)

    snapshot = import_langsmith_query_runs(source, registry=InventoryRegistry("engagement-a"))

    assert snapshot["namespace"] == "langsmith/tenant-a"
    assert {asset["kind"] for asset in snapshot["assets"]} == {"agent_run"}
    assert [edge["kind"] for edge in snapshot["relationships"]].count("parent_child") == 4
    assert {edge["kind"] for edge in snapshot["relationships"]} == {
        "delegation",
        "parent_child",
        "tool_invocation",
    }
    llm_run = next(asset for asset in snapshot["assets"] if asset["identity"]["kind"] == "llm_run")
    assert llm_run["id"] == "run/llm/22222222-2222-4222-8222-222222222222"
    assert llm_run["provenance"] == {
        "record_id": "22222222-2222-4222-8222-222222222222",
        "reference": "restricted-langsmith-export-1",
        "observed_at": "2026-10-10T01:00:02Z",
        "completeness": "complete",
    }
    edge = next(edge for edge in snapshot["relationships"] if edge["kind"] == "tool_invocation")
    assert edge["support"] == "observed"
    assert edge["provenance"]["record_id"] == "44444444-4444-4444-8444-444444444444"
    encoded = json.dumps(snapshot, sort_keys=True)
    assert all(item["name"] not in encoded for item in source["response"]["items"])


def test_generic_tool_run_is_not_presented_as_mcp_or_privileged():
    snapshot = import_langsmith_query_runs(document(), registry=InventoryRegistry("engagement-a"))
    tool_run = next(asset for asset in snapshot["assets"] if asset["identity"]["kind"] == "tool_run")

    assert tool_run["kind"] == "agent_run"
    assert tool_run["trust"] == "unknown"
    assert tool_run["id"] == "run/tool/44444444-4444-4444-8444-444444444444"
    assert all(asset["kind"] != "mcp_tool" for asset in snapshot["assets"])
    assert all(asset["trust"] != "privileged" for asset in snapshot["assets"])


def test_tenant_namespace_prevents_colliding_run_ids():
    first = document()
    second = document()
    second["source"]["tenant"] = "tenant-b"
    registry = InventoryRegistry("engagement-a")

    snapshot_a = import_langsmith_query_runs(first, registry=registry)
    snapshot_b = import_langsmith_query_runs(second, registry=registry)

    assert snapshot_a["snapshot_id"] != snapshot_b["snapshot_id"]
    assert snapshot_a["assets"][0]["external_id"] == snapshot_b["assets"][0]["external_id"]
    assert snapshot_a["assets"][0]["qualified_id"].startswith("langsmith/tenant-a/")
    assert snapshot_b["assets"][0]["qualified_id"].startswith("langsmith/tenant-b/")


def test_repeat_and_exact_duplicate_imports_are_idempotent():
    source = document()
    source["response"]["items"].append(copy.deepcopy(source["response"]["items"][-1]))
    registry = InventoryRegistry("engagement-a")

    first = import_langsmith_query_runs(source, registry=registry)
    second = import_langsmith_query_runs(source, registry=registry)

    assert first["snapshot_id"] == second["snapshot_id"]
    assert len(first["assets"]) == 5


def test_conflicting_duplicate_run_is_rejected_without_registry_mutation():
    valid = document()
    registry = InventoryRegistry("engagement-a")
    accepted = import_langsmith_query_runs(valid, registry=registry)
    conflicting = document()
    duplicate = copy.deepcopy(conflicting["response"]["items"][-1])
    duplicate["name"] = "different-name"
    conflicting["response"]["items"].append(duplicate)

    with pytest.raises(InventoryError, match="duplicate_langsmith_run_conflict"):
        import_langsmith_query_runs(conflicting, registry=registry)
    assert registry.get(accepted["snapshot_id"], engagement_id="engagement-a") == accepted


def test_missing_parent_stays_unknown_and_does_not_create_an_edge():
    source = document()
    missing = "99999999-9999-4999-8999-999999999999"
    tool = source["response"]["items"][-1]
    tool["parent_run_ids"][-1] = missing

    snapshot = import_langsmith_query_runs(source, registry=InventoryRegistry("engagement-a"))

    tool_id = "langsmith/tenant-a/run/tool/44444444-4444-4444-8444-444444444444"
    assert not any(edge["to"] == tool_id for edge in snapshot["relationships"])
    assert {
        "subject": f"run/tool/44444444-4444-4444-8444-444444444444 parent/{missing}",
        "reason": "missing",
    } in snapshot["unknowns"]


def test_truncated_response_marks_all_provenance_partial_without_retaining_cursor():
    source = document()
    source["response"]["next_cursor"] = "secret-cursor-marker"

    adapted = adapt_langsmith_query_runs(source)
    snapshot = InventoryRegistry("engagement-a").import_document(adapted)

    assert adapted["source"]["completeness"] == "partial"
    assert snapshot["source"]["completeness"] == "partial"
    assert all(asset["provenance"]["completeness"] == "partial" for asset in snapshot["assets"])
    assert all(edge["provenance"]["completeness"] == "partial" for edge in snapshot["relationships"])
    assert {"subject": "response pagination", "reason": "missing"} in snapshot["unknowns"]
    assert "secret-cursor-marker" not in json.dumps(snapshot)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda value: value.update(schema_version="cops.langsmith-query-runs/v3"),
            "unsupported_langsmith_schema_version",
        ),
        (lambda value: value["response"]["items"][0].update(inputs={"prompt": "secret"}), "invalid_langsmith_run"),
        (lambda value: value["response"]["items"][0].update(run_type="PROMPT"), "unsupported_langsmith_run_type"),
        (lambda value: value["response"].update(extra_page_state="secret"), "invalid_langsmith_response"),
    ],
)
def test_unsupported_version_shape_and_trace_content_are_rejected(mutation, code):
    source = document()
    mutation(source)
    with pytest.raises(InventoryError, match=code):
        adapt_langsmith_query_runs(source)


def test_cycles_and_conflicting_present_parent_links_are_rejected():
    cyclic = document()
    cyclic["response"]["items"][0]["parent_run_ids"] = ["55555555-5555-4555-8555-555555555555"]
    with pytest.raises(InventoryError, match="langsmith_parent_cycle"):
        adapt_langsmith_query_runs(cyclic)

    cross_trace = document()
    cross_trace["response"]["items"][1]["trace_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    with pytest.raises(InventoryError, match="langsmith_parent_context_conflict"):
        adapt_langsmith_query_runs(cross_trace)

    conflicting_lineage = document()
    conflicting_lineage["response"]["items"][2]["parent_run_ids"] = ["55555555-5555-4555-8555-555555555555"]
    with pytest.raises(InventoryError, match="langsmith_parent_lineage_conflict"):
        adapt_langsmith_query_runs(conflicting_lineage)


def test_run_and_parent_limits_reject_oversized_responses():
    too_many_runs = document()
    template = too_many_runs["response"]["items"][0]
    too_many_runs["response"]["items"] = [copy.deepcopy(template) for _ in range(241)]
    with pytest.raises(InventoryError, match="langsmith_run_limit"):
        adapt_langsmith_query_runs(too_many_runs)

    too_many_parents = document()
    too_many_parents["response"]["items"][0]["parent_run_ids"] = [
        f"00000000-0000-4000-8000-{index:012d}" for index in range(33)
    ]
    with pytest.raises(InventoryError, match="invalid_langsmith_parent_ids"):
        adapt_langsmith_query_runs(too_many_parents)


REPORT_DESCRIPTOR = SinkDescriptor("langsmith-report-fixture", "report", "inventory-report-export")


class RecordingSink:
    def __init__(self, descriptor=REPORT_DESCRIPTOR):
        self.descriptor = descriptor
        self.exports: list[SanitizedExport] = []

    def send(self, export):
        self.exports.append(export)


def export_boundary(descriptor=REPORT_DESCRIPTOR):
    return ExportBoundary(
        ExportPolicy(
            policy_id="synthetic-langsmith-inventory-policy",
            version="2026-10-10.1",
            field_rules=(
                FieldRule("schema_version", Classification.PUBLIC, ExportAction.ALLOW),
                FieldRule("counts.assets", Classification.INTERNAL, ExportAction.ALLOW),
            ),
            destinations=(
                DestinationRule(
                    sink_id=descriptor.sink_id,
                    destination=descriptor.destination,
                    purpose=descriptor.purpose,
                    permitted_classifications=frozenset({Classification.PUBLIC, Classification.INTERNAL}),
                ),
            ),
        ),
        pseudonym_key=b"only-synthetic-langsmith-test-key",
    )


def test_export_uses_concrete_privacy_boundary_with_restricted_reference():
    snapshot = import_langsmith_query_runs(document(), registry=InventoryRegistry("engagement-a"))
    boundary = export_boundary()
    sink = RecordingSink()

    result = export_langsmith_inventory(
        snapshot,
        engagement_id="engagement-a",
        boundary=boundary,
        sink=sink,
        pseudonym_scope="engagement-a",
    )

    assert isinstance(result, SanitizedExport)
    assert result.payload == {
        "schema_version": "cops.ai-inventory-report/v1",
        "counts": {"assets": 5},
    }
    assert sink.exports == [result]
    assert (
        result.audit.restricted_evidence_reference_sha256
        == hashlib.sha256(snapshot["snapshot_id"].encode()).hexdigest()
    )


def test_export_fails_closed_when_boundary_refuses():
    snapshot = import_langsmith_query_runs(document(), registry=InventoryRegistry("engagement-a"))
    unregistered = RecordingSink(SinkDescriptor("unregistered", "report", "inventory-report-export"))
    with pytest.raises(ExportRefused, match="unregistered_destination"):
        export_langsmith_inventory(
            snapshot,
            engagement_id="engagement-a",
            boundary=export_boundary(),
            sink=unregistered,
            pseudonym_scope="engagement-a",
        )
    assert unregistered.exports == []

    wrong_destination = SinkDescriptor("langsmith-report-fixture", "telemetry", "inventory-report-export")
    wrong_sink = RecordingSink(wrong_destination)
    with pytest.raises(ExportRefused, match="adapter_destination_mismatch"):
        export_langsmith_inventory(
            snapshot,
            engagement_id="engagement-a",
            boundary=export_boundary(wrong_destination),
            sink=wrong_sink,
            pseudonym_scope="engagement-a",
        )
    assert wrong_sink.exports == []

    with pytest.raises(InventoryError, match="invalid_export_boundary"):
        export_langsmith_inventory(
            snapshot,
            engagement_id="engagement-a",
            boundary=object(),
            sink=RecordingSink(),
            pseudonym_scope="engagement-a",
        )
