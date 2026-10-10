import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cops.evidence import (InventoryError, InventoryRegistry, adapt_entra_service_principals,
                           compare_inventories, import_inventory, inventory_report)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SCHEMAS = ROOT / "cops" / "evidence" / "schemas"


def load_json(path):
    return json.loads(path.read_text())


def document(*, tenant="tenant-a", tool="billing-tool"):
    provenance = {"record_id": "record-1", "reference": "restricted-record-1", "observed_at": "2026-10-10T00:00:00Z", "completeness": "complete"}
    return {"schema_version": "cops.ai-inventory/v1", "source": {"provider": "langsmith", "tenant": tenant, "collection_id": "runs-1", "collected_at": "2026-10-10T00:00:00Z", "completeness": "complete", "freshness_policy_seconds": 3600}, "assets": [{"id": "run/root", "kind": "agent_run", "display_name": "root", "external_id": "run-1", "owner": "unknown", "sensitivity": "restricted", "trust": "trusted", "provenance": provenance}, {"id": "tool/billing", "kind": "mcp_tool", "display_name": tool, "external_id": "tool-1", "owner": "security", "sensitivity": "restricted", "trust": "privileged", "provenance": provenance}, {"id": "destination/audit", "kind": "destination", "external_id": "dest-1", "owner": "security", "sensitivity": "restricted", "trust": "trusted", "provenance": provenance}], "relationships": [{"id": "edge/run-tool", "from": "run/root", "to": "tool/billing", "kind": "tool_invocation", "support": "observed", "provenance": provenance}, {"id": "edge/tool-destination", "from": "tool/billing", "to": "destination/audit", "kind": "outbound_transfer", "support": "declared", "provenance": provenance}], "unknowns": [{"subject": "run/root input", "reason": "opaque"}]}


def test_import_is_bounded_and_namespaced_without_raw_payloads():
    snapshot = import_inventory(document(), engagement_id="engagement-a")
    assert snapshot["namespace"] == "langsmith/tenant-a"
    assert snapshot["assets"][0]["qualified_id"].startswith("langsmith/tenant-a/")
    unsafe = document(); unsafe["assets"][0]["inputs"] = {"prompt": "omit"}
    with pytest.raises(InventoryError, match="invalid_asset"):
        import_inventory(unsafe, engagement_id="engagement-a")


def test_invalid_document_never_mutates_registry_and_access_is_restricted():
    registry = InventoryRegistry("engagement-a")
    valid = registry.import_document(document())
    assert registry.import_document(document())["snapshot_id"] == valid["snapshot_id"]
    invalid = document(); invalid["relationships"][0]["to"] = "not-present"
    with pytest.raises(InventoryError, match="malformed_reference"):
        registry.import_document(invalid)
    assert registry.get(valid["snapshot_id"], engagement_id="engagement-a")["snapshot_id"] == valid["snapshot_id"]
    with pytest.raises(InventoryError, match="restricted_reference"):
        registry.report(valid["snapshot_id"], engagement_id="engagement-b")
    with pytest.raises(InventoryError, match="restricted_reference"):
        registry.report(valid["snapshot_id"], engagement_id="engagement-a", namespace="wrong/tenant")


def test_compare_reports_tool_changes_and_unknowns_deterministically():
    before = import_inventory(document(), engagement_id="engagement-a")
    changed = document(tool="payments-tool")
    changed["assets"].append({"id": "tool/refunds", "kind": "mcp_tool", "external_id": "tool-2", "owner": "security", "sensitivity": "restricted", "trust": "privileged", "provenance": changed["assets"][0]["provenance"]})
    after = import_inventory(changed, engagement_id="engagement-a")
    result = compare_inventories(before, after, engagement_id="engagement-a")
    assert [item["qualified_id"] for item in result["added"]["assets"]] == ["langsmith/tenant-a/tool/refunds"]
    assert result["changed"]["assets"][0]["id"] == "langsmith/tenant-a/tool/billing"
    assert result["uncertain_relationships"][0]["support"] == "declared"
    report = inventory_report(after, engagement_id="engagement-a")
    assert report["counts"]["assets"] == 4
    assert report["trust_boundaries"][0]["kind"] == "tool_invocation"
    assert report["trust_boundary_paths"] == [{"from": {"id": "langsmith/tenant-a/run/root", "kind": "agent_run"}, "to": {"id": "langsmith/tenant-a/destination/audit", "kind": "destination"}, "relationships": [{"id": "edge/run-tool", "kind": "tool_invocation", "support": "observed", "completeness": "complete"}, {"id": "edge/tool-destination", "kind": "outbound_transfer", "support": "declared", "completeness": "complete"}]}]


def test_compare_reports_permission_and_destination_changes():
    before = import_inventory(document(), engagement_id="engagement-a")
    changed = document()
    changed["assets"][0]["permissions"] = ["tool:billing.read", "tool:billing.write"]
    changed["assets"][0]["scopes"] = ["billing", "audit"]
    changed["assets"].append({"id": "destination/privileged", "kind": "destination", "external_id": "dest-2", "owner": "security", "sensitivity": "restricted", "trust": "privileged", "provenance": changed["assets"][0]["provenance"]})
    changed["relationships"][1]["support"] = "observed"
    changed["relationships"][1]["to"] = "destination/privileged"
    changed["relationships"][1]["kind"] = "delegation"
    after = import_inventory(changed, engagement_id="engagement-a")
    comparison = compare_inventories(before, after, engagement_id="engagement-a")
    assert comparison["changed"]["relationships"][0]["id"] == "edge/tool-destination"
    assert comparison["changed"]["relationships"][0]["after"]["kind"] == "delegation"
    assert comparison["changed"]["relationships"][0]["after"]["to"].endswith("destination/privileged")
    assert comparison["permission_changes"] == [{"id": "langsmith/tenant-a/run/root", "before": [],
                                                  "after": ["tool:billing.read", "tool:billing.write"]}]
    assert comparison["scope_changes"] == [{"id": "langsmith/tenant-a/run/root", "before": [],
                                             "after": ["audit", "billing"]}]


def test_reconciles_an_agent_to_entra_sponsor_without_merging_source_records():
    source = document()
    source["assets"].append({"id": "agent/billing", "kind": "agent", "external_id": "agent-1", "owner": "security", "sensitivity": "restricted", "trust": "privileged", "provenance": source["assets"][0]["provenance"]})
    source["identity_links"] = [{"asset": "agent/billing", "identity": {"provider": "entra", "tenant": "tenant-a", "kind": "service_principal", "id": "sp-1"}, "reason": "sponsor", "provenance": source["assets"][0]["provenance"]}]
    snapshot = import_inventory(source, engagement_id="engagement-a")
    assert snapshot["identity_links"][0]["asset"] == "langsmith/tenant-a/agent/billing"
    assert inventory_report(snapshot, engagement_id="engagement-a")["identity_links"][0]["reason"] == "sponsor"


def test_rejects_duplicate_links_and_retains_conflicting_evidence_as_unknown():
    source = document()
    source["unknowns"].append({"subject": "tool/billing permission", "reason": "conflicting"})
    source["identity_links"] = [{"asset": "run/root", "identity": {"provider": "entra", "tenant": "tenant-a", "kind": "service_principal", "id": "sp-1"}, "reason": "alias", "provenance": source["assets"][0]["provenance"]}] * 2
    with pytest.raises(InventoryError, match="duplicate_identity_link"):
        import_inventory(source, engagement_id="engagement-a")
    source["identity_links"] = source["identity_links"][:1]
    assert import_inventory(source, engagement_id="engagement-a")["unknowns"][-1]["reason"] == "conflicting"


def test_rejects_conflicting_identity_and_keeps_tenants_separate():
    duplicate = document(); copy_asset = copy.deepcopy(duplicate["assets"][0]); copy_asset["kind"] = "agent"; duplicate["assets"].append(copy_asset)
    with pytest.raises(InventoryError, match="duplicate_identity_conflict"):
        import_inventory(duplicate, engagement_id="engagement-a")
    assert import_inventory(document(tenant="tenant-a"), engagement_id="engagement-a")["assets"][0]["qualified_id"] != import_inventory(document(tenant="tenant-b"), engagement_id="engagement-a")["assets"][0]["qualified_id"]


def test_offline_entra_adapter_uses_selected_fields_only():
    doc = adapt_entra_service_principals({"value": [{"id": "sp-1", "appId": "app-1", "displayName": "Sponsor"}]}, tenant="tenant-a", collected_at="2026-10-10T00:00:00Z")
    assert import_inventory(doc, engagement_id="engagement-a")["assets"][0]["identity"]["id"] == "sp-1"
    with pytest.raises(InventoryError, match="invalid_entra_export"):
        adapt_entra_service_principals({"value": [{"id": "sp-1", "appId": "app-1", "passwordCredentials": []}]}, tenant="tenant-a", collected_at="2026-10-10T00:00:00Z")


def test_report_identifies_untrusted_document_to_privileged_tool_path_and_revalidates_snapshots():
    source = document()
    provenance = source["assets"][0]["provenance"]
    source["assets"].extend([
        {"id": "document/upload", "kind": "document", "external_id": "doc-1", "owner": "external", "sensitivity": "unknown", "trust": "untrusted", "provenance": provenance},
        {"id": "agent/ingest", "kind": "agent", "external_id": "agent-1", "owner": "security", "sensitivity": "restricted", "trust": "trusted", "provenance": provenance},
    ])
    source["relationships"].extend([
        {"id": "edge/document-agent", "from": "document/upload", "to": "agent/ingest", "kind": "reads", "support": "observed", "provenance": provenance},
        {"id": "edge/agent-tool", "from": "agent/ingest", "to": "tool/billing", "kind": "tool_invocation", "support": "observed", "provenance": provenance},
    ])
    snapshot = import_inventory(source, engagement_id="engagement-a")
    report = inventory_report(snapshot, engagement_id="engagement-a")
    assert [edge["id"] for edge in report["privileged_document_paths"][0]["relationships"]] == ["edge/document-agent", "edge/agent-tool", "edge/tool-destination"]
    snapshot["relationships"][0]["to"] = "langsmith/tenant-a/destination/audit"
    with pytest.raises(InventoryError, match="restricted_reference"):
        inventory_report(snapshot, engagement_id="engagement-a")


def test_report_excludes_document_to_tool_path_without_an_agent():
    source = document()
    provenance = source["assets"][0]["provenance"]
    source["assets"].append({"id": "document/upload", "kind": "document", "external_id": "doc-1",
                             "owner": "external", "sensitivity": "unknown", "trust": "untrusted",
                             "provenance": provenance})
    source["relationships"].append({"id": "edge/document-tool", "from": "document/upload",
                                    "to": "tool/billing", "kind": "tool_invocation", "support": "observed",
                                    "provenance": provenance})
    report = inventory_report(import_inventory(source, engagement_id="engagement-a"),
                              engagement_id="engagement-a")
    assert report["privileged_document_paths"] == []


@pytest.mark.parametrize(("provider", "tenant"), [("a/b", "c"), ("a", "b/c")])
def test_rejects_namespace_component_delimiter(provider, tenant):
    source = document()
    source["source"]["provider"] = provider
    source["source"]["tenant"] = tenant
    with pytest.raises(InventoryError, match="invalid_source"):
        import_inventory(source, engagement_id="engagement-a")


def test_versioned_schemas_validate_import_comparison_and_lineage_fixtures():
    import_validator = Draft202012Validator(load_json(SCHEMAS / "ai-inventory-v1.schema.json"))
    comparison_validator = Draft202012Validator(load_json(SCHEMAS / "ai-inventory-comparison-v1.schema.json"))
    import_fixture = load_json(FIXTURES / "ai_inventory_v1.json")
    lineage_fixture = load_json(FIXTURES / "ai_inventory_lineage_v1.json")
    comparison_fixture = load_json(FIXTURES / "ai_inventory_comparison_v1.json")
    import_validator.validate(import_fixture)
    import_validator.validate(lineage_fixture)
    comparison_validator.validate(comparison_fixture)
    lineage = import_inventory(lineage_fixture, engagement_id="engagement-a")
    assert [link["reason"] for link in lineage["identity_links"]] == ["sponsor", "alias", "merge", "split"]
    before = import_inventory(import_fixture, engagement_id="engagement-a")
    changed = copy.deepcopy(import_fixture)
    changed["assets"][0]["permissions"] = ["tool:billing.write"]
    changed["assets"][0]["scopes"] = ["audit", "billing"]
    after = import_inventory(changed, engagement_id="engagement-a")
    comparison_validator.validate(compare_inventories(before, after, engagement_id="engagement-a"))
