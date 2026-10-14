# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Comprehensive unit tests for the Entra Identity Workbench."""

import json
import sys
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from entrawb.analysis import (
    analyze_identity_graph,
)
from entrawb.graph import (
    build_identity_graph,
)
from entrawb.ingestion import (
    ingest_tenant_export,
)
from entrawb.models import (
    EntraError,
    IdentityEdge,
    IdentityGraph,
    IdentityNode,
)
from entrawb.reporting import render_json_report, render_markdown_report
from entrawb.validation import validate_graph_artifact, validate_report_artifact

FIXTURE_AS_OF = datetime(2026, 9, 30, 18, tzinfo=UTC)


@pytest.fixture
def contoso_manifest_path() -> Path:
    return PLUGIN_ROOT / "fixtures" / "tenants" / "contoso-corp" / "manifest.json"


def test_ingestion_and_hash_verification(contoso_manifest_path: Path):
    """Test successful ingestion of tenant export and hash verification."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    assert manifest["tenant_id"] == "tenant-contoso-01"
    assert "users" in sources
    assert "agent_blueprints" in sources
    assert "agent_identities" in sources
    assert len(sources["users"]["data"]) == 3


def test_ingestion_hash_mismatch(tmp_path: Path):
    """Test that ingestion strictly fails if SHA-256 digest mismatches."""
    data_file = tmp_path / "users.json"
    data_file.write_text("[]\n", encoding="utf-8")

    manifest = {
        "schema_version": "entra.export-manifest/v1",
        "tenant_id": "test-tenant",
        "tenant_name": "Test",
        "exported_at": "2026-09-30T00:00:00Z",
        "sources": [
            {
                "source_id": "users",
                "path": "users.json",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "completeness": "full",
            }
        ],
    }
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EntraError, match="SHA-256 mismatch"):
        ingest_tenant_export(manifest_file)


def test_ingestion_missing_file(tmp_path: Path):
    """A missing source is recorded as unknown coverage, not an empty export."""
    manifest = {
        "schema_version": "entra.export-manifest/v1",
        "tenant_id": "test-tenant",
        "tenant_name": "Test",
        "exported_at": "2026-09-30T00:00:00Z",
        "sources": [
            {
                "source_id": "users",
                "path": "nonexistent.json",
                "sha256": "abc",
                "completeness": "full",
            }
        ],
    }
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    loaded_manifest, sources = ingest_tenant_export(manifest_file)
    assert sources["users"]["available"] is False
    graph = build_identity_graph(loaded_manifest, sources, as_of=FIXTURE_AS_OF)
    assert graph.source_coverage["users"]["status"] == "unknown"
    assert graph.source_coverage["users"]["reason"] == "missing_file"
    assert graph.source_coverage["groups"]["reason"] == "not_listed"
    assert graph.to_dict()["source_coverage"]["users"]["path"] == "nonexistent.json"


def test_fresh_and_stale_snapshot_policy(contoso_manifest_path: Path):
    """Only a complete export no older than 24 hours supports current paths."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    fresh_graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    assert all(item["status"] == "fresh" for item in fresh_graph.source_coverage.values())
    assert all(edge["evidence_status"] == "fresh" for edge in fresh_graph.to_dict()["edges"])
    assert analyze_identity_graph(fresh_graph)

    stale_graph = build_identity_graph(manifest, sources, as_of=datetime(2026, 10, 2, 12, tzinfo=UTC))
    assert all(item["reason"] == "stale" for item in stale_graph.source_coverage.values())
    assert not analyze_identity_graph(stale_graph)
    stale_edges = stale_graph.to_dict()["edges"]
    assert stale_edges and all(edge["evidence_status"] == "unknown" for edge in stale_edges)
    assert "stale" in stale_edges[0]["evidence_reasons"]
    report = render_json_report(stale_graph, [])
    assert report["source_coverage"]["users"]["reason"] == "stale"
    assert "Evidence coverage is unknown" in render_markdown_report(stale_graph, [])


def test_fractional_assessment_time_keeps_fresh_source_valid(contoso_manifest_path: Path):
    """Export validation uses the same timestamp precision as freshness classification."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    for entry in manifest["sources"]:
        if entry["source_id"] == "users":
            entry["exported_at"] = "2026-09-30T18:00:00.250Z"
    graph = build_identity_graph(
        manifest,
        sources,
        as_of=datetime(2026, 9, 30, 18, 0, 0, 500000, tzinfo=UTC),
    )
    assert graph.source_coverage["users"]["status"] == "fresh"
    assert graph.assessed_at == "2026-09-30T18:00:00.500000Z"
    assert graph.to_dict()["assessed_at"] == graph.assessed_at
    assert render_json_report(graph, analyze_identity_graph(graph))["assessed_at"] == graph.assessed_at


def test_markdown_rejects_hypotheses_from_stale_snapshot(contoso_manifest_path: Path):
    """Prior hypotheses cannot be rendered as current after their exports age out."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    fresh_graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    prior_hypotheses = analyze_identity_graph(fresh_graph)
    assert prior_hypotheses

    stale_graph = build_identity_graph(manifest, sources, as_of=datetime(2026, 10, 11, 12, tzinfo=UTC))
    assert not analyze_identity_graph(stale_graph)
    with pytest.raises(EntraError, match="has no fresh principal"):
        render_markdown_report(stale_graph, prior_hypotheses)


def test_per_source_staleness_marks_derived_paths_unknown(contoso_manifest_path: Path):
    """A stale role export taints direct and inherited role paths only."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    sources["role_assignments"]["data"].append(
        {
            "id": "ra-group-test",
            "principal_id": "group-ai-engineers-01",
            "role_definition_name": "Reader",
            "resource_id": "res-customer-storage-01",
            "scope": "/subscriptions/sub-01/resourceGroups/rg-ai",
        }
    )
    for entry in manifest["sources"]:
        if entry["source_id"] == "role_assignments":
            entry["exported_at"] = "2026-09-28T12:00:00Z"
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    assert graph.source_coverage["role_assignments"]["reason"] == "stale"
    exported = {edge["edge_id"]: edge for edge in graph.to_dict()["edges"]}
    assert exported["grant-broad-directory-01"]["evidence_status"] == "fresh"
    role_edges = [edge for edge in exported.values() if "role_assignments" in edge["evidence_sources"]]
    assert role_edges and all(edge["evidence_status"] == "unknown" for edge in role_edges)
    assert any(edge["grant_type"] == "inherited" for edge in role_edges)
    assert not any(h.category == "privileged_managed_identity" for h in analyze_identity_graph(graph))


@pytest.mark.parametrize(
    ("timestamp", "completeness", "reason"),
    [
        ("bad timestamp", "full", "invalid_timestamp"),
        ("20260930T180000+00:00", "full", "invalid_timestamp"),
        ("2026-10-01T00:00:00Z", "full", "future_timestamp"),
        ("2026-09-30T12:00:00Z", "partial", "incomplete"),
    ],
)
def test_unusable_source_metadata_is_unknown(
    contoso_manifest_path: Path, timestamp: str, completeness: str, reason: str
):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    for entry in manifest["sources"]:
        if entry["source_id"] == "oauth_grants":
            entry["exported_at"] = timestamp
            entry["completeness"] = completeness
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    assert graph.source_coverage["oauth_grants"]["reason"] == reason
    assert not any(h.category == "broad_app_consent" for h in analyze_identity_graph(graph))


def test_non_string_source_timestamp_stays_unknown_and_report_valid(contoso_manifest_path: Path):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    for entry in manifest["sources"]:
        if entry["source_id"] == "oauth_grants":
            entry["exported_at"] = 123
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    assert graph.source_coverage["oauth_grants"]["reason"] == "invalid_timestamp"
    report = render_json_report(graph, analyze_identity_graph(graph))
    for name, document in (("graph", graph.to_dict()), ("report", report)):
        schema = json.loads((PLUGIN_ROOT / "schemas" / f"{name}.v2.schema.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)


def test_entity_typing_and_graph_construction(contoso_manifest_path: Path):
    """Verify distinct principal classifications and that types are never inferred from display names."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources)

    # Check node types
    node_types = {n.node_type for n in graph.nodes.values()}
    assert "user" in node_types
    assert "group" in node_types
    assert "app_registration" in node_types
    assert "service_principal" in node_types
    assert "managed_identity" in node_types
    assert "agent_blueprint" in node_types
    assert "agent_identity" in node_types
    assert "federated_credential" in node_types
    assert "directory_role" in node_types
    assert "resource" in node_types

    # Specifically check Agent Blueprint vs Instantiated Agent ID
    bp_node = graph.nodes["blueprint-support-bot-01"]
    assert bp_node.node_type == "agent_blueprint"
    assert bp_node.properties["intended_privilege"] == "read_only"

    agent_node = graph.nodes["agent-id-support-bot-01"]
    assert agent_node.node_type == "agent_identity"
    assert agent_node.properties["blueprint_id"] == "blueprint-support-bot-01"

    # Check Legacy Foundry service principal
    sp_foundry = graph.nodes["sp-legacy-foundry-02"]
    assert sp_foundry.node_type == "service_principal"
    assert sp_foundry.properties["is_legacy_foundry_principal"] is True

    # Check Managed Identity
    mi_node = graph.nodes["mi-rag-worker-01"]
    assert mi_node.node_type == "managed_identity"
    assert mi_node.properties["identity_type"] == "UserAssigned"


def test_pim_state_and_grant_types(contoso_manifest_path: Path):
    """Verify distinction between direct vs inherited grants and active vs eligible PIM states."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources)

    # Alice has eligible Global Admin
    alice_role = next(
        e for e in graph.edges if e.source_id == "user-alice-01" and e.relation == "assigned_directory_role"
    )
    assert alice_role.pim_state == "eligible"
    assert alice_role.grant_type == "direct"

    # Charlie has active Global Admin
    charlie_role = next(
        e for e in graph.edges if e.source_id == "user-guest-charlie-03" and e.relation == "assigned_directory_role"
    )
    assert charlie_role.pim_state == "active"
    assert charlie_role.grant_type == "direct"

    # OAuth grants: autonomous vs delegated OBO
    daemon_grant = next(e for e in graph.edges if e.edge_id == "grant-broad-directory-01")
    assert daemon_grant.grant_type == "application_autonomous"

    user_grant = next(e for e in graph.edges if e.edge_id == "grant-delegated-user-02")
    assert user_grant.grant_type == "delegated_obo"


def test_exposure_hypotheses_generation(contoso_manifest_path: Path):
    """Test detection of all 6 priority exposure categories."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    hypotheses = analyze_identity_graph(graph)

    categories = {h.category for h in hypotheses}
    assert "broad_app_consent" in categories
    assert "ownerless_principal" in categories
    assert "stale_federated_trust" in categories
    assert "privileged_managed_identity" in categories
    assert "agent_privilege_mismatch" in categories
    assert "cross_tenant_exposure" in categories

    # 1. Broad App Consent
    h_consent = next(h for h in hypotheses if h.category == "broad_app_consent")
    assert h_consent.severity == "critical"
    assert "Directory.AccessAsUser.All" in h_consent.description

    # 2. Stale / Wildcard Federated Trust
    h_fed = next(h for h in hypotheses if h.category == "stale_federated_trust")
    assert h_fed.severity == "critical"
    assert "wildcard" in h_fed.description

    # 3. Agent Privilege Mismatch
    h_agent = next(h for h in hypotheses if h.category == "agent_privilege_mismatch")
    assert h_agent.severity == "critical"
    assert "read_only" in h_agent.description
    assert "Contributor" in h_agent.description

    # 4. Privileged Managed Identity
    h_mi = next(h for h in hypotheses if h.category == "privileged_managed_identity")
    assert h_mi.severity == "high"
    assert "Owner" in h_mi.description

    # 5. Cross Tenant Exposure
    h_cross = next(h for h in hypotheses if h.category == "cross_tenant_exposure")
    assert h_cross.severity == "high"
    assert "tenant-fabrikam-02" in h_cross.description


def test_cross_tenant_isolation():
    """Verify that cross-tenant principals are correctly flagged and isolated."""
    nodes = {
        "user-external-99": IdentityNode(
            node_id="user-external-99",
            node_type="user",
            display_name="External Contractor",
            tenant_id="foreign-tenant-uuid",
            properties={"is_guest": True},
            evidence_source="users",
        ),
        "role-sec-admin": IdentityNode(
            node_id="role-sec-admin",
            node_type="directory_role",
            display_name="Security Administrator",
            tenant_id="local-tenant-uuid",
            evidence_source="directory_roles",
        ),
    }
    edges = [
        IdentityEdge(
            edge_id="edge-cross-admin",
            source_id="user-external-99",
            target_id="role-sec-admin",
            relation="assigned_directory_role",
            grant_type="direct",
            scope="tenant",
            provenance="test",
            evidence_sources=("role_assignments",),
        )
    ]
    without_coverage = IdentityGraph(tenant_id="local-tenant-uuid", nodes=nodes, edges=edges)
    assert without_coverage.node_evidence(nodes["user-external-99"]) == ("unknown", ["missing_coverage"])
    assert without_coverage.edge_evidence(edges[0])[0] == "unknown"
    assert not analyze_identity_graph(without_coverage)

    coverage = {
        source_id: {"status": "fresh", "reason": None} for source_id in ("users", "directory_roles", "role_assignments")
    }
    graph = IdentityGraph(
        tenant_id="local-tenant-uuid",
        nodes=nodes,
        edges=edges,
        source_coverage=coverage,
        assessed_at=FIXTURE_AS_OF.isoformat(),
    )
    hypotheses = analyze_identity_graph(graph)

    cross_hyp = [h for h in hypotheses if h.category == "cross_tenant_exposure"]
    assert len(cross_hyp) == 1
    assert cross_hyp[0].principal_id == "user-external-99"
    assert "foreign-tenant-uuid" in cross_hyp[0].description


def test_unattributed_evidence_is_unknown_even_with_fresh_coverage():
    node = IdentityNode("user-1", "user", "User", "tenant-1")
    graph = IdentityGraph(
        tenant_id="tenant-1",
        nodes={node.node_id: node},
        edges=[],
        source_coverage={"users": {"status": "fresh", "reason": None}},
    )
    assert graph.node_evidence(node) == ("unknown", ["unattributed_source"])


def test_output_schemas_require_freshness_evidence(contoso_manifest_path: Path):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    graph_doc = graph.to_dict()
    report_doc = render_json_report(graph, analyze_identity_graph(graph))
    validate_graph_artifact(graph_doc)
    validate_report_artifact(report_doc)
    for name, document in (("graph", graph_doc), ("report", report_doc)):
        schema = json.loads((PLUGIN_ROOT / "schemas" / f"{name}.v2.schema.json").read_text())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        validator.validate(document)
        for field in ("assessed_at", "max_age_hours", "source_coverage"):
            missing = deepcopy(document)
            del missing[field]
            assert not validator.is_valid(missing), field
        wrong_age = deepcopy(document)
        wrong_age["max_age_hours"] = 48
        assert not validator.is_valid(wrong_age)
        bad_time = deepcopy(document)
        bad_time["assessed_at"] = "not a timestamp"
        assert not validator.is_valid(bad_time)
        no_sources = deepcopy(document)
        no_sources["source_coverage"] = {}
        assert not validator.is_valid(no_sources)
        if name == "graph":
            for key, member in (("nodes", "evidence_source"), ("edges", "evidence_sources")):
                missing = deepcopy(document)
                del missing[key][0][member]
                assert not validator.is_valid(missing), member
        else:
            for member in ("evidence_status", "evidence_sources"):
                missing = deepcopy(document)
                del missing["hypotheses"][0][member]
                assert not validator.is_valid(missing), member


def test_output_schemas_reject_conflicting_freshness_states(contoso_manifest_path: Path):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    for name, document in (
        ("graph", graph.to_dict()),
        ("report", render_json_report(graph, analyze_identity_graph(graph))),
    ):
        schema = json.loads((PLUGIN_ROOT / "schemas" / f"{name}.v2.schema.json").read_text())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for field, value in (
            ("reason", "stale"),
            ("completeness", "partial"),
            ("exported_at", "not-a-timestamp"),
        ):
            contradictory = deepcopy(document)
            contradictory["source_coverage"]["users"][field] = value
            assert not validator.is_valid(contradictory), (name, field)
        unexplained = deepcopy(document)
        unexplained["source_coverage"]["users"].update(status="unknown", reason=None)
        assert not validator.is_valid(unexplained), name
        if name == "graph":
            for key in ("nodes", "edges"):
                contradictory = deepcopy(document)
                contradictory[key][0].update(evidence_status="fresh", evidence_reasons=["stale"])
                assert not validator.is_valid(contradictory), key
                unexplained = deepcopy(document)
                unexplained[key][0].update(evidence_status="unknown", evidence_reasons=[])
                assert not validator.is_valid(unexplained), key


def test_output_schemas_reject_untraceable_provenance(contoso_manifest_path: Path):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    for name, document in (
        ("graph", graph.to_dict()),
        ("report", render_json_report(graph, analyze_identity_graph(graph))),
    ):
        schema = json.loads((PLUGIN_ROOT / "schemas" / f"{name}.v2.schema.json").read_text())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        assert validator.is_valid(document)
        extra_coverage = deepcopy(document)
        extra_coverage["source_coverage"]["invented_source"] = deepcopy(extra_coverage["source_coverage"]["users"])
        assert not validator.is_valid(extra_coverage), name
        if name == "graph":
            node_index = next(
                index
                for index, node in enumerate(document["nodes"])
                if node["node_type"] != "tenant" and node["evidence_status"] == "fresh"
            )
            for source_id in (None, "invented_source"):
                bad_node = deepcopy(document)
                bad_node["nodes"][node_index]["evidence_source"] = source_id
                assert not validator.is_valid(bad_node), source_id
            tenant_index = next(index for index, node in enumerate(document["nodes"]) if node["node_type"] == "tenant")
            bad_tenant = deepcopy(document)
            bad_tenant["nodes"][tenant_index]["evidence_source"] = "users"
            assert not validator.is_valid(bad_tenant)
            edge_index = next(
                index for index, edge in enumerate(document["edges"]) if edge["evidence_status"] == "fresh"
            )
            bad_edge = deepcopy(document)
            bad_edge["edges"][edge_index]["evidence_sources"] = ["invented_source"]
            assert not validator.is_valid(bad_edge)
        else:
            bad_hypothesis = deepcopy(document)
            bad_hypothesis["hypotheses"][0]["evidence_sources"] = ["invented_source"]
            assert not validator.is_valid(bad_hypothesis)


def test_cross_object_validation_rejects_fresh_claims_from_unknown_sources(
    contoso_manifest_path: Path,
):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    graph_doc = graph.to_dict()
    report_doc = render_json_report(graph, analyze_identity_graph(graph))

    node = next(
        item for item in graph_doc["nodes"] if item["node_type"] != "tenant" and item["evidence_status"] == "fresh"
    )
    bad_graph = deepcopy(graph_doc)
    bad_graph["source_coverage"][node["evidence_source"]].update(status="unknown", reason="stale")
    graph_schema = json.loads((PLUGIN_ROOT / "schemas" / "graph.v2.schema.json").read_text())
    assert Draft202012Validator(graph_schema, format_checker=FormatChecker()).is_valid(bad_graph)
    with pytest.raises(EntraError, match="non-fresh source"):
        validate_graph_artifact(bad_graph)

    bad_report = deepcopy(report_doc)
    source_id = bad_report["hypotheses"][0]["evidence_sources"][0]
    bad_report["source_coverage"][source_id].update(status="unknown", reason="stale")
    report_schema = json.loads((PLUGIN_ROOT / "schemas" / "report.v2.schema.json").read_text())
    assert Draft202012Validator(report_schema, format_checker=FormatChecker()).is_valid(bad_report)
    with pytest.raises(EntraError, match="non-fresh source"):
        validate_report_artifact(bad_report)


def test_markdown_report_escapes_export_derived_text(contoso_manifest_path: Path):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    hostile = "name|column\n## Forged heading <details>`code`"
    hypothesis = replace(
        analyze_identity_graph(graph)[0],
        hypothesis_id=hostile,
        principal_name=hostile,
        principal_type=hostile,
        description=hostile,
        missing_evidence=(hostile,),
        recommended_action=hostile,
    )
    graph = replace(graph, tenant_id=hostile)
    report = render_markdown_report(graph, [hypothesis])
    assert hostile not in report
    assert "## Forged heading" not in report
    assert "<details>" not in report
    assert "&#124;" in report
    assert "&#60;details&#62;" in report
    assert "name&#124;column" in report


def test_v1_schemas_remain_compatible_with_existing_artifacts(contoso_manifest_path: Path):
    """Keep accepting the provenance-bearing v1 artifacts emitted before v2."""
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    legacy_graph = graph.to_dict()
    legacy_graph["schema_version"] = "entra.identity-graph/v1"
    legacy_report = render_json_report(graph, analyze_identity_graph(graph))
    legacy_report["schema_version"] = "entra.identity-report/v1"
    for name, document in (("graph", legacy_graph), ("report", legacy_report)):
        v1 = json.loads((PLUGIN_ROOT / "schemas" / f"{name}.schema.json").read_text())
        v2 = json.loads((PLUGIN_ROOT / "schemas" / f"{name}.v2.schema.json").read_text())
        Draft202012Validator(v1, format_checker=FormatChecker()).validate(document)
        assert not Draft202012Validator(v2, format_checker=FormatChecker()).is_valid(document)


def test_manual_graph_without_freshness_metadata_cannot_be_exported():
    """A caller cannot bypass the normal builder and emit an unbounded claim."""
    graph = IdentityGraph(tenant_id="tenant-1", nodes={}, edges=[])
    with pytest.raises(EntraError, match="assessment time"):
        graph.to_dict()
    with pytest.raises(EntraError, match="assessment time"):
        render_json_report(graph, [])
    with pytest.raises(EntraError, match="assessment time"):
        render_markdown_report(graph, [])
    graph = replace(graph, assessed_at="2026-09-30T18:00:00Z")
    with pytest.raises(EntraError, match="every Entra source"):
        graph.to_dict()
    with pytest.raises(EntraError, match="every Entra source"):
        render_json_report(graph, [])
    with pytest.raises(EntraError, match="every Entra source"):
        render_markdown_report(graph, [])


def test_forged_fresh_source_outside_assessment_window_cannot_be_exported(contoso_manifest_path: Path):
    manifest, sources = ingest_tenant_export(contoso_manifest_path)
    graph = build_identity_graph(manifest, sources, as_of=FIXTURE_AS_OF)
    coverage = deepcopy(graph.source_coverage)
    coverage["users"].update(status="fresh", reason=None, exported_at="2026-09-28T18:00:00Z")
    graph = replace(graph, source_coverage=coverage)
    with pytest.raises(EntraError, match="outside the assessment window"):
        graph.to_dict()
    with pytest.raises(EntraError, match="outside the assessment window"):
        render_json_report(graph, [])


def test_cli_execution_and_reports(contoso_manifest_path: Path, tmp_path: Path):
    """Test CLI commands for analyze and graph export."""
    from entrawb.cli import main

    # 1. Test markdown report output
    md_output = tmp_path / "report.md"
    exit_code = main(["analyze", "--manifest", str(contoso_manifest_path), "--output", str(md_output)])
    assert exit_code == 0
    assert md_output.exists()
    content = md_output.read_text(encoding="utf-8")
    assert "# Entra Identity & Agent Exposure Review" in content
    assert "Prioritized Review Hypotheses" in content

    # 2. Test JSON report output
    json_output = tmp_path / "report.json"
    exit_code = main(["analyze", "--manifest", str(contoso_manifest_path), "--json", "--output", str(json_output)])
    assert exit_code == 0
    assert json_output.exists()
    data = json.loads(json_output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "entra.identity-report/v2"
    assert data["hypotheses"] == []
    assert data["source_coverage"]["users"]["reason"] == "stale"

    # 3. Test graph export
    graph_output = tmp_path / "graph.json"
    exit_code = main(["graph", "--manifest", str(contoso_manifest_path), "--output", str(graph_output)])
    assert exit_code == 0
    assert graph_output.exists()
    graph_data = json.loads(graph_output.read_text(encoding="utf-8"))
    assert graph_data["schema_version"] == "entra.identity-graph/v2"
    assert len(graph_data["nodes"]) >= 10
    assert graph_data["source_coverage"]["users"]["reason"] == "stale"
