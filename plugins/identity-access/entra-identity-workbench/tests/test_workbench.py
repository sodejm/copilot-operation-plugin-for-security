"""Comprehensive unit tests for the Entra Identity Workbench."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PLUGIN_ROOT.parent.parent

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from entrawb.analysis import analyze_identity_graph
from entrawb.graph import build_identity_graph
from entrawb.ingestion import ingest_tenant_export
from entrawb.models import EntraError, IdentityGraph, IdentityNode, IdentityEdge
from entrawb.reporting import render_json_report, render_markdown_report


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
    """Test that ingestion fails if source file is missing."""
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

    with pytest.raises(EntraError, match="Source file does not exist"):
        ingest_tenant_export(manifest_file)


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
        e for e in graph.edges
        if e.source_id == "user-alice-01" and e.relation == "assigned_directory_role"
    )
    assert alice_role.pim_state == "eligible"
    assert alice_role.grant_type == "direct"

    # Charlie has active Global Admin
    charlie_role = next(
        e for e in graph.edges
        if e.source_id == "user-guest-charlie-03" and e.relation == "assigned_directory_role"
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
    graph = build_identity_graph(manifest, sources)
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
        ),
        "role-sec-admin": IdentityNode(
            node_id="role-sec-admin",
            node_type="directory_role",
            display_name="Security Administrator",
            tenant_id="local-tenant-uuid",
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
        )
    ]
    graph = IdentityGraph(tenant_id="local-tenant-uuid", nodes=nodes, edges=edges)
    hypotheses = analyze_identity_graph(graph)

    cross_hyp = [h for h in hypotheses if h.category == "cross_tenant_exposure"]
    assert len(cross_hyp) == 1
    assert cross_hyp[0].principal_id == "user-external-99"
    assert "foreign-tenant-uuid" in cross_hyp[0].description


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
    assert data["schema_version"] == "entra.identity-report/v1"
    assert len(data["hypotheses"]) >= 6

    # 3. Test graph export
    graph_output = tmp_path / "graph.json"
    exit_code = main(["graph", "--manifest", str(contoso_manifest_path), "--output", str(graph_output)])
    assert exit_code == 0
    assert graph_output.exists()
    graph_data = json.loads(graph_output.read_text(encoding="utf-8"))
    assert graph_data["schema_version"] == "entra.identity-graph/v1"
    assert len(graph_data["nodes"]) >= 10
