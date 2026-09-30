"""Analyze Entra identity graphs to generate prioritized exposure hypotheses."""

from __future__ import annotations

from typing import Any

from .models import IdentityGraph, ReviewHypothesis

HIGH_RISK_PERMISSIONS = {
    "Directory.AccessAsUser.All": ("critical", "Full directory access impersonating any user"),
    "RoleManagement.ReadWrite.Directory": ("critical", "Can grant any directory role including Global Admin"),
    "AppRoleAssignment.ReadWrite.All": ("critical", "Can grant application permissions to arbitrary apps"),
    "Mail.ReadWrite": ("high", "Unrestricted access to read and modify all mailboxes"),
    "Files.ReadWrite.All": ("high", "Unrestricted read and write access across all SharePoint and OneDrive files"),
    "User.ReadWrite.All": ("high", "Can modify user accounts and reset credentials"),
}

PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Key Vault Administrator",
    "Storage Blob Data Owner",
}


def analyze_identity_graph(graph: IdentityGraph) -> list[ReviewHypothesis]:
    """Inspect identity graph nodes and edges to generate prioritized review hypotheses."""
    hypotheses: list[ReviewHypothesis] = []
    edges_by_source: dict[str, list[Any]] = {}
    edges_by_target: dict[str, list[Any]] = {}

    for edge in graph.edges:
        edges_by_source.setdefault(edge.source_id, []).append(edge)
        edges_by_target.setdefault(edge.target_id, []).append(edge)

    # 1. Broad App Consent Hypotheses
    for edge in graph.edges:
        if edge.relation == "consented_api_permission":
            perm = edge.scope
            principal = graph.nodes.get(edge.source_id)
            principal_name = principal.display_name if principal else edge.source_id
            principal_type = principal.node_type if principal else "unknown"

            if perm in HIGH_RISK_PERMISSIONS:
                severity, reason = HIGH_RISK_PERMISSIONS[perm]
                is_autonomous = edge.grant_type == "application_autonomous"
                if is_autonomous and severity == "high":
                    severity = "critical"

                hypotheses.append(
                    ReviewHypothesis(
                        hypothesis_id=f"HYP-CONSENT-{edge.edge_id}",
                        category="broad_app_consent",
                        severity=severity,
                        principal_id=edge.source_id,
                        principal_name=principal_name,
                        principal_type=principal_type,
                        description=(
                            f"Principal '{principal_name}' holds high-risk permission '{perm}' "
                            f"via {edge.grant_type}. {reason}."
                        ),
                        supporting_edges=(edge.edge_id,),
                        missing_evidence=(
                            "OAuth consent grant audit event",
                            "Historical API invocation frequency",
                        ),
                        recommended_action=(
                            f"Review and scope down permission '{perm}'; verify if least-privilege "
                            "delegated access or scoped resource access can replace tenant-wide consent."
                        ),
                    )
                )

    # 2. Ownerless Principals (App Registrations and Service Principals)
    for node in graph.nodes.values():
        if node.node_type in ("app_registration", "service_principal"):
            owner_edges = [
                e for e in edges_by_target.get(node.node_id, [])
                if e.relation == "owns"
            ]
            if not owner_edges:
                # Check if this principal holds active privileges
                outgoing = edges_by_source.get(node.node_id, [])
                has_privileges = any(
                    e.relation in ("assigned_azure_role", "assigned_directory_role", "consented_api_permission")
                    for e in outgoing
                )
                severity = "high" if has_privileges else "medium"
                supp_edges = tuple(e.edge_id for e in outgoing)

                hypotheses.append(
                    ReviewHypothesis(
                        hypothesis_id=f"HYP-OWNERLESS-{node.node_id}",
                        category="ownerless_principal",
                        severity=severity,
                        principal_id=node.node_id,
                        principal_name=node.display_name,
                        principal_type=node.node_type,
                        description=(
                            f"{node.node_type} '{node.display_name}' has no registered owner "
                            f"{'and holds active role assignments or API permissions' if has_privileges else 'in directory'}."
                        ),
                        supporting_edges=supp_edges,
                        missing_evidence=(
                            "Original app creation audit record",
                            "Current engineering custodian or team attribution",
                        ),
                        recommended_action=(
                            f"Assign a verified administrative owner or decommission orphaned {node.node_type}."
                        ),
                    )
                )

    # 3. Stale or Wildcard Federated Trust
    for node in graph.nodes.values():
        if node.node_type == "federated_credential":
            is_wildcard = node.properties.get("is_wildcard", False)
            subject = str(node.properties.get("subject", ""))
            fed_edges = [
                e for e in edges_by_source.get(node.node_id, [])
                if e.relation == "federated_with"
            ]
            supp_edges = tuple(e.edge_id for e in fed_edges)
            target_sp_id = fed_edges[0].target_id if fed_edges else "unknown"
            target_sp = graph.nodes.get(target_sp_id)
            target_sp_name = target_sp.display_name if target_sp else target_sp_id

            if is_wildcard:
                hypotheses.append(
                    ReviewHypothesis(
                        hypothesis_id=f"HYP-FED-WILDCARD-{node.node_id}",
                        category="stale_federated_trust",
                        severity="critical",
                        principal_id=target_sp_id,
                        principal_name=target_sp_name,
                        principal_type="service_principal",
                        description=(
                            f"Federated credential '{node.display_name}' uses wildcard subject pattern '{subject}' "
                            f"granting token exchange to untrusted or broad branches in external provider."
                        ),
                        supporting_edges=supp_edges,
                        missing_evidence=(
                            "External issuer OIDC token exchange logs",
                            "Explicit branch/environment claims",
                        ),
                        recommended_action=(
                            "Replace wildcard federated credential subject with exact repository environment or branch claim."
                        ),
                    )
                )

    # 4. Privileged Managed Identities
    for node in graph.nodes.values():
        if node.node_type == "managed_identity":
            outgoing = edges_by_source.get(node.node_id, [])
            for e in outgoing:
                if e.relation in ("assigned_azure_role", "assigned_directory_role"):
                    target_res = graph.nodes.get(e.target_id)
                    target_name = target_res.display_name if target_res else e.target_id
                    role_or_scope = e.scope

                    is_priv = any(r.lower() in role_or_scope.lower() or r.lower() in target_name.lower() for r in PRIVILEGED_ROLES)
                    if is_priv:
                        hypotheses.append(
                            ReviewHypothesis(
                                hypothesis_id=f"HYP-PRIV-MI-{e.edge_id}",
                                category="privileged_managed_identity",
                                severity="high",
                                principal_id=node.node_id,
                                principal_name=node.display_name,
                                principal_type=node.node_type,
                                description=(
                                    f"Managed identity '{node.display_name}' holds privileged role/scope "
                                    f"'{role_or_scope}' on '{target_name}'. Compromise of the hosting workload yields full control."
                                ),
                                supporting_edges=(e.edge_id,),
                                missing_evidence=(
                                    "Workload egress restriction policy",
                                    "Runtime token acquisition telemetry",
                                ),
                                recommended_action=(
                                    "Restrict managed identity role assignment to least privilege and narrow resource scope."
                                ),
                            )
                        )

    # 5. Agent-to-Tool / Resource Privilege Mismatch
    for node in graph.nodes.values():
        if node.node_type == "agent_identity":
            bp_id = str(node.properties.get("blueprint_id", ""))
            blueprint = graph.nodes.get(bp_id)
            intended_privilege = blueprint.properties.get("intended_privilege", "read_only") if blueprint else "unknown"

            # Check outgoing privileges assigned to the instantiated agent identity
            outgoing = edges_by_source.get(node.node_id, [])
            for e in outgoing:
                if e.relation in ("assigned_azure_role", "assigned_directory_role", "consented_api_permission"):
                    target_name = graph.nodes[e.target_id].display_name if e.target_id in graph.nodes else e.target_id
                    scope_or_role = e.scope

                    # Check if agent has write/admin privileges conflicting with read-only expectation
                    has_conflict = (
                        intended_privilege in ("read_only", "low") and
                        any(priv.lower() in scope_or_role.lower() or priv.lower() in target_name.lower() for priv in PRIVILEGED_ROLES)
                    )

                    if has_conflict or e.relation == "assigned_directory_role":
                        hypotheses.append(
                            ReviewHypothesis(
                                hypothesis_id=f"HYP-AGENT-MISMATCH-{e.edge_id}",
                                category="agent_privilege_mismatch",
                                severity="critical",
                                principal_id=node.node_id,
                                principal_name=node.display_name,
                                principal_type=node.node_type,
                                description=(
                                    f"Agent Identity '{node.display_name}' (blueprint: '{blueprint.display_name if blueprint else bp_id}') "
                                    f"has intended privilege '{intended_privilege}' but holds high-privilege assignment "
                                    f"'{scope_or_role}' on '{target_name}'."
                                ),
                                supporting_edges=(e.edge_id,),
                                missing_evidence=(
                                    "Agent invocation authorization logs",
                                    "Tool call policy gate definition",
                                ),
                                recommended_action=(
                                    f"Revoke privileged assignment '{scope_or_role}' from agent identity '{node.display_name}'; "
                                    "align runtime entitlements strictly with the declared blueprint."
                                ),
                            )
                        )

    # 6. Cross-Tenant Exposure
    for node in graph.nodes.values():
        if node.tenant_id != graph.tenant_id:
            # Foreign user or guest
            outgoing = edges_by_source.get(node.node_id, [])
            for e in outgoing:
                if e.relation in ("assigned_azure_role", "assigned_directory_role", "member_of"):
                    target_name = graph.nodes[e.target_id].display_name if e.target_id in graph.nodes else e.target_id
                    hypotheses.append(
                        ReviewHypothesis(
                            hypothesis_id=f"HYP-CROSS-TENANT-{e.edge_id}",
                            category="cross_tenant_exposure",
                            severity="high",
                            principal_id=node.node_id,
                            principal_name=node.display_name,
                            principal_type=node.node_type,
                            description=(
                                f"External/Cross-tenant principal '{node.display_name}' (tenant: '{node.tenant_id}') "
                                f"holds local assignment or membership '{e.relation}' with '{target_name}'."
                            ),
                            supporting_edges=(e.edge_id,),
                            missing_evidence=(
                                "Cross-tenant trust federation agreement",
                                "Guest lifecycle and conditional access review",
                            ),
                            recommended_action=(
                                f"Review external guest access for '{node.display_name}'; enforce tenant isolation "
                                "and require strict conditional access policies for external identities."
                            ),
                        )
                    )

    # Sort hypotheses by severity order: critical -> high -> medium -> low -> informational
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    hypotheses.sort(key=lambda h: (severity_order.get(h.severity, 5), h.category, h.hypothesis_id))

    return hypotheses
