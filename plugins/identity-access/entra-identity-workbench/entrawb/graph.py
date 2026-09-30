"""Build and normalize typed identity graphs from Entra export sources."""

from __future__ import annotations

from typing import Any

from .models import EntraError, IdentityEdge, IdentityGraph, IdentityNode


def build_identity_graph(manifest: dict[str, Any], sources: dict[str, Any]) -> IdentityGraph:
    """Construct a typed, directed identity graph from validated export sources."""
    tenant_id = str(manifest["tenant_id"])
    nodes: dict[str, IdentityNode] = {}
    edges: list[IdentityEdge] = []

    # Root tenant node
    nodes[tenant_id] = IdentityNode(
        node_id=tenant_id,
        node_type="tenant",
        display_name=str(manifest.get("tenant_name", tenant_id)),
        tenant_id=tenant_id,
        properties={"exported_at": manifest.get("exported_at")},
    )

    # 1. Users
    users_data = sources.get("users", {}).get("data", [])
    for u in users_data:
        uid = str(u["id"])
        u_tenant = str(u.get("tenant_id", tenant_id))
        nodes[uid] = IdentityNode(
            node_id=uid,
            node_type="user",
            display_name=str(u.get("display_name", uid)),
            tenant_id=u_tenant,
            properties={
                "user_principal_name": u.get("user_principal_name"),
                "is_guest": bool(u.get("is_guest", False)),
                "account_enabled": bool(u.get("account_enabled", True)),
            },
        )

    # 2. Groups
    groups_data = sources.get("groups", {}).get("data", [])
    for g in groups_data:
        gid = str(g["id"])
        nodes[gid] = IdentityNode(
            node_id=gid,
            node_type="group",
            display_name=str(g.get("display_name", gid)),
            tenant_id=tenant_id,
            properties={
                "is_role_assignable": bool(g.get("is_role_assignable", False)),
                "security_enabled": bool(g.get("security_enabled", True)),
            },
        )
        for m_id in g.get("members", []):
            edges.append(
                IdentityEdge(
                    edge_id=f"edge-member-{m_id}-{gid}",
                    source_id=str(m_id),
                    target_id=gid,
                    relation="member_of",
                    grant_type="direct",
                    scope=f"group:{gid}",
                    provenance=f"groups.json:{gid}",
                )
            )

    # 3. Applications
    apps_data = sources.get("applications", {}).get("data", [])
    for app in apps_data:
        app_id = str(app["id"])
        nodes[app_id] = IdentityNode(
            node_id=app_id,
            node_type="app_registration",
            display_name=str(app.get("display_name", app_id)),
            tenant_id=tenant_id,
            properties={
                "client_id": app.get("client_id"),
                "sign_in_audience": app.get("sign_in_audience", "AzureADMyOrg"),
                "has_credentials": bool(app.get("has_credentials", False)),
                "credential_count": int(app.get("credential_count", 0)),
            },
        )
        for owner_id in app.get("owners", []):
            edges.append(
                IdentityEdge(
                    edge_id=f"edge-owns-{owner_id}-{app_id}",
                    source_id=str(owner_id),
                    target_id=app_id,
                    relation="owns",
                    grant_type="direct",
                    scope=f"app:{app_id}",
                    provenance=f"applications.json:{app_id}",
                )
            )

    # 4. Service Principals
    sp_data = sources.get("service_principals", {}).get("data", [])
    for sp in sp_data:
        sp_id = str(sp["id"])
        sp_type = str(sp.get("service_principal_type", "Application"))
        nodes[sp_id] = IdentityNode(
            node_id=sp_id,
            node_type="service_principal",
            display_name=str(sp.get("display_name", sp_id)),
            tenant_id=tenant_id,
            properties={
                "app_id": sp.get("app_id"),
                "service_principal_type": sp_type,
                "account_enabled": bool(sp.get("account_enabled", True)),
                "is_legacy_foundry_principal": bool(sp.get("is_legacy_foundry_principal", False)),
            },
        )
        for owner_id in sp.get("owners", []):
            edges.append(
                IdentityEdge(
                    edge_id=f"edge-owns-{owner_id}-{sp_id}",
                    source_id=str(owner_id),
                    target_id=sp_id,
                    relation="owns",
                    grant_type="direct",
                    scope=f"sp:{sp_id}",
                    provenance=f"service_principals.json:{sp_id}",
                )
            )

    # 5. Managed Identities
    mi_data = sources.get("managed_identities", {}).get("data", [])
    for mi in mi_data:
        mi_id = str(mi["id"])
        nodes[mi_id] = IdentityNode(
            node_id=mi_id,
            node_type="managed_identity",
            display_name=str(mi.get("display_name", mi_id)),
            tenant_id=tenant_id,
            properties={
                "identity_type": mi.get("identity_type", "UserAssigned"),
                "associated_resource_id": mi.get("associated_resource_id"),
                "client_id": mi.get("client_id"),
            },
        )

    # 6. Federated Credentials
    fed_data = sources.get("federated_credentials", {}).get("data", [])
    for fed in fed_data:
        fed_id = str(fed["id"])
        target_sp = str(fed["service_principal_id"])
        nodes[fed_id] = IdentityNode(
            node_id=fed_id,
            node_type="federated_credential",
            display_name=str(fed.get("name", fed_id)),
            tenant_id=tenant_id,
            properties={
                "issuer": fed.get("issuer"),
                "subject": fed.get("subject"),
                "audiences": fed.get("audiences", []),
                "is_wildcard": bool("*" in fed.get("subject", "")),
            },
        )
        edges.append(
            IdentityEdge(
                edge_id=f"edge-fed-{fed_id}-{target_sp}",
                source_id=fed_id,
                target_id=target_sp,
                relation="federated_with",
                grant_type="direct",
                scope=f"sp:{target_sp}",
                provenance=f"federated_credentials.json:{fed_id}",
            )
        )

    # 7. Agent Blueprints (Foundry / Agent ID declarative specifications)
    blueprints_data = sources.get("agent_blueprints", {}).get("data", [])
    for bp in blueprints_data:
        bp_id = str(bp["id"])
        nodes[bp_id] = IdentityNode(
            node_id=bp_id,
            node_type="agent_blueprint",
            display_name=str(bp.get("name", bp_id)),
            tenant_id=tenant_id,
            properties={
                "framework": bp.get("framework", "Microsoft Foundry"),
                "model": bp.get("model"),
                "declared_tools": bp.get("declared_tools", []),
                "declared_resources": bp.get("declared_resources", []),
                "intended_privilege": bp.get("intended_privilege", "read_only"),
            },
        )

    # 8. Agent Identities (Instantiated Entra Agent ID principals)
    agent_id_data = sources.get("agent_identities", {}).get("data", [])
    for ai in agent_id_data:
        agent_id = str(ai["id"])
        bp_id = str(ai["blueprint_id"])
        sponsor_id = str(ai["sponsor_id"])

        nodes[agent_id] = IdentityNode(
            node_id=agent_id,
            node_type="agent_identity",
            display_name=str(ai.get("display_name", agent_id)),
            tenant_id=tenant_id,
            properties={
                "blueprint_id": bp_id,
                "sponsor_id": sponsor_id,
                "agent_type": "EntraAgentID",
                "active_status": ai.get("active_status", "active"),
            },
        )

        # Edge: Agent Identity instantiates Agent Blueprint
        edges.append(
            IdentityEdge(
                edge_id=f"edge-instantiates-{agent_id}-{bp_id}",
                source_id=agent_id,
                target_id=bp_id,
                relation="instantiates",
                grant_type="direct",
                scope=f"blueprint:{bp_id}",
                provenance=f"agent_identities.json:{agent_id}",
            )
        )

        # Edge: Agent Identity is sponsored by human/managed identity
        edges.append(
            IdentityEdge(
                edge_id=f"edge-sponsored-{agent_id}-{sponsor_id}",
                source_id=agent_id,
                target_id=sponsor_id,
                relation="sponsored_by",
                grant_type="direct",
                scope=f"sponsor:{sponsor_id}",
                provenance=f"agent_identities.json:{agent_id}",
            )
        )

    # 9. Resources
    resources_data = sources.get("resources", {}).get("data", [])
    for r in resources_data:
        r_id = str(r["id"])
        nodes[r_id] = IdentityNode(
            node_id=r_id,
            node_type="resource",
            display_name=str(r.get("name", r_id)),
            tenant_id=tenant_id,
            properties={
                "resource_type": r.get("resource_type"),
                "subscription_id": r.get("subscription_id"),
                "resource_group": r.get("resource_group"),
                "is_critical": bool(r.get("is_critical", False)),
            },
        )

    # 10. Directory Roles (with PIM state: active vs eligible)
    dir_roles_data = sources.get("directory_roles", {}).get("data", [])
    for dr in dir_roles_data:
        role_id = str(dr["id"])
        role_name = str(dr.get("role_name", role_id))
        nodes[role_id] = IdentityNode(
            node_id=role_id,
            node_type="directory_role",
            display_name=role_name,
            tenant_id=tenant_id,
            properties={
                "is_privileged": bool(dr.get("is_privileged", False)),
                "description": dr.get("description", ""),
            },
        )
        for assignment in dr.get("assignments", []):
            principal_id = str(assignment["principal_id"])
            pim_state = str(assignment.get("pim_state", "active"))
            edges.append(
                IdentityEdge(
                    edge_id=f"edge-dir-role-{principal_id}-{role_id}",
                    source_id=principal_id,
                    target_id=role_id,
                    relation="assigned_directory_role",
                    grant_type="direct",
                    pim_state=pim_state,
                    scope="tenant",
                    provenance=f"directory_roles.json:{role_id}",
                )
            )

    # 11. Azure Role Assignments (Azure RBAC: direct vs inherited)
    rbac_data = sources.get("role_assignments", {}).get("data", [])
    for ra in rbac_data:
        ra_id = str(ra["id"])
        principal_id = str(ra["principal_id"])
        role_name = str(ra["role_definition_name"])
        target_resource = str(ra["resource_id"])
        grant_type = str(ra.get("grant_type", "direct"))
        scope = str(ra.get("scope", "subscription"))

        edges.append(
            IdentityEdge(
                edge_id=ra_id,
                source_id=principal_id,
                target_id=target_resource,
                relation="assigned_azure_role",
                grant_type=grant_type,
                scope=f"{role_name} on {scope}",
                provenance=f"role_assignments.json:{ra_id}",
                pim_state=ra.get("pim_state", "none"),
            )
        )

    # 12. OAuth Grants & API Permissions (delegated OBO vs autonomous app permissions)
    oauth_data = sources.get("oauth_grants", {}).get("data", [])
    for og in oauth_data:
        og_id = str(og["id"])
        principal_id = str(og["principal_id"])
        api_resource = str(og["api_name"])
        permission = str(og["permission"])
        grant_type = str(og.get("grant_type", "delegated_obo"))

        if api_resource not in nodes:
            nodes[api_resource] = IdentityNode(
                node_id=api_resource,
                node_type="resource",
                display_name=api_resource,
                tenant_id=tenant_id,
                properties={"resource_type": "api_resource"},
            )

        edges.append(
            IdentityEdge(
                edge_id=og_id,
                source_id=principal_id,
                target_id=api_resource,
                relation="consented_api_permission",
                grant_type=grant_type,
                scope=permission,
                provenance=f"oauth_grants.json:{og_id}",
            )
        )

    # Transitive Group Inheritance: compute inherited edges for group members
    group_memberships: dict[str, set[str]] = {}
    for edge in edges:
        if edge.relation == "member_of":
            group_memberships.setdefault(edge.source_id, set()).add(edge.target_id)

    # Propagate group direct assignments down to member principals
    inherited_edges: list[IdentityEdge] = []
    for edge in edges:
        if edge.relation in ("assigned_azure_role", "assigned_directory_role"):
            target_group = edge.source_id
            for member_id, groups in group_memberships.items():
                if target_group in groups:
                    inherited_edge_id = f"inherited-{edge.edge_id}-{member_id}"
                    inherited_edges.append(
                        IdentityEdge(
                            edge_id=inherited_edge_id,
                            source_id=member_id,
                            target_id=edge.target_id,
                            relation=edge.relation,
                            grant_type="inherited",
                            scope=edge.scope,
                            provenance=f"inherited_from:{target_group}",
                            pim_state=edge.pim_state,
                        )
                    )

    edges.extend(inherited_edges)

    return IdentityGraph(
        tenant_id=tenant_id,
        nodes=nodes,
        edges=edges,
        sources=sources,
    )
