"""Deterministic synthetic tenant fixture generator for Entra Identity Workbench."""

import hashlib
import json
from pathlib import Path

DIR = Path(__file__).resolve().parent / "tenants" / "contoso-corp"
DIR.mkdir(parents=True, exist_ok=True)


def write_json(filename: str, data: any) -> tuple[str, str]:
    content = json.dumps(data, indent=2) + "\n"
    path = DIR / filename
    path.write_text(content, encoding="utf-8")
    sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return filename, sha256


# 1. Users
users = [
    {
        "id": "user-alice-01",
        "display_name": "Alice Admin",
        "user_principal_name": "alice@contoso.com",
        "tenant_id": "tenant-contoso-01",
        "is_guest": False,
        "account_enabled": True
    },
    {
        "id": "user-bob-02",
        "display_name": "Bob Developer",
        "user_principal_name": "bob@contoso.com",
        "tenant_id": "tenant-contoso-01",
        "is_guest": False,
        "account_enabled": True
    },
    {
        "id": "user-guest-charlie-03",
        "display_name": "Charlie External",
        "user_principal_name": "charlie_fabrikam.com#EXT#@contoso.com",
        "tenant_id": "tenant-fabrikam-02",
        "is_guest": True,
        "account_enabled": True
    }
]
f_users, sha_users = write_json("users.json", users)

# 2. Groups
groups = [
    {
        "id": "group-ai-engineers-01",
        "display_name": "AI Platform Engineers",
        "is_role_assignable": True,
        "security_enabled": True,
        "members": ["user-bob-02"]
    }
]
f_groups, sha_groups = write_json("groups.json", groups)

# 3. Applications
apps = [
    {
        "id": "app-customer-portal-01",
        "display_name": "Contoso Customer Portal",
        "client_id": "00000001-0000-0000-0000-000000000001",
        "sign_in_audience": "AzureADMyOrg",
        "has_credentials": True,
        "credential_count": 2,
        "owners": ["user-alice-01"]
    },
    {
        "id": "app-ownerless-tool-02",
        "display_name": "Legacy Internal Tool",
        "client_id": "00000002-0000-0000-0000-000000000002",
        "sign_in_audience": "AzureADMyOrg",
        "has_credentials": True,
        "credential_count": 1,
        "owners": []
    }
]
f_apps, sha_apps = write_json("applications.json", apps)

# 4. Service Principals
sps = [
    {
        "id": "sp-customer-portal-01",
        "display_name": "Contoso Customer Portal SP",
        "app_id": "app-customer-portal-01",
        "service_principal_type": "Application",
        "account_enabled": True,
        "is_legacy_foundry_principal": False,
        "owners": ["user-alice-01"]
    },
    {
        "id": "sp-legacy-foundry-02",
        "display_name": "Foundry Legacy Agent SP",
        "app_id": "app-ownerless-tool-02",
        "service_principal_type": "LegacyFoundry",
        "account_enabled": True,
        "is_legacy_foundry_principal": True,
        "owners": ["user-alice-01"]
    },
    {
        "id": "sp-ownerless-daemon-03",
        "display_name": "Orphaned Sync Daemon",
        "app_id": "app-ownerless-tool-02",
        "service_principal_type": "Application",
        "account_enabled": True,
        "is_legacy_foundry_principal": False,
        "owners": []
    }
]
f_sps, sha_sps = write_json("service_principals.json", sps)

# 5. Managed Identities
mis = [
    {
        "id": "mi-rag-worker-01",
        "display_name": "uami-rag-inference-worker",
        "identity_type": "UserAssigned",
        "associated_resource_id": "/subscriptions/sub-01/resourceGroups/rg-ai/providers/Microsoft.Compute/virtualMachines/vm-rag",
        "client_id": "00000003-0000-0000-0000-000000000003"
    }
]
f_mis, sha_mis = write_json("managed_identities.json", mis)

# 6. Federated Credentials
feds = [
    {
        "id": "fed-cred-github-01",
        "name": "github-actions-deploy-wildcard",
        "service_principal_id": "sp-customer-portal-01",
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:contoso-corp/*:*",
        "audiences": ["api://AzureADTokenExchange"]
    }
]
f_feds, sha_feds = write_json("federated_credentials.json", feds)

# 7. Agent Blueprints
blueprints = [
    {
        "id": "blueprint-support-bot-01",
        "name": "Customer Support FAQ Blueprint",
        "framework": "Microsoft Foundry",
        "model": "gpt-4o",
        "declared_tools": ["search_knowledge_base", "read_customer_faq"],
        "declared_resources": ["res-customer-storage-01"],
        "intended_privilege": "read_only"
    }
]
f_bp, sha_bp = write_json("agent_blueprints.json", blueprints)

# 8. Agent Identities
agent_ids = [
    {
        "id": "agent-id-support-bot-01",
        "display_name": "agent-support-runtime-01",
        "blueprint_id": "blueprint-support-bot-01",
        "sponsor_id": "user-alice-01",
        "active_status": "active"
    }
]
f_ai, sha_ai = write_json("agent_identities.json", agent_ids)

# 9. Resources
resources = [
    {
        "id": "res-corp-keyvault-01",
        "name": "kv-contoso-secrets-prod",
        "resource_type": "Microsoft.KeyVault/vaults",
        "subscription_id": "sub-01",
        "resource_group": "rg-core",
        "is_critical": True
    },
    {
        "id": "res-customer-storage-01",
        "name": "stcontosopublicdata",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "subscription_id": "sub-01",
        "resource_group": "rg-ai",
        "is_critical": False
    }
]
f_res, sha_res = write_json("resources.json", resources)

# 10. Directory Roles
dir_roles = [
    {
        "id": "role-global-admin-01",
        "role_name": "Global Administrator",
        "is_privileged": True,
        "description": "Full access to all administrative features in Entra ID",
        "assignments": [
            {
                "principal_id": "user-alice-01",
                "pim_state": "eligible"
            },
            {
                "principal_id": "user-guest-charlie-03",
                "pim_state": "active"
            }
        ]
    }
]
f_dr, sha_dr = write_json("directory_roles.json", dir_roles)

# 11. Azure Role Assignments
role_assignments = [
    {
        "id": "ra-agent-mismatch-01",
        "principal_id": "agent-id-support-bot-01",
        "role_definition_name": "Contributor",
        "resource_id": "res-corp-keyvault-01",
        "grant_type": "direct",
        "scope": "/subscriptions/sub-01/resourceGroups/rg-core/providers/Microsoft.KeyVault/vaults/kv-contoso-secrets-prod"
    },
    {
        "id": "ra-mi-privileged-02",
        "principal_id": "mi-rag-worker-01",
        "role_definition_name": "Owner",
        "resource_id": "res-customer-storage-01",
        "grant_type": "direct",
        "scope": "/subscriptions/sub-01/resourceGroups/rg-ai"
    }
]
f_ra, sha_ra = write_json("role_assignments.json", role_assignments)

# 12. OAuth Grants
oauth_grants = [
    {
        "id": "grant-broad-directory-01",
        "principal_id": "sp-ownerless-daemon-03",
        "api_name": "Microsoft Graph",
        "permission": "Directory.AccessAsUser.All",
        "grant_type": "application_autonomous"
    },
    {
        "id": "grant-delegated-user-02",
        "principal_id": "user-bob-02",
        "api_name": "Microsoft Graph",
        "permission": "User.Read",
        "grant_type": "delegated_obo"
    }
]
f_og, sha_og = write_json("oauth_grants.json", oauth_grants)

# Manifest
manifest = {
    "schema_version": "entra.export-manifest/v1",
    "tenant_id": "tenant-contoso-01",
    "tenant_name": "Contoso Corporation",
    "exported_at": "2026-09-30T12:00:00Z",
    "sources": [
        {"source_id": "users", "path": f_users, "sha256": sha_users, "completeness": "full"},
        {"source_id": "groups", "path": f_groups, "sha256": sha_groups, "completeness": "full"},
        {"source_id": "applications", "path": f_apps, "sha256": sha_apps, "completeness": "full"},
        {"source_id": "service_principals", "path": f_sps, "sha256": sha_sps, "completeness": "full"},
        {"source_id": "managed_identities", "path": f_mis, "sha256": sha_mis, "completeness": "full"},
        {"source_id": "federated_credentials", "path": f_feds, "sha256": sha_feds, "completeness": "full"},
        {"source_id": "agent_blueprints", "path": f_bp, "sha256": sha_bp, "completeness": "full"},
        {"source_id": "agent_identities", "path": f_ai, "sha256": sha_ai, "completeness": "full"},
        {"source_id": "resources", "path": f_res, "sha256": sha_res, "completeness": "full"},
        {"source_id": "directory_roles", "path": f_dr, "sha256": sha_dr, "completeness": "full"},
        {"source_id": "role_assignments", "path": f_ra, "sha256": sha_ra, "completeness": "full"},
        {"source_id": "oauth_grants", "path": f_og, "sha256": sha_og, "completeness": "full"}
    ]
}

m_path = DIR / "manifest.json"
m_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(f"Generated synthetic fixtures in {DIR}")
