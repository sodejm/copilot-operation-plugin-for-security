"""Pinned, read-only collection intentions. This module performs no HTTP requests."""
import json
from urllib.parse import quote
from .input import fields, json_value, read_regular
from .model import AzureError, arm, stable, object_id

GRAPH = "MicrosoftGraph"
ARM = "AzureResourceManager"
RESOURCE_GRAPH = "AzureResourceGraph"
RESOURCE_GRAPH_API = "2024-04-01"
RESOURCE_GRAPH_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=" + RESOURCE_GRAPH_API
GRAPH_DOC = "https://learn.microsoft.com/en-us/graph/api/"
ARM_DOC = "https://learn.microsoft.com/en-us/rest/api/"
# Family, endpoint, least-privilege application permission, reference, expansion input.
GRAPH_CATALOG = (
    ("users", "/users?$select=id", "User.Read.All", "user-list", None),
    ("groups", "/groups?$select=id,isAssignableToRole", "Group.Read.All", "group-list", None),
    ("group_members", "/groups/{id}/members?$select=id", "GroupMember.Read.All", "group-list-members", "groups"),
    ("applications", "/applications?$select=id,appId,signInAudience", "Application.Read.All", "application-list", None),
    ("service_principals", "/servicePrincipals?$select=id,appId,appOwnerOrganizationId,servicePrincipalType", "Application.Read.All", "serviceprincipal-list", None),
    ("owners", "/{kind}/{id}/owners?$select=id", "Application.Read.All", "application-list-owners", "owned_objects"),
    ("federated_credentials", "/applications/{id}/federatedIdentityCredentials", "Application.Read.All", "application-list-federatedidentitycredentials", "applications"),
    ("directory_assignments", "/roleManagement/directory/roleAssignments", "RoleManagement.Read.Directory", "rbacapplication-list-roleassignments", None),
    ("directory_definitions", "/roleManagement/directory/roleDefinitions", "RoleManagement.Read.Directory", "rbacapplication-list-roledefinitions", None),
    ("administrative_units", "/directory/administrativeUnits?$select=id", "AdministrativeUnit.Read.All", "directory-list-administrativeunits", None),
    ("administrative_members", "/directory/administrativeUnits/{id}/members?$select=id", "AdministrativeUnit.Read.All", "administrativeunit-list-members", "administrative_units"),
    ("app_role_assignments", "/servicePrincipals/{id}/appRoleAssignments", "Application.Read.All", "serviceprincipal-list-approleassignments", "service_principals"),
    ("conditional_access", "/identity/conditionalAccess/policies", "Policy.Read.All", "conditionalaccessroot-list-policies", None),
    ("authentication_strengths", "/identity/conditionalAccess/authenticationStrength/policies", "Policy.Read.All", "authenticationstrengthroot-list-policies", None),
    ("directory_pim_eligible", "/roleManagement/directory/roleEligibilityScheduleInstances", "RoleEligibilitySchedule.Read.Directory", "rbacapplication-list-roleeligibilityscheduleinstances", None),
    ("directory_pim_active", "/roleManagement/directory/roleAssignmentScheduleInstances", "RoleAssignmentSchedule.Read.Directory", "rbacapplication-list-roleassignmentscheduleinstances", None),
    ("directory_pim_policies", "/policies/roleManagementPolicies?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&$expand=rules", "RoleManagementPolicy.Read.Directory", "policyroot-list-rolemanagementpolicies", None),
    ("directory_pim_policy_assignments", "/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'", "RoleManagementPolicy.Read.Directory", "policyroot-list-rolemanagementpolicyassignments", None),
)
# Family, provider/type, pinned API, required ARM read operation, reference.
ARM_CATALOG = (
    ("resources", None, None, "Resource-specific read", "resources/resources/get"),
    ("role_assignments", "Microsoft.Authorization/roleAssignments", "2022-04-01", "Microsoft.Authorization/roleAssignments/read", "authorization/role-assignments/list-for-scope"),
    ("role_definitions", "Microsoft.Authorization/roleDefinitions", "2022-04-01", "Microsoft.Authorization/roleDefinitions/read", "authorization/role-definitions/list"),
    ("deny_assignments", "Microsoft.Authorization/denyAssignments", "2022-04-01", "Microsoft.Authorization/denyAssignments/read", "authorization/deny-assignments/list-for-scope"),
    ("scope_parents", "Microsoft.Management/managementGroups", "2020-05-01", "Microsoft.Management/managementGroups/read", "managementgroups/management-groups/get"),
    ("azure_pim_eligible", "Microsoft.Authorization/roleEligibilityScheduleInstances", "2020-10-01", "Microsoft.Authorization/roleEligibilityScheduleInstances/read", "authorization/role-eligibility-schedule-instances/list-for-scope"),
    ("azure_pim_active", "Microsoft.Authorization/roleAssignmentScheduleInstances", "2020-10-01", "Microsoft.Authorization/roleAssignmentScheduleInstances/read", "authorization/role-assignment-schedule-instances/list-for-scope"),
    ("azure_pim_policies", "Microsoft.Authorization/roleManagementPolicies", "2020-10-01", "Microsoft.Authorization/roleManagementPolicies/read", "authorization/role-management-policies/list-for-scope"),
    ("azure_pim_policy_assignments", "Microsoft.Authorization/roleManagementPolicyAssignments", "2020-10-01", "Microsoft.Authorization/roleManagementPolicyAssignments/read", "authorization/role-management-policy-assignments/list-for-scope"),
    ("lighthouse", "Microsoft.ManagedServices/registrationDefinitions", "2022-10-01", "Microsoft.ManagedServices/registrationDefinitions/read", "managedservices/registration-definitions/list"),
    ("lighthouse_assignments", "Microsoft.ManagedServices/registrationAssignments", "2022-10-01", "Microsoft.ManagedServices/registrationAssignments/read", "managedservices/registration-assignments/list"),
)
RESOURCE_APIS = {
    "microsoft.compute/virtualmachines": "2024-07-01",
    "microsoft.automation/automationaccounts": "2024-10-23",
    "microsoft.web/sites": "2024-11-01",
    "microsoft.logic/workflows": "2019-05-01",
    "microsoft.keyvault/vaults": "2023-07-01",
    "microsoft.managedidentity/userassignedidentities": "2023-01-31",
}

RESOURCE_REFERENCES = {
    "microsoft.compute/virtualmachines": "compute/virtual-machines/get",
    "microsoft.automation/automationaccounts": "automation/automation-account/get",
    "microsoft.web/sites": "appservice/web-apps/get",
    "microsoft.logic/workflows": "logic/workflows/get",
    "microsoft.keyvault/vaults": "keyvault/vaults/get",
    "microsoft.managedidentity/userassignedidentities": "managedidentity/user-assigned-identities/get",
}


def source_contract(family, api):
    if any(row[0] == family for row in GRAPH_CATALOG):
        if api != "v1.0" and not (family == "federated_credentials" and api == "2023-01-31"):
            raise AzureError("unsupported_source_api")
        return ARM if api == "2023-01-31" else GRAPH
    for name, _, version, _, _ in ARM_CATALOG:
        if name == family:
            allowed = set(RESOURCE_APIS.values()) if family == "resources" else {version}
            if api not in allowed:
                raise AzureError("unsupported_source_api")
            return ARM
    raise AzureError("unsupported_source_family")


def plan(scope_file):
    from pathlib import Path
    file = Path(scope_file).absolute()
    value = json_value(read_regular(file.parent, file.name, 262144), 262144)
    fields(value, ("schema_version", "tenants"))
    if value["schema_version"] != "attackpath.azure.scope/v1" or not isinstance(value["tenants"], list) or len(value["tenants"]) > 16:
        raise AzureError("invalid_collection_scope")
    requests = []
    def add(tenant, family, api, url, scopes, permission, reference, context=None, *, body=None):
        if len(requests) >= 2048:
            raise AzureError("collection_request_limit")
        request = {"id": stable([tenant, family, url] + ([body] if body is not None else [])), "tenant": tenant, "family": family,
            "product": RESOURCE_GRAPH if body is not None else source_contract(family, api),
            "api": api, "method": "POST" if body is not None else "GET", "url": url,
            "scopes": scopes, "permission": permission, "reference": reference, "context": context or {},
            "pagination": "follow documented continuation within the same tenant, cloud and endpoint; cap pages and bytes"}
        if body is not None:
            request["body"] = body
            request["pagination"] = "retain query and declared scope; pass the returned $skipToken in body.options.$skipToken; cap pages and bytes"
        requests.append(request)
    seen = set()
    lists = ("groups", "applications", "service_principals", "administrative_units", "management_groups", "user_assigned_identities", "resources")
    for tenant in value["tenants"]:
        fields(tenant, ("id", "scopes"), lists)
        tid = tenant["id"]
        if not isinstance(tid, str) or not tid or len(tid) > 256 or any(ord(c) < 32 for c in tid) or tid in seen:
            raise AzureError("invalid_collection_tenant")
        object_id(tid, "scope")
        seen.add(tid)
        for name in ("scopes",) + lists:
            values = tenant.get(name, [])
            if not isinstance(values, list) or len(values) > 128 or any(not isinstance(v, str) or not v or len(v) > 2048 or any(ord(c) < 32 for c in v) for v in values):
                raise AzureError("invalid_collection_scope")
        scopes = sorted(set(arm(s) for s in tenant["scopes"]))
        if not scopes:
            raise AzureError("missing_collection_scope")
        for scope in scopes:
            parts = scope.strip("/").split("/")
            body = {"query": "Resources | project id, type | order by id asc",
                    "options": {"$top": 1000, "resultFormat": "objectArray"}}
            if len(parts) >= 2 and parts[0] == "subscriptions":
                body["subscriptions"] = [parts[1]]
                body["query"] = ("Resources | where id =~ " + json.dumps(scope) +
                    " or id startswith " + json.dumps(scope + "/") + " | project id, type | order by id asc")
            elif len(parts) == 4 and parts[:3] == ["providers", "microsoft.management", "managementgroups"]:
                body["managementGroups"] = [parts[3]]
            else:
                continue
            add(tid, "resource_inventory", RESOURCE_GRAPH_API, RESOURCE_GRAPH_URL, [scope],
                "Microsoft.ResourceGraph/resources/read and underlying resource-type read at the declared scope",
                ARM_DOC + "azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2024-04-01", body=body)
        for family, endpoint, permission, ref, expansion in GRAPH_CATALOG:
            entries = [(None, None)] if expansion is None else [(oid, None) for oid in sorted(set(tenant.get(expansion, [])))]
            if expansion == "owned_objects":
                entries = [(oid, kind) for name, kind in (("applications", "applications"), ("service_principals", "servicePrincipals")) for oid in sorted(set(tenant.get(name, [])))]
            for oid, kind in entries:
                url = endpoint.replace("{id}", quote(oid or "", safe="")).replace("{kind}", kind or "")
                context = {"groupId" if family == "group_members" else "objectId": oid} if oid and family in ("group_members", "owners", "federated_credentials", "administrative_members") else {}
                add(tid, family, "v1.0", "https://graph.microsoft.com/v1.0" + url, ["/"], permission, GRAPH_DOC + ("serviceprincipal-list-owners" if family == "owners" and kind == "servicePrincipals" else ref) + "?view=graph-rest-1.0", context)
        for family, provider, api, permission, ref in ARM_CATALOG:
            if family == "resources":
                for rid in sorted(set(arm(s) for s in tenant.get("resources", []) + tenant.get("user_assigned_identities", []))):
                    parts = rid.split("/providers/")
                    profile = "/".join(parts[-1].split("/")[:2])
                    if profile not in RESOURCE_APIS:
                        raise AzureError("unsupported_resource_profile")
                    add(tid, family, RESOURCE_APIS[profile], "https://management.azure.com" + rid + "?api-version=" + RESOURCE_APIS[profile], [rid], profile + "/read", ARM_DOC + RESOURCE_REFERENCES[profile])
                continue
            if family == "scope_parents":
                for gid in sorted(set(tenant.get("management_groups", []))):
                    rid = "/providers/Microsoft.Management/managementGroups/" + quote(gid, safe="")
                    add(tid, family, api, "https://management.azure.com" + rid + "?api-version=" + api + "&$expand=children&$recurse=true", [arm(rid)], permission, ARM_DOC + ref)
                continue
            for scope in scopes:
                url = "https://management.azure.com" + scope.rstrip("/") + "/providers/" + provider + "?api-version=" + api
                if family in ("role_assignments", "deny_assignments"):
                    url += "&$filter=atScope()"
                add(tid, family, api, url, [scope], permission, ARM_DOC + ref)
        for rid in sorted(set(arm(s) for s in tenant.get("user_assigned_identities", []))):
            add(tid, "federated_credentials", "2023-01-31", "https://management.azure.com" + rid + "/federatedIdentityCredentials?api-version=2023-01-31", [rid], "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read", ARM_DOC + "managedidentity/federated-identity-credentials/list", {"objectId": rid})
    return {"schema_version": "attackpath.azure.collection/v1", "cloud": "AzurePublic", "requests": sorted(requests, key=lambda r: r["id"]),
        "expected_evidence": {"envelope": "cops.evidence/v1", "record": "cops.record/v1", "receipt": "cops.acquisition/v1", "payload": "value array per page, without secret values", "manifest": "attackpath.azure.input/v1 with relative files and SHA-256 checksums", "counts": "receipt pages and records both equal consumed page envelopes; projected items have a separate analyzer bound", "projections": "retain original record parents and locator when projecting single objects or management-group ancestry"},
        "constraints": ["Read-only plan; obtain authorization before collection. No authentication or HTTP execution is implemented.",
            "Enforce explicit scopes and per-request permissions; do not substitute a broad administrator role.",
            "Export every page through cops.evidence/v1 and preserve cops.acquisition/v1 receipts and checksums.",
            "Single-object GETs and management-group children need documented projection into value arrays and parentId observations.",
            "Expand relational requests using enumerated IDs in a second scoped plan; omitted IDs leave coverage unknown.",
            "Resource Graph queries may omit inaccessible resources without warning; successful inventory never proves complete coverage.",
            "Resource Graph inventory requires explicit subscription or management-group scopes; tenant root and ancestry-only IDs do not expand inventory scope.",
            "Inventory projects only id and type. Hydrate explicit supported resource IDs through typed ARM GETs in a second plan; resource_inventory is not accepted as analyzer evidence.",
            "Graph v1.0 group members omit service principals. Hidden membership needs Member.Read.Hidden; missing membership never proves absence.",
            "Conditional Access and authentication strength records are context, not proof that activation or token issuance will succeed.",
            "Do not collect credentials, secret values, app settings, certificates, or access tokens."]}
