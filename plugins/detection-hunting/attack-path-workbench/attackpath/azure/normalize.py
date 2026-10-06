"""Allowlisted projections of documented Graph/ARM pages; never settings/secrets."""

from .model import AzureError, arm

GRAPH_FAMILIES = {
    "users",
    "groups",
    "group_members",
    "applications",
    "service_principals",
    "owners",
    "federated_credentials",
    "directory_assignments",
    "directory_definitions",
    "administrative_units",
    "administrative_members",
    "app_role_assignments",
    "conditional_access",
    "authentication_strengths",
    "directory_pim_eligible",
    "directory_pim_active",
    "directory_pim_policies",
    "directory_pim_policy_assignments",
}
ARM_FAMILIES = {
    "resources",
    "role_assignments",
    "role_definitions",
    "deny_assignments",
    "scope_parents",
    "azure_pim_eligible",
    "azure_pim_active",
    "azure_pim_policies",
    "azure_pim_policy_assignments",
    "lighthouse",
    "lighthouse_assignments",
}
FAMILIES = GRAPH_FAMILIES | ARM_FAMILIES
# Nested projection uses the same explicit key allowlist. Credential values and
# app settings are intentionally absent even when an export contains them.
FIELDS = {
    "id",
    "appId",
    "appOwnerOrganizationId",
    "servicePrincipalType",
    "isAssignableToRole",
    "principalId",
    "principalType",
    "roleDefinitionId",
    "scope",
    "directoryScopeId",
    "appScopeId",
    "condition",
    "conditionVersion",
    "permissions",
    "actions",
    "notActions",
    "dataActions",
    "notDataActions",
    "assignableScopes",
    "roleType",
    "type",
    "properties",
    "identity",
    "tenantId",
    "userAssignedIdentities",
    "clientId",
    "startDateTime",
    "endDateTime",
    "rolePermissions",
    "allowedResourceActions",
    "issuer",
    "subject",
    "audiences",
    "parentId",
    "parent",
    "details",
    "principals",
    "excludePrincipals",
    "doNotApplyToChildScopes",
    "enableRbacAuthorization",
    "keyVaultPermissionModel",
    "kind",
    "state",
    "managedByTenantId",
    "authorizations",
    "eligibleAuthorizations",
    "delegatedRoleDefinitionIds",
    "registrationDefinitionId",
    "policyId",
    "scopeId",
    "scopeType",
    "rules",
    "target",
    "caller",
    "level",
    "operations",
    "enabledRules",
    "maximumDuration",
    "isApprovalRequired",
    "approvalSettings",
    "isEnabled",
    "claimValue",
    "setting",
    "signInAudience",
    "accessPolicies",
    "objectId",
    "resourceId",
    "appRoleId",
    "policyAssignmentId",
    "authenticationStrength",
    "grantControls",
    "builtInControls",
    "conditions",
}


def project(value, key=None):
    if isinstance(value, dict):
        if key == "userAssignedIdentities":
            return {arm(k): project(v) for k, v in value.items()}
        return {k: project(v, k) for k, v in value.items() if k in FIELDS and v is not None}
    if isinstance(value, list):
        if key == "accessPolicies":
            policies = []
            for item in value:
                if not isinstance(item, dict) or not isinstance(item.get("permissions"), dict):
                    raise AzureError("invalid_projection_field")
                policy = project(item)
                policy["permissions"] = {
                    k: v for k, v in item["permissions"].items() if k in ("secrets", "keys", "certificates")
                }
                policies.append(policy)
            return policies
        return [project(v, key) for v in value]
    return value


def policy_requirements(data):
    requirements = {}
    for rule in data.get("rules", []):
        target = rule.get("target", {})
        if target.get("caller") != "EndUser" or target.get("level") != "Assignment":
            continue
        rid = rule.get("id", "")
        if rid.startswith("Enablement_"):
            enabled = rule.get("enabledRules")
            if isinstance(enabled, list) and set(enabled) <= {
                "MultiFactorAuthentication",
                "Justification",
                "Ticketing",
            }:
                requirements["mfa"] = "MultiFactorAuthentication" in enabled
                requirements["extra_requirements"] = bool(set(enabled) - {"MultiFactorAuthentication"})
        if rid.startswith("Approval_"):
            setting = rule.get("setting", rule.get("approvalSettings", {}))
            if type(setting.get("isApprovalRequired")) is bool:
                requirements["approval"] = setting["isApprovalRequired"]
        if rid.startswith("AuthenticationContext_") and type(rule.get("isEnabled")) is bool:
            requirements["authentication_context"] = rule["isEnabled"]
        if rid.startswith("Expiration_"):
            import re

            match = re.fullmatch(r"PT(?:(\d{1,4})H)?(?:(\d{1,4})M)?", rule.get("maximumDuration", ""))
            if match:
                requirements["max_duration_minutes"] = int(match[1] or 0) * 60 + int(match[2] or 0)
    return requirements


def normalize(graph, source, envelope, quality):
    payload = envelope["payload"]
    family, tenant = source["family"], source["tenant"]
    if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
        raise AzureError("unsupported_page_shape")
    context = source.get("context", {})
    for raw in payload["value"]:
        graph.tick()
        if not isinstance(raw, dict):
            raise AzureError("invalid_record_shape")
        data = project(raw)
        if not isinstance(data.get("id"), str):
            raise AzureError("missing_object_id")
        if family == "group_members":
            data["groupId"] = context["groupId"]
        if family in ("owners", "administrative_members", "federated_credentials"):
            data["objectId"] = context["objectId"]
        normalized = family
        if "_pim_" in family:
            data["plane"] = "directory" if family.startswith("directory_") else "azure"
        if family.endswith("_pim_eligible"):
            normalized = "pim_eligible"
        elif family.endswith("_pim_active"):
            normalized = "pim_active"
        elif family.endswith("_pim_policy_assignments"):
            normalized = "pim_policy_assignments"
        elif family.endswith("_pim_policies"):
            normalized = "pim_policies"
            # Preserve documented rules and derive only fully supported requirements.
            validate_projection(normalized, data)
            data["requirements"] = policy_requirements(data.get("properties", data))
        if family == "resources" and data.get("id", "").startswith("/"):
            data["id"] = arm(data["id"])
            from .collection import RESOURCE_APIS

            if RESOURCE_APIS.get(data.get("type", "").lower()) != source["api"]:
                raise AzureError("resource_api_mismatch")
        validate_projection(normalized, data)
        graph.add(normalized, tenant, data, envelope["record_id"], quality)
    return not quality


def validate_projection(family, data):
    """Malformed nested authorization metadata cannot become a guessed grant."""
    p = data.get("properties", data)
    if not isinstance(p, dict):
        raise AzureError("invalid_properties")
    required = {
        "role_assignments": ("principalId", "roleDefinitionId", "scope"),
        "directory_assignments": ("principalId", "roleDefinitionId", "directoryScopeId"),
        "scope_parents": ("parentId",),
        "pim_eligible": ("principalId", "roleDefinitionId"),
        "pim_active": ("principalId", "roleDefinitionId"),
    }.get(family, ())
    if any(not isinstance(p.get(k), str) or not p[k] for k in required):
        raise AzureError("missing_projection_field")
    if family in ("pim_eligible", "pim_active") and not (p.get("scope") or p.get("directoryScopeId")):
        raise AzureError("missing_projection_field")
    for key in (
        "permissions",
        "principals",
        "excludePrincipals",
        "rolePermissions",
        "rules",
        "authorizations",
        "eligibleAuthorizations",
        "accessPolicies",
    ):
        if key in p and (not isinstance(p[key], list) or any(not isinstance(v, dict) for v in p[key])):
            raise AzureError("invalid_projection_field")
    for item in p.get("permissions", []):
        for key in ("actions", "notActions", "dataActions", "notDataActions"):
            if key in item and (not isinstance(item[key], list) or any(not isinstance(v, str) for v in item[key])):
                raise AzureError("invalid_projection_field")
    for item in p.get("rolePermissions", []):
        if not isinstance(item.get("allowedResourceActions"), list) or any(
            not isinstance(v, str) for v in item["allowedResourceActions"]
        ):
            raise AzureError("invalid_projection_field")
    for key in ("scope", "parentId"):
        if key in p:
            arm(p[key])
    if family == "resources" and "identity" in data:
        identity = data["identity"]
        if (
            not isinstance(identity, dict)
            or ("principalId" in identity and not isinstance(identity["principalId"], str))
            or not isinstance(identity.get("userAssignedIdentities", {}), dict)
        ):
            raise AzureError("invalid_identity")
    for key in ("startDateTime", "endDateTime"):
        if p.get(key):
            from .._runtime.cops.evidence.canonical import timestamp

            try:
                timestamp(p[key])
            except ValueError:
                raise AzureError("invalid_validity") from None

    for key in ("assignableScopes", "audiences"):
        if key in p and (not isinstance(p[key], list) or any(not isinstance(v, str) or not v for v in p[key])):
            raise AzureError("invalid_projection_field")
    for scope in p.get("assignableScopes", []):
        arm(scope)
    for key in ("enableRbacAuthorization", "doNotApplyToChildScopes", "isAssignableToRole"):
        if key in p and type(p[key]) is not bool:
            raise AzureError("invalid_projection_field")
    for key in ("principals", "excludePrincipals"):
        if any(not isinstance(v.get("id"), str) or not v["id"] for v in p.get(key, [])):
            raise AzureError("invalid_projection_field")
    for rule in p.get("rules", []):
        if not isinstance(rule.get("id"), str):
            raise AzureError("invalid_projection_field")
        for key in ("target", "setting", "approvalSettings"):
            if key in rule and not isinstance(rule[key], dict):
                raise AzureError("invalid_projection_field")
        if "enabledRules" in rule and (
            not isinstance(rule["enabledRules"], list) or any(not isinstance(v, str) for v in rule["enabledRules"])
        ):
            raise AzureError("invalid_projection_field")
        if "maximumDuration" in rule and not isinstance(rule["maximumDuration"], str):
            raise AzureError("invalid_projection_field")
    for policy in p.get("accessPolicies", []):
        if not isinstance(policy.get("permissions"), dict):
            raise AzureError("invalid_projection_field")
        for values in policy["permissions"].values():
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise AzureError("invalid_projection_field")
        for key in ("tenantId", "objectId"):
            if not isinstance(policy.get(key), str):
                raise AzureError("invalid_projection_field")
    for authorization in p.get("authorizations", []) + p.get("eligibleAuthorizations", []):
        if any(
            not isinstance(authorization.get(k), str) or not authorization[k]
            for k in ("principalId", "roleDefinitionId")
        ):
            raise AzureError("invalid_projection_field")
        ids = authorization.get("delegatedRoleDefinitionIds", [])
        if not isinstance(ids, list) or any(not isinstance(v, str) for v in ids):
            raise AzureError("invalid_projection_field")

    strings = {
        "id",
        "appId",
        "appOwnerOrganizationId",
        "servicePrincipalType",
        "principalId",
        "principalType",
        "roleDefinitionId",
        "scope",
        "scopeId",
        "scopeType",
        "directoryScopeId",
        "appScopeId",
        "condition",
        "conditionVersion",
        "roleType",
        "type",
        "tenantId",
        "clientId",
        "startDateTime",
        "endDateTime",
        "issuer",
        "subject",
        "parentId",
        "kind",
        "state",
        "managedByTenantId",
        "registrationDefinitionId",
        "policyId",
        "objectId",
        "resourceId",
        "appRoleId",
        "policyAssignmentId",
        "caller",
        "level",
        "maximumDuration",
        "claimValue",
        "signInAudience",
    }

    def validate(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in strings and (
                    not isinstance(child, str) or len(child) > 8192 or any(ord(c) < 32 for c in child)
                ):
                    raise AzureError("invalid_projection_field")
                validate(child)
        elif isinstance(value, list):
            for child in value:
                validate(child)

    validate(data)
