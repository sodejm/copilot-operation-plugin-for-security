"""Conservative Azure RBAC decisions; exclusions apply within each role."""
import re
from .model import Decision, arm
from .identity import find, membership, temporal

# Resource Manager deployment clients require the complete deployment operation bundle.
DEPLOYMENT_OPERATIONS = tuple("Microsoft.Resources/deployments/" + action for action in (
    "read", "write", "delete", "cancel/action", "validate/action", "whatIf/action",
    "exportTemplate/action", "operations/read", "operationstatuses/read"))

# Only operations used by pinned v1 rule profiles are modelled.
CONTROL = {a.lower() for a in (
    "Microsoft.Authorization/roleAssignments/write", "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/virtualMachines/extensions/write", "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
    "Microsoft.Automation/automationAccounts/write", "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
    "Microsoft.Automation/automationAccounts/runbooks/publish/action", "Microsoft.Automation/automationAccounts/jobs/write",
    "Microsoft.Web/sites/write", "Microsoft.Web/sites/publish/action", "Microsoft.Logic/workflows/write",
    "Microsoft.Logic/workflows/triggers/run/action", "Microsoft.KeyVault/vaults/accessPolicies/write",
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write") + DEPLOYMENT_OPERATIONS}
DATA = {"microsoft.keyvault/vaults/secrets/getsecret/action", "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"}
ALL_PRINCIPALS = "00000000-0000-0000-0000-000000000000"


def matches(pattern, action):
    if not isinstance(pattern, str) or len(pattern) > 512 or re.search(r"[^a-zA-Z0-9.*/_-]", pattern):
        return None
    return bool(re.fullmatch(re.escape(pattern.lower()).replace(r"\*", ".*"), action.lower()))


def role_grant(definition, action, plane):
    p = definition.properties
    if definition.quality or not isinstance(p.get("permissions"), list):
        return None
    grant, exclude = ("actions", "notActions") if plane == "control" else ("dataActions", "notDataActions")
    unknown = False
    for item in p["permissions"]:
        if not all(isinstance(item.get(k), list) for k in ("actions", "notActions", "dataActions", "notDataActions")):
            unknown = True
            continue
        positives = [matches(v, action) for v in item[grant]]
        negatives = [matches(v, action) for v in item[exclude]]
        if None in positives + negatives:
            unknown = True
        elif any(positives) and not any(negatives):
            return True
    return None if unknown else False


def condition(value, context):
    if not value:
        return True
    if not isinstance(value, str) or len(value) > 8192:
        return None
    # Deliberately narrow grammar: conjunctions of request-field GUID allowlists.
    terms = re.split(r"\s+AND\s+", value.strip(), flags=re.I)
    result = True
    for term in terms:
        match = re.fullmatch(r"\(?\s*@Request\[Microsoft.Authorization/roleAssignments:(RoleDefinitionId|PrincipalId)\]\s+ForAnyOfAnyValues:GuidEquals\s+\{([0-9a-fA-F,\s-]+)\}\s*\)?", term, re.I)
        if not match:
            return None
        field = "roleDefinitionId" if match[1].lower() == "roledefinitionid" else "principalId"
        if not context or field not in context:
            return None
        values = [v.strip().lower() for v in match[2].split(",")]
        if not values or any(not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", v) for v in values):
            return None
        result = result and context[field].split("/")[-1].lower() in values
    return result


def evaluate(graph, tenant, principal, action, scope, *, plane="control", context=None, scenario=None):
    if plane not in ("control", "data") or action.lower() not in (CONTROL if plane == "control" else DATA):
        return Decision("unknown", ["unsupported_operation"])
    scope = arm(scope)
    if plane == "data" and action.lower().startswith("microsoft.keyvault/"):
        vault = find(graph, "resources", tenant, lambda r: arm(r.data["id"]) == scope)
        if vault is None or vault.quality or type(vault.properties.get("enableRbacAuthorization")) is not bool:
            return Decision("unknown", ["key_vault_permission_mode_unknown"], vault.evidence if vault else [])
        if vault.properties["enableRbacAuthorization"] is False:
            return Decision("denied", ["key_vault_access_policy_mode"], vault.evidence)
    principals = membership(graph, tenant, principal)
    denied_refs, deny_unknown = [], []
    for row in graph.rows("deny_assignments", tenant):
        graph.tick()
        p = row.properties
        if not p.get("scope") or not graph.contains(p["scope"], scope, tenant):
            continue
        if p.get("doNotApplyToChildScopes") is True and arm(p["scope"]) != scope:
            continue
        included = {v.get("id", "").lower() for v in p.get("principals", [])}
        excluded = {v.get("id", "").lower() for v in p.get("excludePrincipals", [])}
        relevant = bool(set(principals) & included or ALL_PRINCIPALS in included) and not bool(set(principals) & excluded)
        grant = role_grant(row, action, plane)
        if not relevant:
            if not (set(principals) & excluded) and not graph.covered("group_members", tenant, scope) and included:
                deny_unknown += row.evidence
            continue
        if excluded and not (set(principals) & excluded) and not graph.covered('group_members', tenant, scope):
            deny_unknown += row.evidence
        elif grant is True and not row.quality:
            denied_refs += row.evidence
        elif grant is None or row.quality:
            deny_unknown += row.evidence
    if denied_refs:
        return Decision("denied", ["deny_assignment"], denied_refs)
    if not graph.covered("deny_assignments", tenant, scope) or deny_unknown:
        return Decision("unknown", ["deny_coverage_unknown"], deny_unknown)
    allowed, unknown, latent = [], [], []
    assignments = graph.rows("role_assignments", tenant) + graph.rows("pim_active", tenant) + graph.rows("pim_eligible", tenant)
    for row in assignments:
        graph.tick()
        p = row.properties
        if p.get("directoryScopeId") is not None or not p.get("scope") or not graph.contains(p["scope"], scope, tenant):
            continue
        if p.get("principalId", "").lower() not in principals:
            continue
        valid = temporal(graph, row, scenario)
        if valid.state == "denied":
            continue
        definition = find(graph, "role_definitions", tenant, lambda r: arm(r.data["id"]) == arm(p["roleDefinitionId"]))
        refs, cuts = principals[p["principalId"].lower()]
        if definition is None:
            unknown += row.evidence
            continue
        assignable = definition.properties.get("assignableScopes")
        if not isinstance(assignable, list):
            unknown += row.evidence + definition.evidence
            continue
        if not any(graph.contains(s, p["scope"], tenant) for s in assignable):
            continue
        grant = role_grant(definition, action, plane)
        check = condition(p.get("condition"), context)
        if p.get("condition") and p.get("conditionVersion") != "2.0":
            check = None
        d = Decision(valid.state, valid.reasons, valid.evidence + definition.evidence + refs,
                     valid.cuts + [definition.key] + cuts, valid.assumptions)
        if grant is None or check is None or valid.state == "unknown":
            unknown += d.evidence
        elif grant and check:
            if d.state == "latent_eligibility":
                latent.append(d)
            else:
                allowed.append(d)
    # A definite grant can coexist with another unresolved grant; unresolved denies cannot.
    if allowed:
        return sorted(allowed, key=lambda d: d.evidence)[0]
    if latent:
        return latent[0]
    if unknown or graph.partial or not graph.covered("role_assignments", tenant, scope) or not graph.covered("group_members", tenant, scope) or not graph.covered("azure_pim_eligible", tenant, scope) or not graph.covered("azure_pim_active", tenant, scope):
        return Decision("unknown", ["grant_coverage_unknown"], unknown)
    return Decision("denied", ["no_applicable_grant"])
