"""Paired entitlement chains: exact rights and explicit runtime assumptions."""
import unittest
from attackpath.azure.model import Graph
from attackpath.azure.paths import search

T="tenant-a"
S="/subscriptions/sub-a"
NOW="2026-09-28T12:00:00Z"
SECRET="Microsoft.KeyVault/vaults/secrets/getSecret/action"
VAULT=S+"/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault"

def role(g, principal, actions=(), data=(), scope=S, suffix="role", tenant=T):
    rid=S+"/providers/Microsoft.Authorization/roleDefinitions/"+suffix
    g.add("role_definitions",tenant,{"id":rid,"properties":{"permissions":[{"actions":list(actions),"notActions":[],"dataActions":list(data),"notDataActions":[]}],"assignableScopes":[S]}},suffix+"-definition")
    g.add("role_assignments",tenant,{"id":suffix+"-assignment","properties":{"principalId":principal,"roleDefinitionId":rid,"scope":scope}},suffix+"-assignment")
    return rid

def base():
    g=Graph(NOW)
    for f in ("deny_assignments","role_assignments","group_members","azure_pim_eligible","azure_pim_active"):
        g.cover(f,T,[S],True,f)
    g.scenario={"controlled":[{"tenant":T,"id":"user"}],"targets":[{"tenant":T,"scope":VAULT,"action":SECRET,"plane":"data"}],"runtime":{}}
    g.add("resources",T,{"id":VAULT,"type":"Microsoft.KeyVault/vaults","properties":{"enableRbacAuthorization":True}},"vault")
    return g

def execution(kind, actions, runtime):
    g=base()
    rid=S+"/resourceGroups/rg/providers/"+kind+"/workload"
    obj={"id":rid,"type":kind,"identity":{"principalId":"mi"},"properties":{}}
    if kind=="Microsoft.Web/sites":obj["kind"]="functionapp"
    g.add("resources",T,obj,"workload")
    role(g,"user",actions=actions)
    role(g,"mi",data=[SECRET],scope=VAULT,suffix="downstream")
    g.scenario["runtime"][rid.lower()]={k:True for k in runtime}
    return g,rid

DEPLOYMENT_OPERATIONS = [
    "Microsoft.Resources/deployments/" + action for action in (
        "read", "write", "delete", "cancel/action", "validate/action", "whatIf/action",
        "exportTemplate/action", "operations/read", "operationstatuses/read")]


def deployment():
    g, rid = execution("Microsoft.Compute/virtualMachines",
        ["Microsoft.Resources/deployments/*", "Microsoft.Compute/virtualMachines/extensions/write"],
        ["vm_agent", "network", "token_endpoint"])
    g.rows("role_assignments")[0].properties["scope"] = S + "/resourceGroups/rg"
    return g, rid


class ChainTests(unittest.TestCase):
    def assert_pair(self,g,rule,break_it):
        paths=search(g)
        reached=[p for p in paths if p["classification"]=="modelled_reachable" and rule in [s["rule"] for s in p["steps"]]]
        self.assertTrue(reached,rule)
        self.assertTrue(all(p["evidence"] for p in reached))
        break_it(g)
        paths=search(g)
        self.assertFalse(any(p["classification"]=="modelled_reachable" and rule in [s["rule"] for s in p["steps"]] for p in paths),rule)

    def test_rbac_grant(self):
        g=base();role(g,"user",actions=["Microsoft.Authorization/roleAssignments/write"])
        role(g,"other",data=[SECRET],scope=VAULT,suffix="target")
        self.assert_pair(g,"rbac_grant",lambda g:g.rows("role_definitions")[0].properties["permissions"][0].update(actions=[]))

    def test_application_credentials(self):
        g=base()
        g.add("applications",T,{"id":"app","appId":"client","signInAudience":"AzureADMyOrg"},"app")
        g.add("service_principals",T,{"id":"sp","appId":"client","appOwnerOrganizationId":T,"servicePrincipalType":"Application"},"sp")
        g.add("directory_definitions",T,{"id":"dr","rolePermissions":[{"allowedResourceActions":["microsoft.directory/applications/credentials/update"]}]},"dr")
        g.add("directory_assignments",T,{"id":"da","principalId":"user","roleDefinitionId":"dr","directoryScopeId":"/"},"da")
        g.scenario["credential_restrictions"]=[{"tenant":T,"object":"app","credential_update_allowed":True}]
        role(g,"sp",data=[SECRET],scope=VAULT)
        self.assert_pair(g,"application_credentials",lambda g:g.rows("service_principals")[0].data.update(appOwnerOrganizationId="other-tenant"))

    def test_vm_execution(self):
        g,r=execution("Microsoft.Compute/virtualMachines",["Microsoft.Compute/virtualMachines/write","Microsoft.Compute/virtualMachines/extensions/write"],["vm_agent","network","token_endpoint"])
        self.assert_pair(g,"vm_execution",lambda g:g.scenario["runtime"][r.lower()].update(vm_agent=False))

    def test_arm_deployment_requires_underlying_resource_permission(self):
        g, rid = deployment()
        paths = search(g)
        reached = [p for p in paths if p["classification"] == "modelled_reachable" and
                   "arm_deployment" in [s["rule"] for s in p["steps"]]]
        self.assertTrue(reached)
        steps = reached[0]["steps"]
        prepare = next(s for s in steps if s["rule"] == "arm_deployment")
        execute = next(s for s in steps if s["rule"] == "arm_deployment_execution")
        self.assertEqual((S + "/resourceGroups/rg").lower(), prepare["resource"])
        self.assertEqual(rid, execute["resource"])
        required = {r for d in prepare["prerequisites"] for r in d["reasons"]}
        self.assertEqual({"required_operation:" + a for a in DEPLOYMENT_OPERATIONS}, required)
        # Deployment rights never confer the underlying extension right.
        self.assert_pair(g, "arm_deployment", lambda g:
            g.rows("role_definitions")[0].properties["permissions"][0].update(
                actions=["Microsoft.Resources/deployments/*"]))

    def test_arm_deployment_checks_every_exclusion(self):
        for operation in DEPLOYMENT_OPERATIONS:
            with self.subTest(operation=operation):
                g, _ = deployment()
                self.assert_pair(g, "arm_deployment", lambda g:
                    g.rows("role_definitions")[0].properties["permissions"][0].update(notActions=[operation]))

    def test_arm_deployment_scope_deny_and_runtime(self):
        def wrong_scope(g, rid):
            g.rows("role_assignments")[0].properties["scope"] = S + "/resourceGroups/other"
        def deny(g, rid):
            g.add("deny_assignments", T, {"id": "deny-deployment", "properties": {
                "scope": S + "/resourceGroups/rg", "principals": [{"id": "user"}],
                "excludePrincipals": [], "permissions": [{"actions": ["Microsoft.Resources/deployments/write"],
                "notActions": [], "dataActions": [], "notDataActions": []}]}}, "deny-deployment")
        def unavailable_runtime(g, rid):
            g.scenario["runtime"][rid.lower()]["vm_agent"] = False
        for break_it in (wrong_scope, deny, unavailable_runtime):
            with self.subTest(case=break_it.__name__):
                g, rid = deployment()
                self.assert_pair(g, "arm_deployment", lambda g: break_it(g, rid))
        g, _ = deployment()
        g.scenario["runtime"] = {}
        paths = search(g)
        self.assertTrue(any(p["classification"] == "conditional" and
            "arm_deployment" in [s["rule"] for s in p["steps"]] for p in paths))
        self.assertFalse(any(p["classification"] == "modelled_reachable" for p in paths))
        g.coverage = [c for c in g.coverage if c["family"] != "deny_assignments"]
        deployment_paths = [p for p in search(g) if
            "arm_deployment" in [s["rule"] for s in p["steps"]]]
        self.assertTrue(deployment_paths)
        self.assertTrue(all(p["classification"] == "unknown" for p in deployment_paths))

    def test_arm_deployment_through_lighthouse(self):
        g, _ = deployment()
        g.objects = [r for r in g.objects if r.family != "role_assignments" or r.properties["principalId"] != "user"]
        g.index["role_assignments"] = [r for r in g.index["role_assignments"] if r.properties["principalId"] != "user"]
        definition = g.rows("role_definitions")[0]
        definition.properties["roleType"] = "BuiltInRole"
        registration = S + "/providers/Microsoft.ManagedServices/registrationDefinitions/d"
        g.add("lighthouse", T, {"id": registration, "properties": {
            "managedByTenantId": "managing", "authorizations": [{
                "principalId": "operator", "roleDefinitionId": definition.data["id"]}]}}, "delegation")
        g.add("lighthouse_assignments", T, {"id": S + "/providers/Microsoft.ManagedServices/registrationAssignments/a",
            "properties": {"registrationDefinitionId": registration}}, "delegation-scope")
        g.scenario["controlled"] = [{"tenant": "managing", "id": "operator"}]
        reached = [p for p in search(g) if p["classification"] == "modelled_reachable" and
            "arm_deployment" in [s["rule"] for s in p["steps"]]]
        self.assertTrue(reached)
        self.assertTrue(all("lighthouse" in [s["rule"] for s in p["steps"]] for p in reached))
        self.assert_pair(g, "arm_deployment", lambda g:
            definition.properties["permissions"][0].update(notActions=["Microsoft.Resources/deployments/validate/action"]))

    def test_automation_execution(self):
        g,r=execution("Microsoft.Automation/automationAccounts",["Microsoft.Automation/automationAccounts/runbooks/draft/content/write","Microsoft.Automation/automationAccounts/runbooks/publish/action","Microsoft.Automation/automationAccounts/jobs/write"],["automation_sandbox","network","token_endpoint"])
        self.assert_pair(g,"automation_execution",lambda g:g.scenario["runtime"][r.lower()].update(automation_sandbox=False))

    def test_functions_execution(self):
        g,r=execution("Microsoft.Web/sites",["Microsoft.Web/sites/write","Microsoft.Web/sites/publish/action"],["function_deployment","invocation","network","token_endpoint"])
        self.assert_pair(g,"functions_execution",lambda g:g.scenario["runtime"][r.lower()].update(invocation=False))

    def test_logic_execution(self):
        g,r=execution("Microsoft.Logic/workflows",["Microsoft.Logic/workflows/write","Microsoft.Logic/workflows/triggers/run/action"],["logic_consumption","identity_action","invocation","network","token_endpoint"])
        self.assert_pair(g,"logic_execution",lambda g:g.scenario["runtime"][r.lower()].update(identity_action=False))

    def test_uami_attach(self):
        g,r=execution("Microsoft.Compute/virtualMachines",["Microsoft.Compute/virtualMachines/write","Microsoft.Compute/virtualMachines/extensions/write","Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"],["vm_agent","network","token_endpoint"])
        g.rows("resources")[1].data.pop("identity")
        u=S+"/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u"
        g.add("resources",T,{"id":u,"type":"Microsoft.ManagedIdentity/userAssignedIdentities","properties":{"principalId":"mi"}},"uami")
        self.assert_pair(g,"uami_attach",lambda g:g.rows("role_definitions")[0].properties["permissions"][0].update(actions=["Microsoft.Compute/virtualMachines/write","Microsoft.Compute/virtualMachines/extensions/write"]))

    def test_federation(self):
        g=base();u=S+"/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u"
        g.add("resources",T,{"id":u,"type":"Microsoft.ManagedIdentity/userAssignedIdentities","properties":{"principalId":"mi"}},"uami")
        g.add("federated_credentials",T,{"id":u+"/federatedIdentityCredentials/f","objectId":u,"issuer":"https://issuer.example","subject":"subject","audiences":["api://AzureADTokenExchange"]},"federation")
        role(g,"user",actions=["Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"])
        role(g,"mi",data=[SECRET],scope=VAULT,suffix="target")
        g.scenario["assertions"]=[{"issuer":"https://issuer.example","subject":"subject","audience":"api://AzureADTokenExchange","controlled":True}]
        self.assert_pair(g,"federation",lambda g:g.scenario["assertions"][0].update(subject="different"))

    def test_lighthouse(self):
        g,r=execution("Microsoft.Compute/virtualMachines",[],["vm_agent","network","token_endpoint"])
        g.objects=[x for x in g.objects if x.family!="role_assignments" or x.properties["principalId"]!="user"]
        g.index["role_assignments"]=[x for x in g.index["role_assignments"] if x.properties["principalId"]!="user"]
        rid=g.rows("role_definitions")[0].data["id"]
        g.rows("role_definitions")[0].properties.update(roleType="BuiltInRole",permissions=[{"actions":["Microsoft.Compute/virtualMachines/write","Microsoft.Compute/virtualMachines/extensions/write"],"notActions":[],"dataActions":[],"notDataActions":[]}])
        g.add("lighthouse",T,{"id":S+"/providers/Microsoft.ManagedServices/registrationDefinitions/d","properties":{"managedByTenantId":"managing","authorizations":[{"principalId":"operator","roleDefinitionId":rid}],"eligibleAuthorizations":[{"principalId":"operator","roleDefinitionId":rid}]}},"delegation")
        g.add("lighthouse_assignments",T,{"id":S+"/providers/Microsoft.ManagedServices/registrationAssignments/a","properties":{"registrationDefinitionId":g.rows("lighthouse")[0].data["id"]}},"delegation-scope")
        g.scenario["controlled"]=[{"tenant":"managing","id":"operator"}]
        self.assert_pair(g,"lighthouse",lambda g:g.rows("role_definitions")[0].properties.update(roleType="CustomRole"))

    def test_unknown_runtime_and_no_vault_write_secret_jump(self):
        g,r=execution("Microsoft.Compute/virtualMachines",["Microsoft.Compute/virtualMachines/write","Microsoft.Compute/virtualMachines/extensions/write"],[])
        paths=search(g)
        self.assertTrue(any(p["classification"]=="conditional" for p in paths))
        g=base();role(g,"user",actions=["Microsoft.KeyVault/vaults/write"])
        self.assertFalse(any(p["classification"]=="modelled_reachable" for p in search(g)))
