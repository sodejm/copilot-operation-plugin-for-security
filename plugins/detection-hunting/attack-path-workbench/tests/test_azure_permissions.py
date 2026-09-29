"""Authorization truth table encoded before the evaluator implementation."""
import copy
import unittest
from attackpath.azure.model import Graph
from attackpath.azure.permissions import evaluate

T = "tenant-a"
S = "/subscriptions/sub-a"
R = S + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
WRITE = "Microsoft.Compute/virtualMachines/write"


def graph(actions=("*",), exclusions=()):
    g = Graph("2026-09-28T12:00:00Z")
    g.add("role_definitions", T, {"id": S + "/providers/Microsoft.Authorization/roleDefinitions/role", "properties": {
        "permissions": [{"actions": list(actions), "notActions": list(exclusions), "dataActions": [], "notDataActions": []}], "assignableScopes": [S]}}, "definition")
    g.add("role_assignments", T, {"id": "assignment", "properties": {"principalId": "user", "roleDefinitionId": S + "/providers/Microsoft.Authorization/roleDefinitions/role", "scope": S}}, "assignment")
    g.cover("deny_assignments", T, [S], True, "denies")
    g.cover("role_assignments", T, [S], True, "assignments")
    g.cover("group_members", T, [S], True, "members")
    g.cover("azure_pim_eligible", T, [S], True, "eligible")
    g.cover("azure_pim_active", T, [S], True, "active")
    return g


class AzurePermissionTests(unittest.TestCase):
    def test_inherited_grant_and_segment_boundaries(self):
        g = graph()
        self.assertEqual("allowed", evaluate(g, T, "user", WRITE, R).state)
        self.assertEqual("unknown", evaluate(g, T, "user", WRITE, "/subscriptions/sub-ab").state)

    def test_not_actions_is_per_role_and_other_role_regrants(self):
        g = graph(exclusions=(WRITE,))
        self.assertEqual("denied", evaluate(g, T, "user", WRITE, R).state)
        definition = copy.deepcopy(g.rows("role_definitions")[0].data)
        definition["id"] += "-second"
        definition["properties"]["permissions"][0]["notActions"] = []
        g.add("role_definitions", T, definition, "second-definition")
        g.add("role_assignments", T, {"id": "second", "properties": {"principalId": "user", "roleDefinitionId": definition["id"], "scope": S}}, "second")
        self.assertEqual("allowed", evaluate(g, T, "user", WRITE, R).state)

    def test_deny_precedence_and_exception(self):
        g = graph()
        deny = {"id": "deny", "properties": {"scope": S, "principals": [{"id": "00000000-0000-0000-0000-000000000000"}], "excludePrincipals": [], "permissions": [{"actions": [WRITE], "notActions": [], "dataActions": [], "notDataActions": []}], "doNotApplyToChildScopes": False}}
        g.add("deny_assignments", T, deny, "deny")
        self.assertEqual("denied", evaluate(g, T, "user", WRITE, R).state)
        g.rows("deny_assignments")[0].data["properties"]["excludePrincipals"] = [{"id": "user"}]
        self.assertEqual("allowed", evaluate(g, T, "user", WRITE, R).state)

    def test_missing_denies_and_unsupported_condition_are_unknown(self):
        g = graph()
        g.coverage = []
        self.assertEqual("unknown", evaluate(g, T, "user", WRITE, R).state)
        g = graph()
        g.rows("role_assignments")[0].data["properties"]["condition"] = "unrecognized"
        self.assertEqual("unknown", evaluate(g, T, "user", WRITE, R).state)

    def test_control_data_and_unsupported_operation(self):
        g = graph()
        vault = S + "/providers/Microsoft.KeyVault/vaults/v"
        g.add("resources", T, {"id": vault, "type": "Microsoft.KeyVault/vaults", "properties": {"enableRbacAuthorization": True}}, "vault")
        self.assertEqual("denied", evaluate(g, T, "user", "Microsoft.KeyVault/vaults/secrets/getSecret/action", vault, plane="data").state)
        self.assertEqual("unknown", evaluate(g, T, "user", "Invented/provider/action", R).state)

    def test_expired_and_stale_do_not_grant(self):
        g = graph()
        g.rows("role_assignments")[0].data["properties"]["endDateTime"] = "2026-09-27T00:00:00Z"
        self.assertEqual("denied", evaluate(g, T, "user", WRITE, R).state)
        g = graph()
        g.rows("role_assignments")[0].quality = ["stale"]
        self.assertEqual("unknown", evaluate(g, T, "user", WRITE, R).state)

    def test_group_cycle_preserves_witness(self):
        g = graph()
        g.rows("role_assignments")[0].data["properties"]["principalId"] = "g2"
        for parent, child in (("g1", "user"), ("g2", "g1"), ("g1", "g2")):
            g.add("group_members", T, {"id": child, "groupId": parent}, parent + child)
        d = evaluate(g, T, "user", WRITE, R)
        self.assertEqual("allowed", d.state)
        self.assertTrue(any("g1user" in ref for ref in d.evidence))


if __name__ == "__main__":
    unittest.main()
