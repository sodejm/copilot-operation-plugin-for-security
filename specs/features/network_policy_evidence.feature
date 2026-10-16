Feature: Typed network policy and observed reachability
  Scenario: Correct a forbidden path while retaining a required path
    Given complete firewall and rendered Kubernetes policy inventories
    When a broad allow rule is replaced with a scoped rule
    Then forbidden paths are predicted denied and required paths remain allowed
    And isolated network checks separately verify enforcement

  Scenario: Missing evidence cannot establish isolation
    Given incomplete namespaces, unsupported rules, stale DNS or missing flows
    When segmentation evidence is assessed
    Then the result retains an insufficient-evidence finding
    And absence of an observation never becomes a successful denial test
