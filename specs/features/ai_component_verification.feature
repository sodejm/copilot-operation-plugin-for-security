Feature: Offline AI component verification
  The verifier treats component metadata as data and records bounded assurance states.

  Scenario: Detect a behavior-bearing MCP description substitution
    Given a versioned component manifest and an observed invocation
    When the MCP tool description differs from the declared component identity
    Then the component is reported as substituted and its baseline is stale

  Scenario: Preserve the stale state after restoration
    Given a baseline made stale by a component change
    When the original component is restored without a review approval
    Then the baseline remains stale

  Scenario: Require receipt-backed signatures when policy requires signing
    Given a signing-required component manifest with a claimed verified signature
    When no trusted receipt binds the signature to the component identity
    Then the component is rejected as an unverified signature claim

  Scenario Outline: Report trust evidence limitations
    Given a versioned component manifest
    When its evidence is "<state>"
    Then the verifier records the corresponding limited assurance state
    Examples:
      | state              |
      | unsigned allowed   |
      | signature failed   |
      | untrusted signer   |
      | revoked            |
      | opaque alias       |
