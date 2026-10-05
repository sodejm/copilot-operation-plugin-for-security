Feature: Capability Reconciliation and Truth-in-Advertising
  As a security operations lead
  I need all advertised capabilities reconciled against implemented tools and boundaries
  So that theoretical agent profiles and offline tools are never falsely presented as live-validated execution

  Scenario: Auditing complete capability catalog alignment
    Given the current COPS repository catalog
    When the capability truth-in-advertising auditor is executed
    Then the audit succeeds with status "valid"
    And exactly 14 plugins are reconciled
    And exactly 18 specialist profiles are reconciled
    And exactly 36 scenarios are reconciled
    And exactly 0 capabilities claim "live-validated" mode

  Scenario: Filtering capabilities by operational readiness mode
    Given the reconciled capability registry is loaded
    When querying capabilities with mode "laboratory"
    Then at least 15 laboratory capabilities are returned
    When querying capabilities with mode "import"
    Then at least 10 import capabilities are returned
    When querying capabilities with mode "planned"
    Then at least 30 planned capabilities are returned

  Scenario: Rejecting unverified live execution claims
    Given a capability entry claiming mode "live-validated" without verified evidence
    When capability audit is executed on the candidate registry
    Then the audit fails with error code "unverified_live_claim"

  Scenario: Rejecting packages claiming unverified live integration
    Given a plugin package claiming "live_integration" as "validated" without live evidence
    When capability audit is executed on the candidate registry
    Then the audit fails with error code "unverified_live_integration"

  Scenario: Rejecting capabilities with missing truth boundaries
    Given a capability entry with empty truth boundaries
    When capability audit is executed on the candidate registry
    Then the audit fails with error code "missing_truth_boundary"
