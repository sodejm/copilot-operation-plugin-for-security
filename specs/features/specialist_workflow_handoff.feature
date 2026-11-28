Feature: Specialist Routing and Bounded Workflow Handoffs
  As a cybersecurity operations lead
  I need structured task and evidence handoffs between Planner, Specialist, Skeptic, and Auditor
  So that proposed workflows resolve to real skills, capabilities are verified, evidence is challenged, and authorization cannot expand

  Scenario: Orchestrating a successful Triad specialist handoff workflow
    Given a valid active engagement and approved action plan
    When the complete Triad handoff workflow is executed for task "Perform network discovery"
    Then the handoff reaches status "completed" with approval status "approved"
    And the transition log records 4 lifecycle transitions
    And the handoff satisfies the specialist handoff contract schema
    And the completed handoff contains no execution result

  Scenario: Rejecting a proposal without a workflow target at acceptance
    Given a proposed handoff without a workflow target
    When the specialist attempts to accept the handoff
    Then the acceptance fails with "MissingCapabilityError"
    And the handoff status is "rejected"

  Scenario: Rejecting a nonexistent workflow skill at acceptance
    Given a proposed handoff with a nonexistent workflow skill
    When the specialist attempts to accept the handoff
    Then the acceptance fails with "MissingCapabilityError"
    And the handoff status is "rejected"

  Scenario: Rejecting handoff when specialist lacks required capability
    Given a proposed handoff requiring unsupported capabilities
    When the specialist attempts to accept the handoff
    Then the acceptance fails with "MissingCapabilityError"
    And the handoff status is "rejected"

  Scenario: Rejecting handoff with conflicting evidence during skeptic review
    Given an accepted handoff with contradictory telemetry observations
    When the domain skeptic reviews the handoff
    Then the skeptic review fails with "ConflictingEvidenceError"
    And the handoff status is "rejected"

  Scenario: Preventing authorization expansion when target diverges
    Given a handoff in review
    When the auditor checks an unapproved candidate target
    Then the audit fails with "AuthorizationExpansionError"
    And the handoff approval status is "reapproval_required"

  Scenario: Preventing material plan modification without reapproval
    Given a handoff in review
    When the auditor checks with modified material plan fields
    Then the audit fails with "MaterialPlanModifiedError"
    And the handoff approval status is "reapproval_required"
