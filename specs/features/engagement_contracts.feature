Feature: Engagement, Action, Result, and Finding Contracts
  As a security operations engineer
  I need versioned, immutable operational contracts
  So that engagements, action plans, execution outcomes, and findings are tamper-evident and truthful

  Scenario: Validating a complete engagement and legal lifecycle transitions
    Given a valid engagement document from "valid_engagement.json"
    When the engagement is validated against the contract schema
    Then validation succeeds with schema version "cops.engagement/v1"
    And transitioning the engagement from "planned" to "active" succeeds
    And transitioning the engagement from "active" to "completed" succeeds

  Scenario: Rejecting illegal state transitions
    Given an engagement in state "completed"
    When attempting to transition the engagement to "active"
    Then the transition is rejected with error code "illegal_transition"
    Given an action plan in state "rejected"
    When attempting to transition the action plan to "executing"
    Then the transition is rejected with error code "illegal_transition"

  Scenario: Preserving truthfulness for non-success run results
    Given a run result with status "partial" and reason "execution_timeout_exceeded"
    When evaluating whether the run result was successful
    Then the result evaluates to unsuccessful
    And validation confirms the non-empty reason is present

  Scenario: Rejecting verified findings with missing evidence references
    Given a finding claiming verification "verified" with no evidence references
    When the finding is validated against the contract schema
    Then validation is rejected with error code "missing_evidence_reference"

  Scenario: Rejecting malformed identifiers and tampered action plan digests
    Given a contract document with a malformed identifier
    When the contract is validated
    Then validation is rejected with error code "malformed_identifier"
    Given an action plan document with a tampered plan digest
    When the action plan is validated
    Then validation is rejected with error code "integrity_mismatch"
