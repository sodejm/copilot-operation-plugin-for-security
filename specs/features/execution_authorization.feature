Feature: Execution Authorization Envelopes and Legacy Receipt Rejection
  As a security operations lead
  I need cryptographically bound, operator-authenticated execution authorization envelopes
  So that high-consequence operations cannot be executed with forged, expired, mismatched, or legacy receipts

  Scenario: Authorizing an immutable action plan and verifying signature
    Given a valid action plan from "valid_action_plan.json"
    When an execution authorization envelope is created by operator "secops@corp.internal"
    Then the authorization status is "approved"
    And verification against the action plan succeeds

  Scenario: Rejecting tampered action plans after authorization
    Given a valid action plan from "valid_action_plan.json"
    And an execution authorization envelope created for that plan
    When the action plan target or operations are altered
    Then verification of the authorization is rejected with an integrity mismatch

  Scenario: Rejecting legacy checksum receipts as execution authority
    Given a legacy authorization receipt with schema version "1.0"
    When attempting to verify the legacy receipt as execution authority for an action plan
    Then verification is rejected with a deprecation warning and authorization failure

  Scenario: Preventing replay by atomically consuming the authorization envelope
    Given a verified execution authorization envelope
    When the authorization envelope is consumed by worker "worker-node-01"
    Then the authorization status transitions to "consumed"
    And attempting to consume the authorization again is rejected
