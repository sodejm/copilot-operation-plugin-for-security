Feature: Offline engagement retest and closure review
  Scenario: Supported absence on the same asset
    Given a baseline finding and a later assessed retest of the same engagement and exact asset
    When an absent observation references retest evidence for that scenario and asset
    Then the comparison labels the finding candidate_fixed and blocks closure pending independent verification

  Scenario: Inaccessible or changed asset
    Given a baseline finding
    When the retest target is inaccessible or has a different identity
    Then the comparison does not label the finding candidate_fixed

  Scenario: Incomplete cleanup or changed live plan
    Given an otherwise supported candidate_fixed finding
    When cleanup remains unresolved or the live retest plan differs from the baseline plan
    Then the comparison requires further review and never closes the engagement

  Scenario: Same-plan live retest
    Given an assessed live retest using the baseline plan ID
    When the comparison finds an absent observation
    Then it still requires verification of the run authority and cleanup binding

  Scenario: Verified laboratory execution evidence
    Given a disposable laboratory case with a signed authorization, attested worker result, observation, cleanup receipt, and exact journal record
    When the content-addressed bundle is verified against the exact baseline finding and asset
    Then it yields a candidate retest input and closure remains blocked pending independent review

  Scenario: Changed or replayed laboratory execution evidence
    Given a persisted laboratory retest evidence bundle
    When its plan, identity, authorization consumption, supervisor attestation, observation, cleanup, or journal binding differs
    Then verification fails closed and no retest review input is produced
