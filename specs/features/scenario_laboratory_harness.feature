Feature: Scenario Laboratory Harness
  As a security operations specialist
  I want a harness that uses verifier trust, active engagement, measured worker capabilities, canary verification, and reproducible reset
  So that authorized scenarios execute reproducibly with explicit evidence and residual boundaries

  Scenario: Registering and verifying an operator laboratory environment
    Given an inert operator laboratory environment contract
    When the laboratory harness verifies the environment isolation and canary data
    Then the environment status transitions to "verified"
    And isolation verification status is "verified"
    And the canary token is confirmed

  Scenario: Rejecting an environment with mismatched tool prerequisites
    Given an operator laboratory environment with outdated tool versions
    When the laboratory harness attempts to verify tool prerequisites
    Then verification fails with a prerequisite mismatch error
    And the environment cannot transition to verified

  Scenario: Reproducible environment reset restores baseline state
    Given a verified laboratory environment
    When the laboratory harness triggers a reproducible reset
    Then the environment status transitions to "verified"
    And a reset timestamp is recorded
    And the canary is verified in the reset environment

  Scenario: Executing an authorized positive laboratory case with cleanup receipt
    Given a verified laboratory environment and signed execution authorization
    When the laboratory harness executes a positive case
    Then the laboratory case result status is "success"
    And the canary verification succeeds
    And a valid cleanup receipt with status "completed" is emitted

  Scenario: Executing a remediated laboratory case demonstrating mitigation
    Given a verified laboratory environment and signed execution authorization
    When the laboratory harness executes a remediated case
    Then the laboratory case result status is "remediated"
    And the run result records that the attack was mitigated by active security controls
    And a valid cleanup receipt with status "completed" is emitted

  Scenario: Controlled negative case execution rejects attack path without false claims
    Given a verified laboratory environment and signed execution authorization
    When the laboratory harness executes a negative case
    Then the laboratory case result status is "rejected"
    And the run result status is "failed"
    And no positive compromise claims are made
