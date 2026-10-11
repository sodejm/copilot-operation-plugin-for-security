Feature: Scenario Laboratory Harness
  As a security operations specialist
  I want independently signed operator observations and authorized remote dispatch
  So that laboratory case claims are tied to measured boundaries and results

  Scenario: Registering and verifying an operator laboratory environment
    Given an inert operator laboratory environment contract
    When the laboratory harness verifies signed isolation and canary observations
    Then the environment status is "verified"
    And isolation verification status is "verified"
    And the canary token is confirmed

  Scenario: Rejecting an environment with mismatched tool prerequisites
    Given an operator laboratory environment with outdated tool versions
    When the laboratory harness attempts to verify tool prerequisites
    Then verification fails with a prerequisite mismatch error
    And the environment cannot transition to verified

  Scenario: Reproducible reset requires a challenged operator receipt and a fresh observation
    Given a verified laboratory environment
    When the operator supplies a signed reset receipt for the pending challenge
    Then the environment status is "verified"
    And a reset timestamp is recorded
    And the canary is verified in the reset environment

  Scenario Outline: Authorized remote cases require bound operator observations
    Given a verified laboratory environment and signed execution authorization
    When the laboratory harness dispatches and classifies a "<case_type>" case
    Then the laboratory case result status is "<expected_status>"
    And the worker cleanup status is "completed"
    And positive canary verification is "<canary_verified>"

    Examples:
      | case_type  | expected_status | canary_verified |
      | positive   | success         | true            |
      | remediated | remediated      | false           |
      | negative   | rejected        | false           |

  Scenario Outline: Unverified worker inventories prevent remote dispatch
    Given a verified laboratory environment and signed execution authorization
    And a directly constructed worker capability inventory
    When the laboratory harness attempts a "<case_type>" case with that inventory
    Then the inventory gate rejects the laboratory case
    And no remote dispatch occurs

    Examples:
      | case_type  |
      | positive   |
      | negative   |
      | remediated |
