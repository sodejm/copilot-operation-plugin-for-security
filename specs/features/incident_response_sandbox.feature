Feature: Incident response sandbox execution
  Scenario: An approved fixture action follows an explicit dry run
    Given a synthetic tenant fixture and a matching expiring plan
    When the analyst dry runs and executes the plan
    Then only the named fixture target changes
    And the result records successful post-action verification
    And a replay of the same plan is rejected

  Scenario: A changed target prevents execution
    Given a successful dry run receipt
    When the fixture changes before execution
    Then execution rejects the drift without applying the action

  Scenario: Partial failure reports rollback status
    Given a fixture configured for partial action failure
    When the analyst executes a dry run plan
    Then the result records partial success and rollback outcome
    And the result records failed post-action verification

  Scenario: Unavailable verification remains explicit
    Given a fixture configured with unavailable post-action verification
    When the analyst executes a dry run plan
    Then the result records unavailable post-action verification
