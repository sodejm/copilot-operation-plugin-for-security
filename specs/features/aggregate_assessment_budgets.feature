Feature: Aggregate assessment attempt budgets

  Scenario: Concurrent children share one aggregate allowance
    Given a fixture assessment budget with two permitted concurrent attempts
    When three child attempts reserve concurrently
    Then only two attempts are admitted
    And the shared ledger never exceeds its concurrency limit

  Scenario: Retry and recursive child limits apply before dispatch
    Given a fixture assessment budget with bounded attempts and depth
    When a child retries and then requests a child beyond the permitted depth
    Then the retry consumes a new attempt
    And the excessive depth is denied before fixture dispatch

  Scenario: Duplicate and late receipts do not release allowance twice
    Given an admitted fixture attempt with dispatch intent
    When an unknown usage receipt and its duplicate arrive
    Then the allowance remains conservatively charged
    When a later known usage receipt arrives
    Then the attempt settles once with its known usage

  Scenario: Cancellation and restart preserve uncertain dispatch
    Given an admitted fixture attempt with dispatch intent
    When the engagement is cancelled and the ledger is reopened
    Then new attempts are denied
    And the in-flight attempt remains reserved as uncertain

  Scenario: Missing ledger and expired deadline fail closed
    Given a fixture assessment budget with a short deadline
    When the deadline expires before a new reservation
    Then the reservation is denied
    When the clock moves behind the last denied reservation
    Then the rolled-back clock is rejected
    When the ledger storage becomes unavailable
    Then the fixture callback is not dispatched
