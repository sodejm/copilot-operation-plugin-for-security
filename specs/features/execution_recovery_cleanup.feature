Feature: Execution Recovery and Cleanup Receipts

  Scenario: Rolling back tracked side effects emits a valid cleanup receipt
    Given an initialized side-effect ledger and cleanup manager
    And a temporary file tracked in the side-effect ledger
    When cleanup manager rollback is executed
    Then the tracked file is removed from disk
    And a valid cleanup receipt with status "completed" is emitted

  Scenario: Refusing rollback of resources outside worker workspace
    Given an initialized side-effect ledger and cleanup manager
    And an external system file tracked in the side-effect ledger
    When cleanup manager rollback is executed
    Then the external system file is not removed
    And the cleanup receipt status is "failed" with unresolved effects

  Scenario: Interruption of non-idempotent step yields uncertain outcome without retry
    Given an isolated worker configured with an approval store
    And an action plan containing a non-idempotent mutating step
    When execution is interrupted during the non-idempotent step
    Then the run result status is "uncertain"
    And automatic retry is disallowed
    And cleanup receipt documents unresolved caller-owned state

  Scenario: Restart recovery preserves cleanup ownership and audit state
    Given a durable cleanup journal containing unresolved worker-owned side effects
    And one cleanup transition was interrupted before its terminal journal record
    When a replacement worker recovers the cleanup journal
    Then already-cleaned effects are not replayed
    And the interrupted cleanup outcome is recorded as unknown
    And recovered process identifiers are not signalled
    And persistence failures produce an explicit partial or failed cleanup receipt

  Scenario: Eager staging cleanup remains visible in the final result
    Given executable staging effects were durably cleaned before final rollback
    When the worker emits its final cleanup receipt and run result
    Then the receipt reports every durable staging cleanup action without replaying it
    And the run result reports cleanup status "completed"

  Scenario: Cleanup persistence failure reports only surviving locations
    Given a resource was deleted but its terminal cleanup transition could not be persisted
    When the cleanup manager emits the failed cleanup receipt
    Then the deleted resource is unresolved without a stale quarantine location

  Scenario: Restart cleanup requires durable creation identity
    Given a durable cleanup journal with file and directory creation crash windows
    When cleanup recovery evaluates recorded creation identities
    Then only resources with durably recorded creation identity are removed
    And unverified creation outcomes remain in a durable unresolved receipt
