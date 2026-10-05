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
    And cleanup receipt documents verified rollback
