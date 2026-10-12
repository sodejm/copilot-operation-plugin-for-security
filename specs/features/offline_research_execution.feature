Feature: Offline research execution profile
  As an engagement operator
  I need signed local inputs and an observed Linux network boundary
  So that the worker rejects unapproved data and egress paths before execution

  Scenario: Read an approved local corpus
    Given a signed offline research plan for a pinned local corpus and worker
    And a fresh matching observation of an isolated Linux network namespace
    When the worker consumes approval and reads the corpus
    Then the result records the approved and observed isolation digests
    And the result records the staged corpus digest and observation scope

  Scenario: Reject a substituted or unsafe corpus
    Given a signed offline research plan for a pinned local corpus and worker
    When the corpus changes, is oversized, or becomes a symlink
    Then the worker rejects the request before consuming approval

  Scenario: Reject egress and credential requests
    Given a signed offline research plan
    When its target, adapter, arguments, egress policy, or credentials request an external channel
    Then the worker rejects the request before consuming approval

  Scenario: Reject stale or mismatched isolation evidence
    Given a signed offline research plan
    When the isolation observation is missing, stale, or differs from the approved digest
    Then the worker rejects the request before consuming approval

  Scenario: Reject a substituted authorization receipt
    Given a signed offline research plan and a one-use approval
    When a different authorization receipt is supplied to the worker
    Then the worker rejects execution
