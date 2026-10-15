Feature: Offline research request preflight
  As an engagement operator
  I need executable checks for the approval-bound local profile
  So that unsafe inputs are rejected during preflight

  Scenario: Stage an approved local corpus with matching synthetic observation
    Given an offline research plan for a pinned local corpus and worker
    When preflight validates and stages the approved corpus
    Then the staged digest and synthetic isolation observation match the plan

  Scenario: Reject substituted or unsafe corpus files
    Given an offline research plan for a pinned local corpus and worker
    When the corpus changes, is oversized, or becomes a symlink
    Then corpus staging rejects every unsafe source

  Scenario: Reject external channels
    Given an offline research plan for a pinned local corpus and worker
    When the target, adapter, arguments, egress policy, or credentials request an external channel
    Then offline request preflight rejects every external channel

  Scenario: Reject stale or mismatched isolation evidence
    Given an offline research plan for a pinned local corpus and worker
    When the isolation observation is stale or differs from the approved digest
    Then isolation preflight rejects the invalid evidence

  Scenario: Reject a substituted authorization receipt
    Given an offline research plan for a pinned local corpus and worker
    When the approval client receives a substituted receipt
    Then receipt provenance validation rejects the substitution
