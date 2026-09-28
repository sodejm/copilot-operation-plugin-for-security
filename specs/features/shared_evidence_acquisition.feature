Feature: Shared bounded evidence acquisition
  Scenario Outline: Resume representative adapters without losing accepted evidence
    Given a private checkpoint for the "<adapter>" adapter
    When acquisition is interrupted after committing its first page
    And acquisition resumes with the same scope and budgets
    Then two unique records and a complete receipt are available
    Examples:
      | adapter |
      | graph   |
      | arg     |

  Scenario: Record exhaustion remains visible to every consumer
    Given a private checkpoint for the "graph" adapter
    When acquisition reaches its record limit before query exhaustion
    Then the common assessment reports partial and unknown freshness

  Scenario: Dry-run planning does not resolve authentication
    Given a private checkpoint for the "graph" adapter
    When I preview its acquisition plan
    Then no credential or transport call occurs

  Scenario: Observation age is assessed without provider-specific logic
    Given a private checkpoint for the "arg" adapter
    When a complete acquisition has an explicitly old observation
    Then the common assessment reports complete and stale freshness
