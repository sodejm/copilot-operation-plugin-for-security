Feature: Analyst-led SOC investigation planning
  Scenario: AC01 Scope and identity violations are rejected
    Given a scoped synthetic investigation
    When scope and identity boundaries are challenged
    Then the investigation contract rejects the violations

  Scenario: AC02 Duplicate evidence and replay cannot inflate support
    Given a scoped synthetic investigation
    When the same observation is imported again
    Then evidence support and completed work remain unchanged

  Scenario: AC03 Contradictions and missing coverage remain visible
    Given a scoped synthetic investigation
    When contradictory evidence and a coverage gap are recorded
    Then review preserves uncertainty and the coverage gap

  Scenario: AC04 Branches and ranking select bounded independent work
    Given a scoped synthetic investigation
    When next steps are ranked before and after evidence
    Then only ready independent steps within budget are proposed

  Scenario: AC05 Cycles and duplicate hunt requests are rejected
    Given a scoped synthetic investigation
    When a plan contains a cycle or duplicate request
    Then validation rejects the ambiguous plan

  Scenario: AC06 Budgets and no progress stop further work without a verdict
    Given a scoped synthetic investigation
    When execution reaches a budget or no-progress limit
    Then planning stops for review without classifying the case

  Scenario: AC07 Replanning preserves completed work and enables new branches
    Given a scoped synthetic investigation
    When pending work is revised after a result
    Then completed work is immutable and new work becomes eligible

  Scenario: AC08 Vendor integrity and compatibility gate query handoffs
    Given a scoped synthetic investigation
    When a handoff encounters drift or unverified surface support
    Then query delegation fails closed

  Scenario: AC09 Hostile prose stays data and reports do not expose it
    Given a scoped synthetic investigation
    When evidence contains instruction-like prose
    Then output contains only evidence references and no prose

  Scenario: AC10 CLI snapshots are validated private and never overwritten
    Given a scoped synthetic investigation
    When the CLI imports a result and repeats an output path
    Then it creates a private validated snapshot and rejects overwrite
