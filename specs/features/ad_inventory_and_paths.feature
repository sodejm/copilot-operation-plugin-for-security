Feature: Offline AD inventory and relationship analysis
  As an authorized identity assessor
  I need evidence-linked graph paths from scoped AD exports
  So that unknown coverage and inferred relationships remain visible

  Scenario: Synthetic two-forest inventory
    Given the synthetic AD inventory export
    When the AD inventory analyzer runs
    Then the report contains one candidate path and one missing path
    And the candidate path requires validation across a protected trust boundary
    And the missing path is unknown in the collected graph

  Scenario: Conflicting identities fail closed
    Given the synthetic AD inventory export with a conflicting identity
    When the AD inventory analyzer runs
    Then the AD inventory analyzer rejects the export

  Scenario: Unapproved forest boundary fails closed
    Given the synthetic AD inventory export with an unapproved forest edge
    When the AD inventory analyzer runs
    Then the AD inventory analyzer rejects the export
