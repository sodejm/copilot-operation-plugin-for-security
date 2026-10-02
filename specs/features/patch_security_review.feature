Feature: Offline patch security review
  Scenario: PSR-01 flags a candidate source-to-sink path
    Given a synthetic Python patch that passes a request parameter to a shell
    When the pinned commits are reviewed
    Then the report records a candidate and no validated finding

  Scenario: PSR-02 does not flag a benign patch
    Given a synthetic Python patch that uses a constant argument list
    When the pinned commits are reviewed
    Then the report has no candidate shell path

  Scenario: PSR-03 requires analyst validation
    Given a candidate with asserted preconditions and disconfirming evidence
    When an analyst validates the candidate
    Then the validation is recorded as an unverified analyst assertion

  Scenario: PSR-04 enforces bounded reads
    Given a changed source file beyond the configured byte budget
    When the pinned commits are reviewed
    Then review stops before reading the full source
