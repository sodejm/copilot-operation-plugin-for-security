Feature: Portable operator workflow
  As a security engineer or analyst
  I want one predictable entry point for every packaged capability
  So that I can discover, try, and validate tools without learning repository internals

  Scenario: Discover packages and their evidence boundaries
    Given the canonical COPS package catalog
    When I list the available cybersecurity packages
    Then every catalog package is shown with offline, host, and live support states

  Scenario: Exercise every package through its safe demo and a repeated run
    Given the canonical COPS package catalog
    When I run each package's declared offline demo
    Then every demo succeeds without shell interpretation

  Scenario: Run exported playbacks with their declared framework runtime
    Given the canonical COPS package catalog
    When I export and run every playback with an isolated COPS runtime
    Then all exported playbacks verify their results without source package files

  Scenario: Reject a command that escapes its package
    Given the canonical COPS package catalog
    When a package declares a command outside its own directory
    Then the package command is rejected before execution

  Scenario: Detect stale generated host indexes
    Given a generated host index that differs from its canonical document
    When generated host indexes are checked
    Then the stale index is reported without being rewritten

  Scenario: Stop after a default non-idempotent action fails
    Given a workflow action with two attempts and no idempotence opt-in
    When its first execution fails
    Then the workflow stops without a second execution or approval consumption

  Scenario: Retry an explicitly idempotent action
    Given a workflow action with two attempts and explicit idempotence
    When its first execution fails and its second succeeds
    Then both approved attempts use the same logical idempotency key

  Scenario: Do not retry an interrupted non-idempotent action
    Given a non-idempotent workflow action with cleanup
    When execution is interrupted after its approval is consumed
    And the interrupted workflow resumes
    Then cleanup completes without a second execution or approval consumption

  Scenario: Resume an unconsumed planned attempt
    Given a non-idempotent workflow action limited to one attempt
    When the process stops before its planned approval is consumed
    And the planned workflow resumes
    Then the exact saved plan and approval execute once
