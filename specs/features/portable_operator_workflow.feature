Feature: Portable operator workflow
  As a security engineer or analyst
  I want one predictable entry point for every packaged capability
  So that I can discover, try, and validate tools without learning repository internals

  Scenario: Discover packages and their evidence boundaries
    Given the canonical COPS package catalog
    When I list the available cybersecurity packages
    Then every catalog package is shown with offline, host, and live support states

  Scenario: Exercise every package through its safe demo
    Given the canonical COPS package catalog
    When I run each package's declared offline demo
    Then every demo succeeds without shell interpretation

  Scenario: Reject a command that escapes its package
    Given the canonical COPS package catalog
    When a package declares a command outside its own directory
    Then the package command is rejected before execution

  Scenario: Detect stale generated host indexes
    Given a generated host index that differs from its canonical document
    When generated host indexes are checked
    Then the stale index is reported without being rewritten
