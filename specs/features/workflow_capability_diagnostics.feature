Feature: Workflow Capability and Package Diagnostics
  As a security operations specialist
  I want comprehensive platform, tool prerequisite, package workflow, and capability truth diagnostics
  So that unavailable tools are explicitly reported and theoretical capabilities are never falsely presented as operational

  Scenario: Diagnosing system platform and runtime environment
    Given a supported host platform and Python runtime
    When the diagnostic runner inspects the system environment
    Then the system platform diagnostic indicates supported status
    And the detected OS is one of "darwin", "linux", "windows"

  Scenario: Diagnosing security tool prerequisites matrix
    Given the tested host tools matrix
    When the diagnostic runner inspects external tool availability
    Then at least 5 security tools are evaluated
    And "python3" is detected as "available"
    And missing tools are explicitly reported without failing offline planning

  Scenario: Diagnosing package workflow structures
    Given registered plugin packages in the repository
    When the diagnostic runner inspects plugin package workflows
    Then at least 14 plugin packages are evaluated
    And "offensive-engagement-workbench" is diagnosed as "ready" or "degraded"
    And all package manifests are validated

  Scenario: Auditing capability truth-in-advertising alignment
    Given the reconciled capability registry
    When capability diagnostics are executed
    Then the capability truth audit passes
    And exactly 68 total capabilities are verified
    And exactly 0 capabilities claim unverified "live-validated" execution

  Scenario: Evaluating strict diagnostic enforcement
    Given an unknown or degraded package specification
    When the diagnostic runner executes in strict mode
    Then overall diagnostic readiness fails
