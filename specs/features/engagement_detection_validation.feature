Feature: Evidence-bounded engagement detection validation
  As an operator reviewing an unattended assessment
  I need expected ATT&CK telemetry separated from measured action outcomes
  So that missing or unrelated logs cannot be called a successful defense

  Scenario: A linked in-window alert is detected
    Given a completed action with a linked telemetry record and alert
    When the offline detection report is built
    Then the measured status is detected

  Scenario: A complete zero-result search establishes a missed detection
    Given a completed action with telemetry and a covering zero-result search
    When the offline detection report is built
    Then the measured status is missed

  Scenario: An incomplete search is ambiguous
    Given a completed action with telemetry and an incomplete search
    When the offline detection report is built
    Then the measured status is ambiguous

  Scenario: No observed execution is unavailable
    Given an action without an execution observation
    When the offline detection report is built
    Then the measured status is unavailable

  Scenario: Cross-tenant evidence is rejected
    Given a completed action with evidence from another tenant
    When the offline detection report is attempted
    Then the offline detection report is rejected

  Scenario: Pinned source traceability remains theoretical
    Given the E17.02 offline source traceability catalog
    When source mappings are checked against pinned provenance
    Then every S01 through S13 source maps to canonical identifiers
    And native SOC validation remains pending
