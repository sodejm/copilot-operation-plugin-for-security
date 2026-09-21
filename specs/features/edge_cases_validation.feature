Feature: Plugin Validation Edge Cases
  As a marketplace maintainer
  I want skill discovery to follow the package contents
  So that newly added skills are validated without a hardcoded list.

  Scenario: Dynamic validation of a custom skill
    Given a valid categorized Security Logging Advisor package
    And a valid custom skill named "custom-audit"
    When the package validation script executes
    Then the custom skill should be validated
    And the validation should pass
