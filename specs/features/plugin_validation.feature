Feature: Plugin Architecture and Schema Validation
  As a marketplace maintainer
  I want to validate each portable plugin package
  So that host manifests and Agent Skills remain structurally consistent.

  Scenario: Validate Copilot, Codex, and Claude manifests
    Given a valid categorized Security Logging Advisor package
    When the package validation script executes
    Then the Copilot manifest must contain required identity keys
    And the Codex manifest must contain required interface metadata
    And all host manifest identities must match
    And the validation should pass

  Scenario: Validate skills frontmatter
    Given a valid categorized Security Logging Advisor package
    When the package validation script executes
    Then every packaged skill must contain name and description frontmatter
    And the validation should pass
