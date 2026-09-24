Feature: Portable cybersecurity marketplace
  As a marketplace maintainer
  I want deterministic organization and evidence gates
  So that packages remain discoverable and claims remain factual

  Scenario: Validate the categorized marketplace catalog
    Given the repository marketplace catalog
    When the marketplace contract is validated
    Then every package is categorized and indexed for each supported host

  Scenario: Reject a nonstandard portable manifest
    Given a package manifest with an unknown top-level field
    When the Agent Plugins v1.0.0 manifest is validated
    Then the portable manifest is rejected

  Scenario: Reject an unsafe prerequisite declaration
    Given a prerequisite package with shell syntax
    When the prerequisite declaration is validated
    Then the prerequisite declaration is rejected

  Scenario: Export without host-native files
    Given a package with Claude Code and Codex host files
    When the package is exported for Agent Plugins v1.0.0
    Then the portable package keeps skills and namespaced extensions
    And the portable package excludes native host files

  Scenario: Reject an unreviewed package-root entry
    Given a package with an unreviewed package-root entry
    When the package is exported for Agent Plugins v1.0.0
    Then the portable export is rejected

  Scenario: Accept a fully supported finding
    Given a finding with complete current supporting evidence
    When the finding contract is validated
    Then the finding is accepted

  Scenario: Reject unstated uncertainty
    Given a limited-confidence finding without an uncertainty statement
    When the finding contract is validated
    Then the finding is rejected for missing uncertainty

  Scenario: Reject an unsupported delivery claim
    Given a merged delivery claim without merge evidence
    When the finding contract is validated
    Then the finding is rejected for missing delivery evidence
