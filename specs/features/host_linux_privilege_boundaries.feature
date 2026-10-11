Feature: Offline Linux privilege-boundary evidence classification
  Imported host evidence must not be confused with verified live exploitation.

  Scenario: A synthetic canary crossing is reported with context and cleanup
    Given the positive synthetic Linux host fixture
    When the host privilege-boundary importer assesses it
    Then the report identifies a reported canary crossing from synthetic evidence
    And all eight Linux surfaces have explicit coverage states
    And the selected check records its kernel, distribution version, namespace, and protections

  Scenario: Negative and fixed canaries remain blocked
    Given the negative and fixed synthetic Linux host fixtures
    When the host privilege-boundary importer assesses both
    Then both reports identify reported blocked canaries

  Scenario: An unsupported prerequisite cannot prove a crossing
    Given a positive synthetic Linux host fixture with an unmatched namespace requirement
    When the host privilege-boundary importer assesses it
    Then the observation is inapplicable and has no success classification

  Scenario: A canary without cleanup evidence fails closed
    Given a positive synthetic Linux host fixture without verified cleanup
    When the host privilege-boundary importer attempts to assess it
    Then the importer rejects the incomplete canary report
