Feature: Offline Windows privilege-boundary evidence classification
  Imported Windows evidence must preserve prerequisites and never imply verified live exploitation.

  Scenario: A synthetic canary crossing is reported with Windows context
    Given the vulnerable synthetic Windows host fixture
    When the Windows host importer assesses it
    Then the report identifies a source-reported canary crossing
    And all seven Windows surfaces have explicit coverage states
    And the selected check records build, architecture, token, and protections

  Scenario: Protected and remediated canaries remain blocked
    Given the protected and remediated synthetic Windows host fixtures
    When the Windows host importer assesses both
    Then both reports identify source-reported blocked canaries

  Scenario: An unmatched build cannot select a check
    Given a vulnerable synthetic Windows host fixture with an unmatched build
    When the Windows host importer assesses it
    Then the Windows observation is inapplicable without a success classification

  Scenario: A canary without cleanup assertion fails closed
    Given a vulnerable synthetic Windows host fixture without cleanup assertion
    When the Windows host importer attempts to assess it
    Then the Windows importer rejects the incomplete canary report
