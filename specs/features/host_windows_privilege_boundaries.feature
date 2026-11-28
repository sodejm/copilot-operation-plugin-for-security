Feature: Windows privilege-boundary evidence classification
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

  Scenario: A native Windows bridge declares only the surfaces it assessed
    Given a capability-declared native Windows bridge export
    When the Windows host importer assesses it
    Then the report preserves the native bridge mode and explicit coverage

  Scenario: Same-token process observations and cleanup receipt are validated independently
    Given a native bridge export and assessment-owned cleanup receipt
    When the bridge receipt is validated against the export and empty canary root
    Then the receipt preserves the separate-process lifecycle observations without claiming a privilege crossing
