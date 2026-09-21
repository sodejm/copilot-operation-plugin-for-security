Feature: Portable cybersecurity marketplace
  As a marketplace maintainer
  I want deterministic organization and evidence gates
  So that packages remain discoverable and claims remain factual

  Scenario: Validate the categorized marketplace catalog
    Given the repository marketplace catalog
    When the marketplace contract is validated
    Then every package is categorized and indexed for each supported host

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
