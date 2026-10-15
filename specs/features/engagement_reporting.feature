Feature: Evidence-bounded offline engagement reports
  As an operator reviewing an unattended assessment
  I need coverage and findings to reflect validated evidence
  So that a report cannot turn a scanner assertion into an observed outcome

  Scenario: A supported laboratory observation is assessed
    Given a valid offline assessment bundle
    When the assessment report is built
    Then its coverage and finding are assessed
    And the saved assessment report validates

  Scenario: An unverified observation does not corroborate a scanner assertion
    Given a valid offline assessment bundle
    And its finding is a scanner assertion with an unverified observation
    When the assessment report is built
    Then its coverage is partial
    And the saved assessment report validates

  Scenario: An incomplete embedded finding fails cleanly
    Given a valid offline assessment bundle
    And its finding has no result identifier
    When the assessment report is built
    Then report building fails with an invalid finding contract

  Scenario: A saved partial finding cannot retain recorded evidence strength
    Given a valid offline assessment bundle
    When the assessment report is built
    And the saved finding is changed to unsupported recorded evidence
    Then the saved assessment report is rejected

  Scenario: A saved scanner report cannot promote partial coverage
    Given a valid offline assessment bundle
    And its finding is a scanner assertion
    When the assessment report is built
    And the saved scanner coverage is changed to assessed
    Then the saved assessment report is rejected

  Scenario: A live observation outside the run window cannot validate coverage
    Given a valid offline assessment bundle
    And its live observation precedes the run window
    When the assessment report is built
    Then its live coverage and finding are not assessed
    And the saved assessment report validates

  Scenario: Evidence for one asset cannot assess a second asset
    Given a valid offline assessment bundle
    And its finding also affects a second asset without evidence
    When the assessment report is built
    Then the second asset is not assessed and the finding is partial
    And the saved assessment report validates

  Scenario: An attack path requires an acyclic prerequisite
    Given a valid offline assessment bundle
    And its attack path has a supported prerequisite
    When the assessment report is built
    Then its attack path and prerequisite validate
    When the saved prerequisite points back to the attack path
    Then the saved assessment report is rejected
