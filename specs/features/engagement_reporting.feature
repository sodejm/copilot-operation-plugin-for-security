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
