Feature: One request completes a Detection Quality fixture review
  Scenario: Report the telemetry gaps in both packaged suites
    Given an operator requests a review of both bundled detection fixture sets
    When COPS completes the request
    Then the Detection Engineer uses the Detection Quality review skill
    And the report identifies the missing Sentinel and Splunk telemetry

  Scenario: Complete the review from one Copilot chat request
    Given an operator requests a review of both bundled detection fixture sets
    When the Copilot tool accepts the ask and continues with its returned run ID
    Then the Detection Engineer uses the Detection Quality review skill
    And the report identifies the missing Sentinel and Splunk telemetry
