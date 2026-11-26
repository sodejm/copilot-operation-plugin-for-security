Feature: One request completes a Detection Quality fixture review
  Scenario: Report the telemetry gaps in both packaged suites
    Given an operator requests a review of both bundled detection fixture sets
    When COPS completes the request
    Then the Detection Engineer uses the Detection Quality review skill
    And the report identifies the missing Sentinel and Splunk telemetry
