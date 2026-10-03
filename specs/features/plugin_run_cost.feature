Feature: Local plugin run cost accounting
  Operators can price explicitly attributed executions and compare transparent scenarios.

  Scenario: Import copied session evidence once and report its exact price
    Given synthetic plugin cost inputs in a private workspace
    When I import the session and its copy twice through the cost CLI
    And I report the private cost ledger
    Then two unique requests have a complete API equivalent and reproducible pricing

  Scenario: Missing service tier remains unpriced
    Given synthetic plugin cost inputs in a private workspace
    And the manifest has no service tier assumption
    When I import the session and its copy twice through the cost CLI
    And I report the private cost ledger
    Then the run has unpriced requests and no accepted-result price

  Scenario: Profile local inputs and scale a forecast
    Given synthetic plugin cost inputs in a private workspace
    When I profile repository wiki and threat model inputs through the cost CLI
    And I forecast the profiled input through the cost CLI
    Then duplicate content is counted once and the forecast retains its assumptions

  Scenario: Compare employee and hybrid costs at the agreed volume
    Given synthetic plugin cost inputs in a private workspace
    When I compare manual and hybrid work through the cost CLI
    Then annual capacity and recurring savings use three runs weekly and the supplied hourly rates

  Scenario: Reject a profile without input
    When I request a cost profile with no sources
    Then the cost CLI reports missing input instead of zero cost
