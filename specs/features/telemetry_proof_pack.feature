Feature: Offline telemetry proof correlation
  As a detection and pipeline operator
  I need each supplied synthetic marker stage assessed independently
  So that ambiguous or delayed exports do not certify a complete trace

  Scenario: Unique records support a complete trace
    Given one matching record for each of the five stages
    And every stage timestamp falls inside the manifest window including clock skew
    When the telemetry proof pack correlates the supplied records
    Then each stage is observed and the report is healthy

  Scenario: Duplicate destination marker remains visible
    Given two distinct destination records contain the same synthetic marker
    And the other four stages have one valid matching record each
    When the telemetry proof pack correlates the supplied records
    Then destination indexing is unresolved with both matching evidence IDs
    And its supplied evidence hash is retained
    And the other four stage observations are retained

  Scenario: Delayed indexing does not erase later supplied records
    Given destination indexing, query evaluation, and alert records occur after the capture window
    And source and routing records occur inside the capture window
    When the telemetry proof pack correlates the supplied records
    Then the three late stages are unresolved with their timestamps and evidence hashes
    And source and routing remain observed

  Scenario: Missing export does not establish a live outage
    Given no destination record was supplied for the synthetic marker
    When the telemetry proof pack correlates the supplied records
    Then destination indexing is missing and the report is broken
    And the report describes the status as supplied evidence only
