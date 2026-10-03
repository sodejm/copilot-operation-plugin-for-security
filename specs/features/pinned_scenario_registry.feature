Feature: Pinned Scenario and Provenance Registry
  As a security operations architect
  I need a validated catalog of canonical scenarios and pinned research provenance
  So that assessment capabilities are grounded in licensed research with zero orphan mappings

  Scenario: Validating complete scenario and provenance registry integrity
    Given the canonical scenario registry and provenance registry files
    When the registry integrity validator is executed
    Then the validation status is "valid"
    And exactly 13 provenance sources are loaded
    And at least 200 inventoried items are verified
    And at least 30 canonical scenarios are registered

  Scenario: Querying and filtering scenarios
    Given the scenario registry is loaded
    When querying scenarios with MITRE tactic "discovery"
    Then at least 5 matching scenarios are returned
    When querying scenarios with family "COPS-E10.01"
    Then the scenario "COPS-E10.01-S01" is present in the results

  Scenario: Inspecting scenario metadata and safety profiles
    Given the scenario "COPS-E01.01-S01"
    When its details are retrieved from the registry
    Then its title is "Network Port and Service Discovery"
    And its safety profile declares impact "read_only"
    And its provenance references source "S01" with license "MIT"

  Scenario: Verifying provenance sources and license pinning
    Given the provenance registry is loaded
    When inspecting the source "S07"
    Then its name is "Bishop Fox: Kubernetes Bad Pods"
    And its category is "article"
    And it contains 8 inventoried items
    And all inventory items resolve to valid scenario targets

  Scenario: Rejecting orphan mappings and duplicate scenario identifiers
    Given a scenario registry containing a duplicate scenario identifier
    When scenario integrity validation is executed
    Then the validation fails with error code "duplicate_scenario_id"
    Given a provenance registry containing an orphan scenario mapping
    When scenario integrity validation is executed
    Then the validation fails with error code "orphan_inventory_mapping"
