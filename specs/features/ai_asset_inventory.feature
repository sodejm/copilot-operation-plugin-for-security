Feature: AI asset inventory import
  Scenario: Imported run lineage stays bounded and tenant scoped
    Given a versioned AI inventory with an observed agent run and tool edge
    When the inventory is imported for its engagement
    Then the graph has tenant-qualified assets and selected-record provenance
    And raw trace content is not accepted

  Scenario: A malformed inventory does not produce partial state
    Given an inventory registry with a valid inventory
    When an inventory has a relationship to a missing asset
    Then the import is rejected with a malformed reference diagnostic
    And the valid snapshot remains available only to its engagement
