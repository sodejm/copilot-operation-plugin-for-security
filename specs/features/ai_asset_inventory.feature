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

  Scenario: A selected LangSmith query-runs response becomes a bounded graph
    Given a versioned offline LangSmith v2 query-runs response
    When chain, LLM, embedding, retriever and tool operation records are imported for a tenant
    Then present parent-child and observed semantic relationships retain selected-record provenance
    And every imported record remains a generic restricted agent run with unknown trust
    And operation types do not invent provider resources, MCP registration or privileges
    And missing parents and pagination remain explicit unknowns without invented edges
    And raw trace content and unsupported response fields are rejected

  Scenario: LangSmith inventory export uses the privacy boundary
    Given an imported LangSmith inventory report and a caller-provided sink
    When the report is exported through the concrete export boundary to a registered report sink
    Then the boundary receives only the bounded report and its restricted reference
    And an unregistered or non-report sink is refused without fallback output
    And a boundary refusal produces no fallback export
