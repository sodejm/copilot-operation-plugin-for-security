Feature: Offline attack path workbench
  Scenario: APW-01 validates source integrity
    Given an illustrative local export and versioned input
    When the source hash differs from the declared hash
    Then analysis stops with an input gate error

  Scenario: APW-02 reconciles records and provenance
    Given accepted and malformed illustrative records
    When the export is normalized
    Then each accepted fact has a source pointer and malformed records are quarantined

  Scenario: APW-03 rejects invalid graph transitions
    Given an edge with a missing node or prerequisite
    When the graph is constructed
    Then the invalid transition is excluded with a gate reason

  Scenario: APW-04 separates structural and candidate paths
    Given observed and hypothetical conditional transitions
    When paths are traced to a user-defined crown jewel
    Then supported structural routes and candidate routes are separate

  Scenario: APW-05 produces stable rank and bounded blast radius
    Given duplicate routes and supported assets
    When paths are ranked
    Then equivalent routes are grouped and distinct supported assets are counted once

  Scenario: APW-06 leaves business impact unrated
    Given a path without an approved impact profile
    When consequences are assessed
    Then potential CIA effects are conditional and business rating is unrated

  Scenario: APW-07 blocks unspecified integrations
    Given no approved Wiz documentation or MITRE reference bundle
    When query and behavior output is requested
    Then query rendering is blocked and technique and flow outputs remain pending

  Scenario: APW-08 checks claims and reproducibility
    Given a report with cited material claims
    When identical inputs are analyzed twice
    Then canonical outputs match and the ledger has no invented owner or closure

  Scenario: APW-09 records specialist disagreements
    Given two conflicting structured specialist opinions
    When reviews are collected
    Then both opinions remain visible for human disposition

  Scenario: APW-10 exercises denial and recovery
    Given a broken illustrative export
    When the source is corrected and reanalyzed
    Then the corrected input succeeds without reusing the failed result

  Scenario: APW-11 bounds every untrusted read
    Given an illustrative manifest with an oversized source or unsafe path
    When the export is analyzed
    Then ingestion rejects the input before report completion
    And successful runs record effective limits and consumed budget

  Scenario: APW-12 stops bounded path search reproducibly
    Given an illustrative graph with more routes than the chosen search budget
    When analysis reaches an expansion, frontier, path, or report byte limit
    Then the v2 report records the effective limits, consumption, and stop reason
    And incomplete rankings are labelled as best discovered routes
    And the same policy and receipt replay during claim audit

  Scenario: APW-13 distinguishes complete and partial legacy report sets
    Given the four legacy reports target a fresh descriptor-anchored directory
    When any report write fails or the requested output parent is swapped
    Then no completion marker created by that invocation remains
    And successful runs bind all four exact report bytes in a last-written marker
