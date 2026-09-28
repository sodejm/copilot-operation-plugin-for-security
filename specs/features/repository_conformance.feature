Feature: Portable COPS repository validation
  Contributor checks inspect project sources without traversing local artifacts.

  Scenario: Ignore local environments while retaining tracked ignored sources
    Given a Git checkout with tracked, new, and ignored Python files
    When repository sources are enumerated
    Then tracked and new sources are included
    And ignored local artifacts are excluded

  Scenario: Do not follow source symlinks outside the checkout
    Given a source archive with symlinks to external files and directories
    When repository sources are enumerated
    Then only the archive's own source is included

  Scenario: Ignore broken Python inside an archive's virtual environment
    Given a source archive with valid project Python and an invalid virtual environment
    When Python sources are validated
    Then Python validation passes
    When a new invalid project source is added
    Then Python validation fails

  Scenario: Keep product model guidance portable
    Given the COPS command and model guidance
    Then the command does not pin a model
    And model guidance requires the live host catalog

  Scenario: Propagate a failed aggregate check
    Given an aggregate gate with a failing package validation command
    When the aggregate gate runs
    Then the gate returns failure and still runs the scenario suite

  Scenario: Stop before repository checks when test prerequisites are missing
    Given an aggregate gate with missing test prerequisites
    When the aggregate gate runs
    Then the gate returns failure without running repository checks

  Scenario: Verify a prepared test environment without installing dependencies
    Given a prepared interpreter matching the declared test requirements
    When contributor test prerequisites are verified
    Then prerequisite verification passes without installing dependencies
