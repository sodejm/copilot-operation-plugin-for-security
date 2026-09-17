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
    Given an aggregate gate with a failing plugin validation command
    When the aggregate gate runs
    Then the gate returns failure and still runs the scenario suite
