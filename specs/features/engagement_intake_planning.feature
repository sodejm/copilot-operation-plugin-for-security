Feature: Engagement Intake and Execution Planning
  As a cybersecurity operations lead
  I need rigorous engagement intake, scope validation, and mode enforcement
  So that adversarial assessments are strictly authorized, reviewable, and safe

  Scenario: Ingesting a valid bounded engagement
    Given a valid engagement specification with targets "10.0.0.5,api.internal" and exclusions "10.0.0.1"
    When the engagement intake is validated
    Then the intake validation succeeds with status "planned"
    And the engagement scope contains 2 included targets and 1 excluded target

  Scenario: Rejecting engagement with missing owner
    Given an engagement specification with an empty operator
    When the engagement intake is validated
    Then the intake validation fails with error "MissingOwnerError"

  Scenario: Rejecting engagement with ambiguous wildcard target
    Given an engagement specification with included target "*"
    When the engagement intake is validated
    Then the intake validation fails with error "ScopeAmbiguityError"

  Scenario: Rejecting engagement with incompatible assessment window
    Given an engagement specification with end time preceding start time
    When the engagement intake is validated
    Then the intake validation fails with error "IncompatibleWindowError"

  Scenario: Rejecting engagement with incomplete budget
    Given an engagement specification with negative budget duration
    When the engagement intake is validated
    Then the intake validation fails with error "IncompleteBudgetError"

  Scenario: Refusing incomplete live execution request
    Given an engagement specification requesting mode "live" without an execution budget
    When the engagement intake is validated
    Then the intake validation fails with error "IncompleteLiveRequestError"

  Scenario: Compiling an immutable reviewable action plan
    Given a valid bounded engagement and scenario "COPS-E03.01-S01"
    When an action plan is compiled for target "10.0.0.5"
    Then the action plan status is "draft"
    And the action plan includes platform prerequisites
    And the action plan operations include expected evidence, side effects, and cleanup obligations
    And the action plan digest is verifiable

  Scenario: Resolving a polite endpoint assessment question without execution
    Given a current engagement with the selected target "10.0.0.5"
    When the goal "Can you assess the selected endpoint?" is resolved
    Then the goal selects target "10.0.0.5"
    And the goal reports that no assessment occurred

  Scenario: Duplicate representations do not create multiple goal targets
    Given a current engagement with duplicate representations of target "api.internal"
    When the goal "Assess api.internal." is resolved
    Then the goal selects target "api.internal"

  Scenario: Oversized scope is rejected before intake validation
    Given a current engagement with more than 1024 scope entries
    When the goal "Assess the selected endpoint." is resolved
    Then the goal fails with code "scope_too_large"
