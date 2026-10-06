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
