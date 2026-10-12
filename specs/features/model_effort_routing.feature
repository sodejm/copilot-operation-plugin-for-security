Feature: Advisory model and effort routing
  COPS suggests suitable settings from verified host availability without changing access.

  Scenario: Routine work uses an efficient model
    Given a fresh catalog with an efficient model and a security flagship
    When I request advice for a documentation edit
    Then the efficient model is suggested at low effort

  Scenario: Security analysis benefits from a flagship
    Given a fresh catalog with an efficient model and a security flagship
    When I request advice for a trust boundary security review
    Then the security flagship is suggested at high effort

  Scenario: Gated models cannot be forced
    Given a fresh catalog whose security flagship has denied access
    When I request advice for a trust boundary security review
    Then no model is suggested and the access exclusion is explained

  Scenario: Missing discovery keeps current settings unknown
    When I request advice without a catalog or current settings
    Then host discovery is required and current settings are unverified
