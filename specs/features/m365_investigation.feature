Feature: Bounded Microsoft 365 investigation acquisition
  Scenario: Reject a cross-origin pagination link before credential use
    Given a selected Microsoft 365 sign-in collection
    When the provider supplies a next link on another origin
    Then collection is partial and the next link is not requested

  Scenario: Correlate only explicit tenant-bound identities
    Given synthetic sign-in, audit, and service principal evidence
    When the analyst correlates the three source records
    Then the report preserves source provenance and a shared IP alone makes no identity match
