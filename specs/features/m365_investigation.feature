Feature: Bounded Microsoft 365 investigation acquisition
  Scenario: Reject a cross-origin pagination link before credential use
    Given a selected Microsoft 365 sign-in collection
    When the provider supplies a next link on another origin
    Then collection is partial and the next link is not requested

  Scenario: Correlate only explicit tenant-bound identities
    Given synthetic sign-in, audit, and service principal evidence
    When the analyst correlates the three source records
    Then the report preserves source provenance and a shared IP alone makes no identity match

  Scenario: Correlate OAuth application consent and mail access
    Given synthetic OAuth grant, mail message, and service principal evidence
    When the analyst correlates the cloud app evidence
    Then the report correlates user and application entities without leaking tokens

  Scenario: Correlate Defender security alert with risky sign-in
    Given synthetic Defender security alert and sign-in evidence
    When the analyst correlates the endpoint alert evidence
    Then the report identifies matching entity leads while preserving alert severity
