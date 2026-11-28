Feature: Entra identity export freshness and evidence limits
  Scenario: A complete recent export supports review hypotheses
    Given a complete Entra fixture export
    When the analyst assesses it six hours after export
    Then the Entra report contains seven hypotheses supported by fresh sources

  Scenario: A stale export does not support current hypotheses
    Given a complete Entra fixture export
    When the analyst assesses it forty eight hours after export
    Then the Entra report identifies stale coverage without current hypotheses

  Scenario: An absent OAuth grant source stays unknown
    Given an Entra fixture export without an OAuth grant entry
    When the analyst assesses it six hours after export
    Then the Entra report identifies missing OAuth grant coverage without a consent claim

  Scenario: A partial OAuth grant source stays unknown
    Given an Entra fixture export with partial OAuth grant coverage
    When the analyst assesses it six hours after export
    Then the Entra report identifies incomplete OAuth grant coverage without a consent claim
