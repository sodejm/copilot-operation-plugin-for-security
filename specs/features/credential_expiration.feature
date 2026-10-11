Feature: Connector credential expiration lifecycle
  Scenario Outline: Expired credentials refresh the rejected page once
    Given a private checkpoint for the "<adapter>" adapter
    When a later page rejects an expired credential and accepts one refresh
    Then two unique pages are available without exposing the credential
    Examples:
      | adapter |
      | graph   |
      | arg     |

  Scenario: Failed credential refresh preserves accepted evidence
    Given a private checkpoint for the "graph" adapter
    When a later page rejects an expired credential and refresh fails
    Then only the accepted page remains with a redacted authentication result
