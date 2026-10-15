Feature: Web API inventory and approved request replay
  Scenario Outline: Preserve supported API inventory formats
    Given an API definition in <format>
    When the definition is imported
    Then the inventory preserves its endpoints and authentication metadata
    And credential values are redacted

    Examples:
      | format       |
      | HAR 1.2      |
      | OpenAPI 3    |
      | Swagger 2    |
      | Postman      |
      | raw HTTP     |

  Scenario: Preview is side effect free
    Given a replay request for an explicitly allowed destination
    When the operator previews the replay
    Then no request reaches the destination
    And the preview reports zero dispatched requests

  Scenario: Live replay consumes exact approval
    Given an action plan bound to the exact request digests and destination
    And an approval authority receipt for that plan and worker identity
    And every request and redirect remains within engagement scope
    When the isolated worker executes the replay
    Then the approval is consumed once
    And the destination receives only the approved requests
    And the report redacts session credentials

  Scenario: Object authorization distinguishes owner, other user, and anonymous
    Given a vulnerable or corrected disposable API service
    When owner, other-user, and anonymous cases access the same object through REST and GraphQL
    Then owner access is allowed
    And anonymous access is denied
    And other-user access is a failure for the vulnerable service
    And other-user access is denied by the corrected service

  Scenario: Rate limit evidence is conclusive only after the configured threshold
    Given repeated requests from one bounded session
    When enough requests are observed
    Then missing throttling is a failure
    And an HTTP 429 response with retry guidance is a fix
    But too few observations are insufficient evidence
