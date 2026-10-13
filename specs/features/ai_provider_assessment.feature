Feature: Offline AI provider assessment fixtures
  Provider-shaped synthetic responses are normalized under one plan and budget contract.

  Scenario: Four provider families use the same assessment report
    Given an offline synthetic provider plan for OpenAI, Azure, AWS, and GCP
    When the approved response fixtures are assessed
    Then every family has a completed result with known synthetic usage
    And no provider content or endpoint appears in the report

  Scenario: A changed boundary is denied before fixture processing
    Given a case with a changed tenant, endpoint, model, request, or tool
    When the case is assessed against the plan
    Then the gate denies it without a budget attempt or provider effect

  Scenario: Partial usage remains charged and the budget can stop later cases
    Given an approved partial response with no usage
    When the case is assessed
    Then its budget attempt remains usage unknown
    And a later attempt beyond the budget is denied

  Scenario: Live and paid plans are unavailable
    Given a provider assessment plan requesting live or paid execution
    When the plan is loaded
    Then the runner rejects it before credential or network access
