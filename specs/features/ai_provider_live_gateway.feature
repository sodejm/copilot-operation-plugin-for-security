Feature: Opt-in provider gateway emulator
  A signed one-use dispatch and shared budget constrain synthetic provider requests.

  Scenario: Four approved text canaries pass their provider envelopes
    Given approved live emulator cases for OpenAI, Azure, AWS, and GCP
    When each case is dispatched through its signed gateway emulator
    Then each result has a normalized outcome and a conservative budget state
    And no prompt, endpoint, account, or provider output appears in public evidence

  Scenario: A changed authorization boundary cannot dispatch
    Given a live case with a changed gateway, worker, provider scope, request, or canary
    When its gateway admission is evaluated
    Then the case is denied before a provider-shaped response is processed

  Scenario: One-use authorization and exhausted budget stop subsequent sends
    Given a previously consumed grant or an exhausted shared budget
    When a further live dispatch is attempted
    Then the emulator sends no second request

  Scenario: Unknown results remain charged without replay
    Given a dispatched case with a malformed, partial, cancelled, or disconnected result
    When the live result is recorded
    Then the attempt remains uncertain without automatic retry

  Scenario: Tool output remains an inert proposal
    Given an admitted provider response with a tool proposal
    When the response is normalized
    Then no provider tool is executed
