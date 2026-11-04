Feature: Opt-in provider gateway contracts and adapters
  Versioned signed scope constrains provider requests; controlled results remain local evidence.

  Scenario: The v3 production contract requires complete signed scope
    Given bounded v3 production plan and cases
    When the production contract shape is validated
    Then scoped auth identities, transport, digests, and budgets are mandatory
    And unknown v3 contract fields are rejected

  Scenario: Historical emulator evidence remains readable without production eligibility
    Given historical v2 emulator plan and cases
    When their historical schemas are validated
    Then the documents remain readable
    But they cannot satisfy the v3 production contract

  Scenario: Provider endpoint aliases cannot satisfy the v3 contract
    Given bounded v3 production plan and cases
    When a provider target contains a normalization alias
    Then the v3 contract rejects the target

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

  Scenario: Provider dispatch and local tool share a parent allowance
    Given a local tool has reserved allowance under an agent parent
    When approved provider canaries dispatch under that parent
    Then each provider dispatch consumes the remaining subtree allowance
    And a further provider dispatch is denied before gateway send

  Scenario: A provider child cannot widen its parent allowance
    Given a live provider case with a narrower agent parent budget
    When its provider child requests wider limits
    Then the widened provider child is denied before gateway send

  Scenario: Concurrent provider dispatches compete for one allowance
    Given two approved provider cases with one shared concurrency slot
    When both provider dispatches start concurrently
    Then only one provider request reaches its gateway emulator
