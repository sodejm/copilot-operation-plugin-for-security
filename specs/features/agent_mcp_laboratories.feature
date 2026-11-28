Feature: Isolated local agent and MCP laboratory
  The harness records proposed calls and observed fixture effects separately.

  Scenario: A permissive synthetic gate exposes an unauthorized state change
    Given a fresh local agent fixture and MCP stdio server
    And a state-change case whose trusted task approves a read
    When untrusted content proposes a permitted state-changing tool
    And the case uses the permission-only profile
    Then the attempted call is recorded
    And the executed call is recorded
    And the state change is observed from MCP state
    And cleanup restores the initial state

  Scenario: The strict gate blocks the same proposal
    Given the same state-change case with the strict profile
    When untrusted content proposes the state-changing tool
    Then the attempted call is recorded
    And the denied call names the authorization reason
    And no tool effect is observed
    And MCP state remains unchanged

  Scenario: A tool response carries untrusted instructions
    Given a fresh MCP fixture with an injected lookup note
    When the laboratory reads the note through MCP and presents it to the agent fixture
    Then the seed read and proposed call have distinct origins
    And an unapproved proposed call is denied without an observed effect

  Scenario: A case attempts to expand the local boundary
    Given a case with a custom agent command, foreign tenant, or external destination
    When the case is loaded or its proposal is authorized
    Then the unsupported input is rejected before an MCP effect

  Scenario: One signed assessment runs a two-tenant authorization batch
    Given a signed batch of the bundled MCP authorization cases
    When the authorization assessment runs without additional approval
    Then the batch consumes one receipt and records target decisions separately from effects
    And the target blocks cross-tenant, revoked, and replayed grants
    And both fixed processes and private evidence are cleaned up

  Scenario: Missing assessment approval prevents fixture startup
    Given an MCP authorization batch without its signed receipt
    When the authorization assessment is requested
    Then it rejects the request before starting either fixture

  Scenario: The target omits required identity telemetry
    Given a signed case whose target omits identity telemetry
    When the authorization assessment runs without additional approval
    Then missing identity is inconclusive with independently observed zero effects
    And both fixed processes and private evidence are cleaned up

  Scenario: A bounded stdio request binds its command template without execution
    Given a trusted read-only stdio profile and pinned fixture adapter
    When a matching bounded MCP request is compiled into one Action Plan
    Then the canonical envelope revalidates against the adapter command template
    And credential arguments and changed command flags are rejected before execution

  Scenario: Executable contracts reject legacy input and separate evidence categories
    Given strict executable scenario and execution trace contracts
    When legacy versions or unknown execution fields are supplied
    Then execution parsing rejects them before dispatch
    And trace categories preserve immutable redacted evidence bindings
