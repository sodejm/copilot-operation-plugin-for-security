Feature: Progressive headless workbench requests
  Exploratory collaboration is lightweight and never grants execution authority.

  Scenario: Start from a task without formal engagement setup
    Given a task to inspect a supplied sample
    When the harness creates an exploratory work request
    Then the request succeeds without an Engagement or ActionPlan

  Scenario: Escalate a loose request without authorizing execution
    Given a task to inspect a supplied sample
    When the harness proposes execution outside offline work
    Then the proposal is blocked and grants no authority

  Scenario: Reject agent-selected host paths
    Given a task to inspect a supplied sample
    When the harness supplies a host output path to the tool
    Then the invocation fails without echoing the supplied path

  Scenario: Resume an explicitly accepted local task
    Given a private local operation runtime
    When the harness durably accepts a sample task
    Then the task is queued without execution
    When the harness resumes the accepted sample task
    Then its result is persisted and another resume does not repeat the attempt

  Scenario: Stateful operations do not silently configure themselves
    Given a task to inspect a supplied sample
    When the harness asks for durable status without runtime configuration
    Then the runtime blocks without creating state

  Scenario: Worker operations are unavailable
    When the harness requests a worker operation
    Then the operation is unavailable

  Scenario: Cancelled pure work is not retried after lease expiry
    Given a private local operation runtime
    When the harness durably accepts a sample task
    When the running pure attempt is cancelled and its lease expires
    Then recovery cancels the pure attempt without another handler call
