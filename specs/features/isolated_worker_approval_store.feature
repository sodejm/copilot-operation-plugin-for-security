Feature: Isolated Execution Worker and Approval State Store
  As a security operations lead
  I need verifier trust, active engagement, worker capability attestation, and an ACID approval store
  So that only compatible authorized plans dispatch and approvals cannot be double-spent

  Scenario: Consuming a provisioned approval through a separate authority
    Given a signed approval provisioned outside the execution worker
    And a protected approval authority bound to the expected worker process
    When the worker submits the authorization identifier and exact action plan
    Then the authority verifies and consumes the stored approval exactly once
    And the worker never receives a signing key or approval registration capability

  Scenario Outline: Rejecting an approval control boundary mismatch
    Given a signed approval provisioned outside the execution worker
    When an approval control request has a "<mismatch>" mismatch
    Then the authority rejects the request without consuming the approval

    Examples:
      | mismatch          |
      | worker UID        |
      | worker GID        |
      | worker process    |
      | worker identity   |
      | action plan       |
      | authorization ID  |

  Scenario: Refusing dispatch without required Linux isolation
    Given a compatible approved action plan
    And a worker host missing a required process sandbox control
    When the worker checks readiness before execution
    Then the worker rejects dispatch without consuming the approval

  Scenario: Refusing a remote host or worker identity mismatch
    Given a versioned execution request over host-key-verified SSH
    When the SSH host identity or worker identity differs from the request
    Then the worker rejects the request before dispatch

  Scenario: Storing an approval and executing an authorized action plan
    Given an initialized SQLite approval store
    And a valid action plan and signed authorization envelope
    When the authorization envelope is registered in the approval store
    And the isolated worker executes the authorized plan
    Then the execution result is "success"
    And the authorization status in the approval store is updated to "consumed"
    And the ephemeral workspace directory is cleaned up

  Scenario: Preventing concurrent double-spending across workers
    Given an approved authorization envelope in the approval store
    When multiple worker threads attempt to atomically consume the approval simultaneously
    Then exactly one worker successfully consumes the approval
    And all other worker requests fail with a conflict error

  Scenario: Enforcing tool whitelisting and resource limits
    Given an isolated worker configured with allowed tools "echo"
    And an authorized action plan requesting an unapproved tool "unauthorized_scanner"
    When the worker executes the plan
    Then execution fails with status "failed"
    And the status details state that the tool is not allowed

  Scenario Outline: Normalizing adapter process outcomes
    Given an authorized fake adapter action plan
    When the fake adapter reports "<outcome>"
    Then the execution result is "<status>"
    And the execution exit code is <exit_code>

    Examples:
      | outcome         | status    | exit_code |
      | success         | success   | 0         |
      | timeout         | uncertain | 124       |
      | output overflow | uncertain | 125       |
      | failure         | failed    | 9         |

  Scenario Outline: Suppressing incomplete adapter output before persistence
    Given an authorized fake adapter action plan
    When the fake adapter reports "<outcome>"
    Then the execution result is "uncertain"
    And the execution exit code is <exit_code>
    And the persisted adapter output is empty

    Examples:
      | outcome         | exit_code |
      | timeout         | 124       |
      | output overflow | 125       |
