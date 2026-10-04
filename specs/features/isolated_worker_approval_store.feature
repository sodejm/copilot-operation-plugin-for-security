Feature: Isolated Execution Worker and Approval State Store
  As a security operations lead
  I need an isolated worker runtime and ACID approval state store
  So that authorized operations run within strict process boundaries and approvals cannot be double-spent

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
