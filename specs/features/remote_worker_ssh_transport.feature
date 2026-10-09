Feature: Remote Worker SSH Transport
  As a security operations lead
  I need remote worker requests bound to a pinned SSH host and worker identity
  So that a request cannot be accepted from a substituted remote endpoint

  Scenario: Accepting a bounded response from the pinned host and worker
    Given a pinned SSH transport for host "worker.example.test" and worker "worker-lab-01"
    When the remote worker returns the matching versioned response
    Then the SSH transport returns the remote payload
    And strict host-key verification and forwarding protections were requested

  Scenario Outline: Refusing a remote response binding mismatch
    Given a pinned SSH transport for host "worker.example.test" and worker "worker-lab-01"
    When the remote worker returns a mismatched "<binding>"
    Then the SSH transport rejects the response before returning its payload

    Examples:
      | binding   |
      | protocol  |
      | request   |
      | host      |
      | worker    |

  Scenario Outline: Refusing an unbounded remote exchange
    Given a pinned SSH transport for host "worker.example.test" and worker "worker-lab-01"
    When the remote exchange exceeds its "<limit>" limit
    Then the SSH transport rejects the response before returning its payload

    Examples:
      | limit      |
      | response   |
      | diagnostic |
      | time       |
