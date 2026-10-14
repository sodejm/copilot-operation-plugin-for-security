Feature: Bounded service entry-point validation handoff
  As an operator giving COPS a plain-language assessment goal
  I want discovered endpoints classified before any follow-on action
  So that a port observation cannot silently become a service claim or an authorization to probe

  Scenario: An observed protocol on a nonstandard port is routed without changing the endpoint
    Given an approved endpoint with an SSH protocol banner on TCP port 2222
    When COPS prepares a service-validation handoff
    Then it proposes the registered cops-pentest-specialist with the network-remote-and-file-services skill for that exact endpoint
    And its plan requires a separate execution authorization and a bounded budget
    And preparing the handoff sends no network request

  Scenario: Port association alone does not establish a service or finding
    Given an open TCP port with no protocol response and a port-derived HTTP fingerprint
    When COPS prepares a service-validation handoff
    Then the service remains unverified
    And no specialist action or verified finding is claimed

  Scenario: Unapproved and unavailable endpoints fail closed
    Given a discovered endpoint outside the approved endpoint set
    When COPS prepares a service-validation handoff
    Then it is blocked without a follow-on plan
    And closed or unreachable endpoints likewise receive no follow-on plan

  Scenario: A scan checkpoint cannot grant scope or clear quarantine
    Given a checkpoint lists an endpoint as approved and records a resolution quarantine
    When COPS prepares session handoffs against separately validated engagement endpoints
    Then a checkpoint approval alone cannot produce a plan
    And the quarantined host stays blocked regardless of letter case

  Scenario: A recorded assessment must belong to the completed scan probe
    Given an approved endpoint with a recognized protocol response
    But its evidence has missing or mismatched active-scan provenance
    When COPS prepares session handoffs
    Then it returns no specialist plan
    And it names the session or evidence repair needed before routing

  Scenario: An observed service without a registered route stays unsupported
    Given an approved endpoint with a recorded HTTP protocol response
    When COPS prepares session handoffs
    Then it reports the missing registered service skill
    And it proposes no specialist action

  Scenario: A candidate is distinct from successful authorized use
    Given a reachable approved service with an observed protocol response
    When COPS prepares a service-validation handoff
    Then the result records a candidate and an auditable validation plan
    And it records neither a verified finding nor successful authorized use
