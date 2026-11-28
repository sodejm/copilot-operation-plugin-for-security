Feature: Bounded service entry-point validation
  As an operator giving COPS a plain-language assessment goal
  I want discovered endpoints classified before any follow-on action
  So that a port observation cannot silently become a service claim or an authorization to probe

  # In this executable laboratory, "independent evidence" means a fixture-owned
  # passive audit record rather than provider-authored output. The fixture and
  # verifier share one process, administrative authority, and parser; this is not
  # independently administered attestation or external target evidence. Cleanup
  # means fixture transport closure, not rollback or effect reversal.

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
    And duplicate assessment records for one completed probe are rejected as an invalid session

  Scenario Outline: Observed services route to each registered specialist family
    Given an approved endpoint with an independently recorded <service> protocol response
    When COPS prepares session handoffs
    Then it proposes the registered cops-pentest-specialist with the <skill> skill for that exact endpoint
    Examples:
      | service    | skill                                    |
      | HTTP       | web-api-inventory-and-replay             |
      | SSH        | network-remote-and-file-services         |
      | Redis      | network-data-services                    |
      | SMTP       | network-messaging-services               |
      | Docker API | network-developer-interfaces             |
      | DNS        | network-infrastructure-services          |
      | SOCKS      | network-legacy-and-proxy-services        |

  Scenario: A candidate is distinct from successful authorized use
    Given a reachable approved service with an observed protocol response
    When COPS prepares a service-validation handoff
    Then the result records a candidate and an auditable validation plan
    And it records neither a verified finding nor successful authorized use

  # Approval is consumed once when dispatch is durably recorded, and the passive
  # audit binds the exact dispatch correlation, one-use reference, and time.
  Scenario: A low-impact specialist probe records a benign service assessment
    Given an authorized exact plan for a disposable loopback SSH service on a nonstandard port
    And a bounded specialist provider is registered
    When the operator selects low-impact validation with a fresh attempt budget and approval receipt
    Then the provider connects only to that exact endpoint
    And independent protocol evidence records exposure, authentication, configuration, version, and trust
    And the result is benign without a verified finding or successful authorized use

  # Controlled proof atomically consumes the exact durable prerequisite from the
  # completed candidate attempt together with a fresh approval.
  Scenario: Controlled proof confirms a versioned configuration flaw and cleanup
    Given low-impact validation found a Redis candidate with a versioned issue 143 reproduction
    When the operator separately selects controlled proof with a fresh attempt budget and approval receipt
    Then protocol evidence and independent effect evidence are both retained
    And cleanup evidence is retained before the finding becomes verified
    And the report separates observed exposure, candidate, verified finding, and successful authorized use
    And ATT&CK mappings state their evidence limits and finding coverage records tested and untested dimensions
    And the report retains the issue 143 reproduction, version, remediation, approval receipt, and attempt provenance

  Scenario: A remediated protected service remains a non-finding
    Given an authorized exact plan for a disposable loopback service requiring authentication
    When a bounded low-impact specialist probe receives the protected response
    Then the result records the authentication boundary and remediation state
    And it does not claim a finding or successful authorized use

  # Ambiguity after durable dispatch remains uncertain and is never auto-retried;
  # insufficient evidence applies only when no uncertain effect remains.
  Scenario: Missing independent evidence fails closed
    Given a specialist provider returns no independently collected protocol evidence
    When the operator selects low-impact validation
    Then the result is insufficient evidence
    And it does not claim a candidate, verified finding, or successful authorized use

  Scenario: Provider availability is an explicit pre-dispatch gate
    Given no native or approved specialist provider is registered
    When the operator selects a validation action
    Then the result is provider unavailable
    And no attempt is reserved, approved, or dispatched

  Scenario: Every retry is a new bounded and approved action
    Given a validation attempt has a terminal receipt
    When the operator retries the validation
    Then the retry uses a new attempt identifier, budget reservation, and approval receipt
    And a reused attempt identifier fails before provider dispatch

  Scenario: Operator runs the public seven-family loopback service-validation journey
    Given a disposable seven-family loopback laboratory
    When the operator runs the public service-validation journey
    Then the journey discovers, routes, investigates, validates, and reports every fixture
    And the report retains independent evidence, authorization, budget, and cleanup provenance
    And external provider coverage remains explicitly unsupported
