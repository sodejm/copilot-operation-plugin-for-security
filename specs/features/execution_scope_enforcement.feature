Feature: Execution Scope and Network Egress Enforcement
  As a security compliance lead
  I need execution-time destination validation and network egress controls
  So that operations cannot expand scope, query cloud metadata, or reach excluded resources

  Scenario: Allowing in-scope network destinations
    Given an engagement scope containing included subnet "10.0.0.0/24" and domain "corp.internal"
    When the ScopeGuard verifies destination "10.0.0.15"
    Then the destination is permitted
    When the ScopeGuard verifies destination "corp.internal"
    Then the destination is permitted

  Scenario: Blocking excluded IP destinations
    Given an engagement scope containing included subnet "10.0.0.0/24" with excluded IP "10.0.0.1"
    When the ScopeGuard verifies destination "10.0.0.1"
    Then the destination is rejected as an excluded target

  Scenario: Blocking cloud instance metadata queries
    Given an engagement scope
    When the ScopeGuard verifies destination "169.254.169.254"
    Then the destination is rejected as a blocked cloud metadata address

  Scenario: Preventing DNS rebinding attacks to metadata endpoints
    Given a hostname "rebind.malicious.corp" resolving to cloud metadata IP "169.254.169.254"
    When the ScopeGuard verifies the hostname destination
    Then the destination is rejected as a blocked cloud metadata address

  Scenario: Binding an authenticated resource to an exact request target
    Given an approved authenticated service identity and exact HTTPS request target
    When the mediator verifies the live destination, TLS identity, and request target
    Then the request is dispatched only when every binding matches exactly

  Scenario: Requiring operating-system containment for mandatory mediation
    Given an adapter receives an egress broker capability
    When the adapter executes in the worker network sandbox
    Then direct IPv4 and IPv6 connections are denied and mediated broker requests remain available

  Scenario: Dispatching one exact POST through an operator gateway
    Given a signed dispatch descriptor for authorization "auth-1" and dispatch "dispatch-1"
    And the descriptor binds one gateway origin, request target, SPIFFE identity, account, project, region, model, endpoint, body digest, and body length
    And the worker has a matching bounded request body
    When the worker completes gateway transport preflight
    Then it sends exactly one HTTPS POST to the bound gateway origin and request target
    And it treats the provider target only as signed authorization data and exposes no provider credential to the worker

  Scenario: Rejecting an invalid gateway POST before consuming approval
    Given a pending one-use authorization and a signed dispatch descriptor
    When the gateway origin, request target, SPIFFE identity, body digest, or body length fails validation
    Then the worker sends no request
    And the authorization remains unconsumed

  Scenario: Rejecting redirects and retries for a gateway POST
    Given an approved gateway POST dispatch has been transmitted once
    When the gateway returns a redirect or the connection result is unknown
    Then the dispatch is recorded with a redacted rejected or unknown outcome
    And the worker does not follow a redirect or send another request

  Scenario: Rejecting a replayed dispatch at the gateway
    Given a gateway has durably claimed dispatch "dispatch-1"
    When it receives another request for dispatch "dispatch-1"
    Then it rejects the request before an upstream provider attempt
    And it emits only redacted replay evidence

  Scenario: Keeping synthetic gateway evidence free of provider data
    Given the loopback-only gateway emulator receives a valid dispatch
    When it validates the descriptor and returns a synthetic outcome
    Then its evidence contains only identifiers, hashes, byte counts, decision codes, and bounded status metadata
    And it contains no provider credential, raw request body, authorization header, raw provider response, or provider network destination
