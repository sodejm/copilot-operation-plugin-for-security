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
