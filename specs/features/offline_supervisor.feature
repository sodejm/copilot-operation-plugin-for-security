Feature: Owner-provisioned offline supervisor profile
  The configured profile must not be selected or removed by a relay request.
  These scenarios use in-process test authority, not a deployed SSH host.

  Scenario: Construct an offline worker without network capabilities
    Given an owner-provisioned offline supervisor with signed test approval
    When the supervisor constructs its worker
    Then only the offline profile is required and no external capabilities are configured

  Scenario: Reject a request with its offline profile removed
    Given an owner-provisioned offline supervisor with signed test approval
    When a relay request omits the offline profile
    Then the request is rejected before approval consumption

  Scenario: Reject credentials and egress in offline configuration
    Given an owner-provisioned offline supervisor with signed test approval
    When offline configuration includes credentials or egress
    Then every conflicting configuration is rejected
