Feature: Offline Azure entitlement analysis
  Azure paths require validated local evidence, exact rights, and explicit assumptions.

  Scenario: Managed identity execution has its required evidence and assumptions
    Given an Azure bundle with VM execution prerequisites
    When the Azure analyzer evaluates the bundle
    Then a VM execution path is modelled reachable
    And every path evidence reference exists in the evidence ledger

  Scenario: Missing runtime context stays conditional
    Given an Azure bundle with VM execution prerequisites
    And the runtime assumptions are absent
    When the Azure analyzer evaluates the bundle
    Then VM execution remains conditional

  Scenario: Incomplete acquisition cannot establish reachability
    Given an Azure bundle with VM execution prerequisites
    And acquisition is incomplete
    When the Azure analyzer evaluates the bundle
    Then no path is modelled reachable

  Scenario: Integrity failure prevents report completion
    Given an Azure bundle with VM execution prerequisites
    And an evidence checksum is invalid
    When the Azure analyzer evaluates the bundle
    Then integrity failure prevents a completion marker

  Scenario: An alternate grant survives a proposed entitlement removal
    Given an Azure bundle with two independent secret access grants
    When the Azure analyzer evaluates the bundle
    Then each single removal leaves a reachable path

  Scenario: Collection planning stays read only
    Given an explicit Azure collection scope
    When the Azure collection plan is generated
    Then every planned request is a versioned read operation with a permission and reference

  Scenario: ARM deployment requires deployment and underlying resource rights
    Given an Azure bundle with ARM deployment prerequisites
    When the Azure analyzer evaluates the bundle
    Then an ARM deployment path is modelled reachable
    And every path evidence reference exists in the evidence ledger

  Scenario: An excluded deployment operation cannot establish reachability with incomplete group coverage
    Given an Azure bundle with ARM deployment prerequisites
    And deployment validation is excluded from the role
    When the Azure analyzer evaluates the bundle
    Then ARM deployment remains unknown because alternate grants are unresolved
