Feature: Offline-qualified Sentinel Hunt Workbench
  As a principal security engineer
  I want deterministic hunt authoring and adversarial qualification
  So that model-authored KQL is constrained by evidence and surface contracts

  Scenario: Validate the twelve-hunt gold library
    Given the Sentinel Hunt Workbench package
    When I validate the Sentinel hunt library
    Then exactly 12 gold hunt definitions pass the contract
    And no live-service assurance claim is awarded

  Scenario: Reject raw KQL parameter injection
    Given the Sentinel Hunt Workbench package
    When I render hunt "H01" with a raw KQL fragment parameter
    Then rendering fails closed as a content validation error

  Scenario: Run the deterministic adversarial corpus
    Given the Sentinel Hunt Workbench package
    When I run the Sentinel hunt test suite with seed 20260916
    Then 576 curated cases pass
    And at least 3000 generated perturbations pass
    And all critical semantic mutations are caught

  Scenario: Detect generated adapter drift
    Given the Sentinel Hunt Workbench package
    When I verify the generated platform adapters
    Then the adapter hashes match their canonical sources

  Scenario: Withhold offline qualification without external evidence
    Given the Sentinel Hunt Workbench package
    When I create a release qualification report
    Then the report is not offline qualified without two human approvals
    And the report marks cross-platform model evaluation as pending
