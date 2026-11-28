Feature: fail-closed AI export privacy
  Scenario: Split sensitive text is inspected before a sink sees it
    Given a policy that allows a provider assessment text field
    When a credential is split across stream chunks
    Then the sink receives one sanitized export and no raw chunk is released

  Scenario: Unknown content is refused
    Given a registered provider sink
    When an export has an unknown destination or attachment encoding
    Then no sink call occurs and the caller receives a bounded refusal

  Scenario: Nested tool evidence uses field actions
    Given a policy with tool argument and result field rules
    When nested evidence contains personal data, a credential, and an opaque identifier
    Then the sink receives deterministic redaction or scoped pseudonyms only

  Scenario: Sink failure has no raw fallback
    Given a sink that rejects a sanitized export
    When the boundary attempts delivery
    Then the failure is sanitized and no second delivery uses the source payload

  Scenario: Supported assessment export transforms before the caller sink
    Given a validated synthetic envelope and receipt and a registered assessment report sink
    When a caller invokes export_assessment_report
    Then the registered fake sink receives only the transformed report and an unregistered sink receives no call
