Feature: Credential Masking and Evidence Capture

  Scenario: Masking sensitive bearer tokens in worker output stream
    Given a stream redactor configured with default patterns
    When redacting the stream text "Authorization: Bearer secret_access_token_12345678"
    Then the redacted text contains "Bearer [REDACTED:TOKEN]"
    And the secret "secret_access_token_12345678" is not in the redacted text

  Scenario: Masking known engagement secret in worker output stream
    Given a stream redactor configured with known secret "ClientProdSecret2026!"
    When redacting the stream text "Connecting using ClientProdSecret2026! to admin console"
    Then the redacted text contains "[REDACTED:SECRET]"
    And the secret "ClientProdSecret2026!" is not in the redacted text

  Scenario: Recording step telemetry and generating evidence hashes
    Given an evidence recorder with a temporary workspace
    When recording execution output with a synthetic credential for step "step01"
    Then the recorded artifact is saved to disk
    And the artifact contains "[REDACTED:GITHUB_TOKEN]"
    And at least one evidence hash is generated
    And the synthetic credential is absent from the artifact

  Scenario: Rejecting a credential grant bound to another worker
    Given a consumed authorization for worker "worker-bdd"
    And a credential grant bound to worker "other-worker"
    When worker "worker-bdd" requests the approved operation credential
    Then credential resolution is rejected before provider access

  Scenario: Treating prompt injection as untrusted evidence data
    Given an evidence recorder configured with known secret "ClientProdSecret2026!"
    When recording adversarial output containing the known secret
    Then the serialized evidence excludes the known secret
    And the evidence classifies output as untrusted data only
    And the evidence includes exact operation provenance

  Scenario: Blocking persistence when evidence redaction fails
    Given an evidence recorder whose redactor fails
    When recording output with the failing redactor
    Then no evidence record or artifact is persisted
