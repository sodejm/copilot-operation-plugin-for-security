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
    When recording execution output "API returned ghp_abcdefghijklmnopqrstuvwxyz1234567890" for step "step-01"
    Then the recorded artifact is saved to disk
    And the artifact contains "[REDACTED:GITHUB_TOKEN]"
    And at least one evidence hash is generated
