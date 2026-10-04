---
name: credential-evidence-handling
description: Review and enforce credential redaction and evidence binding in worker execution streams.
---

# Credential and Evidence Handling Skill

This skill enforces zero-leakage standards for credentials and ensures all execution outputs are sealed in cryptographic evidence envelopes.

## Workflow

1. **Inspect Secret References**: Verify that action plans reference credentials only through opaque identifiers (`credential_references: ["cred-vault-01"]`), never plaintext tokens or keys.
2. **Stream Redactor Validation**: Test that `StreamRedactor` scrubs Bearer tokens, GitHub personal access tokens (`ghp_`), AWS keys (`AKIA...`), PEM private keys, and known engagement secrets.
3. **Evidence Artifact Hashing**: Verify that `EvidenceRecorder` writes redacted outputs to isolated artifacts and attaches SHA256 checksums to `cops.run-result/v1`.
