# Specification: Credential Masking and Evidence Capture

## Purpose
Enforces zero-credential leakage across execution streams and provides deterministic cryptographic evidence recording. All worker outputs, whether standard output or standard error, are automatically redacted prior to persistence or inclusion in run-result contracts.

## Architecture
- `cops.execution.StreamRedactor`:
  - Scans character and byte streams for sensitive patterns (Bearer tokens, GitHub PATs, AWS access keys, RSA/EC private keys, JWTs, and password assignments).
  - Matches and replaces configured known engagement secrets with `[REDACTED:SECRET]`.
  - Replaces token and credential patterns with specific redaction tokens (`[REDACTED:TOKEN]`, `[REDACTED:PRIVATE_KEY]`, etc.).
- `cops.execution.EvidenceRecorder`:
  - Captures step execution metrics: `tool`, `action`, `exit_code`, timestamps, and output lengths.
  - Automatically pipes stdout and stderr through `StreamRedactor`.
  - Reserves a unique, collision-safe artifact inode under `<workspace>/artifacts/`
    before dispatch and revalidates its identity before writing redacted output.
  - Reports persisted artifact size and bytes truncated after redaction.
  - Produces canonical SHA256 digests for output artifacts and binds them into `evidence_records` on `cops.run-result/v1`.

## Security Boundaries
1. **No Cleartext Secret Persistence**: No raw credentials or tokens are saved to disk in ephemeral or persistent workspaces.
2. **Immutable Run-Result Evidence**: Run-result envelopes cryptographically link authorization signatures with individual step telemetry digests.
3. **Incomplete Output Suppression**: Timeout and raw-output overflow discard all
   retained raw bytes before redaction, hashing, or persistence because collection
   can stop inside a secret. Post-redaction artifact truncation is explicit in
   evidence metadata and changes an otherwise successful run to `partial` with exit
   code `125`.
4. **Path-Safe Failure Reporting**: Evidence reservation and write failures expose
   stable path-free reasons while preserving the underlying exception only for
   local debugging.
