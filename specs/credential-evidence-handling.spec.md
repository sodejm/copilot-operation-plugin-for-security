# Specification: Scoped Credentials and Execution Evidence

## Purpose

Permit a credential to enter only the approved operation process and produce
schema-validated `cops.evidence/v1` records without persisting raw credentials or
unredacted execution data.

## Credential resolution boundary

`cops.execution.ScopedCredentialResolver` accepts the authority-issued
`ApprovalConsumptionReceipt` returned by the worker's consume-only
`ApprovalControl.consume_authorization` call for the current dispatch. A
caller-created authorization whose fields merely say `consumed` is not authority.
The worker passes the exact receipt returned by that control to the resolver
immediately before an approved operation launch. The resolver defensively checks
the receipt's authorization digest, plan identifier and digest, engagement,
worker, and target bindings before provider access.

Every `CredentialGrant` binds one declared reference to all of these values:

- plan identifier and digest;
- engagement, target, and worker identity;
- operation step, tool, tool version, and action; and
- a dedicated `COPS_CREDENTIAL_*` environment variable.

The plan's credential references form an allowlist. Each operation receives only
its exact grants, so different steps can use different credentials and a step with
no grant remains credential-free. An exact grant that names an undeclared
reference fails closed. Provider values must be non-empty text without a NUL byte.
Reserved loader, broker, runtime, locale, and ordinary process variables cannot be
overwritten because credential variables require the dedicated prefix.

Executable discovery and version probing receive no credential environment. After
all bindings match, the resolver obtains the provider values, registers all of
them with the evidence redactor, and returns an operation-only environment. A
provider or redactor failure exposes a stable secret-free error and prevents the
operation from launching.

## Evidence capture boundary

`cops.execution.EvidenceRecorder` requires a complete `EvidenceContext` for real
execution. Each record is a validated `cops.evidence/v1` envelope with exact plan,
authorization, engagement, worker, target, step, tool, tool-version, and action
provenance.

Before anything is persisted, the recorder:

1. redacts stdout, stderr, errors, artifact identifiers, and artifact content;
2. reduces streams, errors, and artifact content to redacted bytes or
   non-reversible metadata;
3. rejects absolute, drive-qualified, empty-component, and traversal artifact
   identifiers; and
4. constructs and validates the evidence envelope.

Only after those gates succeed does it write the reserved redacted output inode
and append the evidence record. Any redaction or schema-validation failure
discards the reservation and leaves no evidence record or artifact. Tool output is
classified as untrusted data; text that resembles an instruction never becomes
worker authority.

`StreamRedactor` scans byte and text streams for configured secrets and common
token, private-key, and password patterns. Known secrets are replaced with
`[REDACTED:SECRET]`; pattern matches use their specific redaction markers.

## Storage and retention

Raw stream, error, artifact-identifier, and artifact-content values are held in
memory only long enough to redact them. Raw persistence is prohibited. Timeout or
raw-output overflow discards all retained raw bytes because collection can stop
inside a secret.

Redacted output is stored in the owner-controlled workspace. On POSIX systems the
recorder enforces private directories and `0600` evidence files and uses held
directory and file descriptors to resist path substitution. These permissions are
access controls; they do not encrypt evidence at rest. Deployments that require
encryption must provide an encrypted filesystem or storage service independently.

COPS does not automatically delete redacted evidence. The workspace owner controls
retention and must apply the engagement's retention schedule and deletion process.
The lifecycle fields describe these enforced write controls and the absence of
automatic deletion; a policy label by itself does not perform deletion or prove
encryption.

## Acceptance evidence

- Cross-worker and exact-operation grants with a mismatched plan digest,
  engagement, or target fail before provider access. Grants for a different plan
  or operation cannot supply a credential to the current operation and cause no
  provider access.
- Different operations receive only their exact grants; a credential-free
  operation receives an empty environment.
- NUL-bearing values, reserved environment names, provider failures, and redactor
  failures prevent launch without exposing provider text.
- Secrets are absent from serialized evidence, stream/error metadata, artifact
  identifiers, artifact content metadata, and persisted output.
- Prompt-injection text remains untrusted evidence data with exact provenance.
- Envelope validation and redaction complete before persistence; failure leaves no
  record or artifact.
- Unsafe absolute and traversal artifact identifiers fail closed.
