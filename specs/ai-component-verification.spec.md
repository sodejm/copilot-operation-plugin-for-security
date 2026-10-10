# Offline AI component verification

This contract verifies a bounded, versioned local manifest of behavior-bearing
AI components. It does not load prompts, execute skills or tools, fetch a URL,
or validate a publisher signature itself. Signature-verification results and
active-invocation observations are supplied as evidence and are reported with
their limitations.

## Acceptance criteria

- [ ] Accept only `cops.ai-components/v1` manifests with bounded components,
  dependency identifiers, expected publisher identity, provenance references,
  and a policy version.
- [ ] Canonicalize behavior-bearing MCP name, description, schemas and policy;
  detect a changed tool description/schema and prompt or skill content digest.
  JSON member order produces the same identity.
- [ ] Keep integrity, authenticity, licensing/provenance and organization
  approval separate. A matching digest alone is only integrity evidence.
- [ ] Require each component to name a registered #209 licensing decision and
  preserve its ID and rationale in the verification report.
- [ ] Report unsupported verification, missing provenance, failed signature,
  untrusted signer, revoked evidence, explicitly approved component and allowed
  unsigned component as distinct results.
- [ ] Treat a manifest-supplied `verified` signature status as an unverified
  claim unless it matches a caller-supplied trusted verification receipt for the
  same component and canonical identity. A signing-required policy rejects every
  non-receipt-backed state.
- [ ] Treat an opaque mutable alias as limited assurance; never invent an
  immutable digest for it.
- [ ] Bind an observed invocation to the declared component identity and report
  a substituted component without executing it.
- [ ] Mark a baseline stale when a depended-on component changes; a later
  restoration retains the stale state until a separate review records approval.
  Reports identify declared dependent tests and affected assessment scope.
- [ ] Consume a normalized `cops.ai-inventory/v1` snapshot from issue #235 when
  one is supplied, and reject a declaration whose component is absent from it.

## Boundary and evidence rules

The verifier retains only component IDs, canonical identities, policy version,
and supplied evidence IDs in its output. Content, URLs and descriptions are
untrusted data. A caller is responsible for retaining the underlying signed
evidence, receipt, and cryptographic signature verification. A trusted receipt is
accepted as caller-supplied evidence, never an assertion that this module verified
a signature or reviewer. Executable identity remains the separate #187 control.
