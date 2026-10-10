# Offline AI component verification

`cops.evidence.ai_components` compares a bounded `cops.ai-components/v1`
manifest with supplied local observations. It does not load component content,
fetch remote records, execute a tool, or cryptographically validate a signature.
Those operations require separate authorized controls.

Machine-readable structure is defined in
[`cops/evidence/schemas/ai-components-v1.schema.json`](../cops/evidence/schemas/ai-components-v1.schema.json).
The schema validates the manifest envelope. The offline Python verifier separately
validates registered licensing decisions, inventory linkage, and exact
caller-supplied receipt matching.

| Input | What is checked | Limitation |
| --- | --- | --- |
| MCP tool | Name, description, input/output schemas, and policy are canonicalized | Metadata can be deceptive; it is never executed |
| Prompt, skill, dataset | Declared content digest is bound into the component identity | The underlying content is not retained or fetched |
| Model alias | Alias and optional immutable digest are recorded | A mutable alias without a digest has limited assurance |
| Invocation | Caller-supplied component identity and manifest ID | It is observation evidence, not runtime enforcement |
| AI inventory | Optional normalized `cops.ai-inventory/v1` snapshot | Inventory completeness remains the source's stated completeness |

The report keeps integrity, authenticity, provenance, licensing, and organization
approval separate. A matching component identity establishes integrity only. Each
component must name a registered provenance decision through
`licensing_decision_id`; the report preserves that exact decision ID and rationale.
This links to the #209 decision registry, but does not represent a source-specific
reuse review unless the registry itself records one.

A manifest `signature.status: "verified"` is a claim until its `receipt_id`,
component ID, and canonical identity match an entry supplied in
`trusted_verification_receipts`. Receipts are trusted caller inputs; this module
does not verify receipt signatures or establish trust in a verifier. With
`signing_required: true`, every state other than a receipt-backed `verified`
signature is rejected, including `unsupported_verification`, `unsigned_allowed`,
missing signatures, and unverified claims.

```python
from cops.evidence.ai_components import verify_component_manifest

report = verify_component_manifest(manifest, observations=observations,
                                   revoked_evidence_ids=revoked_ids,
                                   trusted_verification_receipts=receipts,
                                   inventory=inventory, engagement_id="engagement-a")
```

When a component changes, callers must mark dependent assessment baselines stale
and require review and retest. Baselines declare both
`component_test_dependencies` and `component_assessment_scope`, so reports identify
the tests and assessment scope affected by the changed component. Restoring prior
content does not reset an existing stale baseline: a separate review record must do
that. Keep the source manifest, signed evidence, revocation evidence, receipt, and
review record under the engagement's retention policy; this module emits only
bounded identifiers and states. New manifest revisions remain `v1`-compatible only
when fields retain their current meaning. Incompatible semantics require a new
schema version and migration review.

| Capability mode | Evidence here | Excluded assurance |
| --- | --- | --- |
| `import` | Offline fixture and supplied inventory comparison | Live component behavior or signer cryptography |
| `laboratory` | A separately authorized test harness may provide observations | Production authorization or execution |
| `live-validated` | Requires separate documented deployment evidence | Never inferred from this verifier |
