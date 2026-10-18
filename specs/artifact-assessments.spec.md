# Offline artifact assessment specification

## Contract

The implementation exposes:

```text
assess(capability, artifacts, *, as_of, engagement_id, result_id,
       scenario_id, max_artifacts, max_artifact_bytes, max_total_bytes)
```

The returned mapping has schema `cops.artifact-assessment/v1`, uses repository-valid `cops.finding/v1` findings, and includes `capability`, `assessment_mode`, `generated_at`, `readiness`, `finding_codes`, content-free `evidence`, `coverage`, `limitations`, and `prerequisites`.

## Required behavior

1. Input processing is offline and deterministic. It does not execute supplied code, decoded PowerShell, binaries, hooks, templates, or workflow steps. It does not use the network or shell.
2. Count, per-artifact byte, total-byte, decoded-PowerShell, record, and traversal bounds constrain processing.
3. Evidence contains the original canonical input digest and byte count. Forensic byte input is neither decoded nor modified.
4. Findings quote no source, prompt, scanner message, credential occurrence, token, or decoded payload content.
5. Explicit credential-value fields are rejected recursively with a stable content-free error. Credential-history assessment accepts opaque fingerprints only. The separate registered Git scanner recognizes bounded COPS, classic GitHub PAT, AWS access-key identifier, Bearer and PEM private-key shapes, emits opaque fingerprints and never includes matched bytes in output. Matches establish potential exposure, not credential validity.
6. Unsupported heavyweight or live formats return a limitation and a pinned registered-adapter prerequisite. They do not produce a passing readiness claim.
7. Missing or malformed required security evidence remains unknown through an unresolved finding or `insufficient_evidence` readiness.
8. An offline clean result cannot establish provider-side revocation, current advisory state, runtime segmentation, remote service trust, production configuration, or deployment readiness. Typed cryptographic verification establishes only the supplied local trust policy at the assessment timestamp.

## Capability assertions

- Application security parses Python syntax, examines bounded JavaScript/TypeScript or added diff lines, and ingests normalized scanner records for injection and visible route-authorization evidence.
- Foundry security compares direct or indirect injection test outcomes and observed tool calls with a supplied allowlist.
- Compliance evidence requires a named SOC 2, CIS, or NIST framework version, control identifier, status, evidence references, and collection time. Evidence older than 90 days is unresolved as stale.
- Forensic evidence verifies original-byte SHA-256, collection permission, and chronological custody metadata.
- Malware analysis performs static byte checks and bounded base64 decoding without execution or attribution claims.
- Cloud analysis uses typed Terraform 1.x effective-after resources, rendered Kubernetes/Helm workloads, RBAC and NetworkPolicy, and registered AWS/Azure/GCP export shapes. Unknown values and unsupported or malformed resources retain insufficient-evidence findings. Deny statements, deleted resources and outbound traffic cannot establish inbound exposure; effective-policy and provider validation remain separate.
- Supply-chain analysis processes npm and Python locks, CycloneDX/SPDX/container SBOMs, GitHub Actions references, and caller-supplied pinned advisory fixtures. npm root/workspace/link records are not registry packages. Registry identity is an exact HTTPS hostname check. Python continuation lines are joined before exact-version/hash validation. Advisory matching retains the package ecosystem and normalizes Python names. Workflow write permissions and privileged untrusted-head checkout are reported. Unsupported includes, substitutions, aliases, dynamic action references, and malformed components remain unresolved; no dependency or workflow is executed.
- Credential history correlates exposure state, redaction, rotation, and author identity by opaque fingerprint without retaining a credential value.
- Registered Git collection requires a caller-supplied executable SHA-256 pin, verifies a private copy before invocation, bounds history, files, bytes and elapsed time, and refuses symlinks, linked metadata and object alternates. Hooks, replacement objects, interactive prompts and lazy fetch are disabled. Findings distinguish a historical match from provider-side revocation; the isolated laboratory separately verifies revocation against an ephemeral service and checks repository immutability.
- Network segmentation retains the legacy allow graph and adds versioned firewall,
  rendered Kubernetes NetworkPolicy, flow and DNS envelopes. Firewall rules use
  ordered first-match semantics. Kubernetes policies are additive within each
  direction; both selected ingress and egress policy must permit a path. Namespace
  and Pod inventories must be declared complete. Missing observations, stale DNS,
  unsupported policy features and exceeded bounds remain unresolved. Absence of a
  flow cannot prove denial; static predictions cannot prove CNI enforcement.
- Transport identity preserves metadata inspection and adds `certificate_chain` and `jwt_verification` through `cryptographic-verification/v1`, pinned to cryptography 50.0.2. Explicit local trust, bounded keys/chains, strict identity and time validation, and an explicit client fingerprint allowlist are required. Malformed trust and missing prerequisites yield unknown; actual rejection is a local observation. Revocation and remote acceptance still require separate evidence. Laboratory correction compares these offline results with actual mTLS and JWT service requests using ephemeral credentials.

## Regression evidence

`tests/fixtures/artifact_assessment_cases_v1.json` is a versioned, synthetic corpus with four cases per capability:

- vulnerable evidence that produces a precise finding code
- corrected evidence that does not produce that code
- missing or malformed evidence that remains unknown
- benign evidence that exercises the parser without a false positive

`tests/test_artifact_assessments.py` validates all 40 cases, every serialized Finding, input immutability, hashes and byte counts, output redaction, hard bounds, recursive credential rejection, and an unsupported PCAP adapter boundary.

`tests/test_supply_chain_corrections.py` covers nested/scoped npm identity,
workspace exclusions, deceptive registry URLs, multiline requirements, ecosystem
collisions, quoted/local actions, write permissions, and pull-request checkout
boundaries, including corrected and unsupported inputs.

Checkout analysis associates `uses` and `with` with the same sequence item under
`steps`, regardless of key order or an initial `name`. Only direct `with` inputs
can establish untrusted-head checkout; adjacent steps, nested environment maps,
and block-scalar contents cannot. Duplicate or unsupported input mappings remain
partial evidence.

## Binary telemetry imports

The [EVTX import contract](evtx-import.spec.md) precedes assessment. Its typed
record references and source digest preserve provenance, but derived indicators
alone cannot become verified findings. Unsupported or incomplete records remain
partial evidence. Native acquisition requires separate permissions and evidence.

## Conditional IAM statements

An Allow statement containing `Condition` is outside the bounded IAM evaluator,
including an empty or malformed condition. It produces an evidence gap and cannot
establish public storage or effective wildcard permissions. Other unconditional
statements are still assessed. This applies to direct AWS policies, `Policy`
exports, and registered Terraform IAM/S3 policy resources; no input is modified.
