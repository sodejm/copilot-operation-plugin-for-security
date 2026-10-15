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
5. Explicit credential-value fields are rejected recursively with a stable content-free error. Credential-history processing accepts opaque fingerprints only.
6. Unsupported heavyweight or live formats return a limitation and a pinned registered-adapter prerequisite. They do not produce a passing readiness claim.
7. Missing or malformed required security evidence remains unknown through an unresolved finding or `insufficient_evidence` readiness.
8. An offline clean result cannot establish provider-side revocation, current advisory state, runtime segmentation, cryptographic trust, production configuration, or deployment readiness.

## Capability assertions

- Application security parses Python syntax, examines bounded JavaScript/TypeScript or added diff lines, and ingests normalized scanner records for injection and visible route-authorization evidence.
- Foundry security compares direct or indirect injection test outcomes and observed tool calls with a supplied allowlist.
- Compliance evidence requires a named SOC 2, CIS, or NIST framework version, control identifier, status, evidence references, and collection time. Evidence older than 90 days is unresolved as stale.
- Forensic evidence verifies original-byte SHA-256, collection permission, and chronological custody metadata.
- Malware analysis performs static byte checks and bounded base64 decoding without execution or attribution claims.
- Cloud analysis walks structured Terraform, rendered Kubernetes/Helm, or provider exports for IAM, storage, ingress, and workload risks.
- Supply-chain analysis processes npm and Python locks, CycloneDX/SPDX/container SBOMs, GitHub Actions references, and caller-supplied pinned advisory fixtures. npm root/workspace/link records are not registry packages. Registry identity is an exact HTTPS hostname check. Python continuation lines are joined before exact-version/hash validation. Advisory matching retains the package ecosystem and normalizes Python names. Workflow write permissions and privileged untrusted-head checkout are reported. Unsupported includes, substitutions, aliases, dynamic action references, and malformed components remain unresolved; no dependency or workflow is executed.
- Credential history correlates exposure state, redaction, rotation, and author identity by opaque fingerprint without retaining a credential value.
- Network segmentation computes expected reachability from structured allow rules and validates structured DNS evidence.
- Transport identity inspects TLS metadata, mTLS settings, JWT claims and algorithms, and JWKS metadata while explicitly reserving signature, trust-anchor, revocation, and handshake checks for registered adapters or laboratories.

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
