# Offline artifact assessments

`cops.assessments` provides bounded, deterministic inspection of supplied security artifacts. It does not execute artifacts, invoke a shell, access the network, mount disk images, render templates, or contact a cloud or identity provider.

```python
from cops.assessments import assess

report = assess(
    "application_security",
    [
        {
            "artifact_id": "service-source",
            "kind": "python_source",
            "content": "def parse(value):\n    return eval(value)\n",
        }
    ],
    as_of="2026-10-15T12:00:00Z",
)
```

The same contract is available through a bounded JSON command-line interface:

```console
python -m cops.assessments assess application_security \
  --input assessment-input.json \
  --as-of 2026-10-15T12:00:00Z
```

The input file may be a JSON list of artifact envelopes or an object with an
`artifacts` list. Because JSON cannot carry bytes, `content_b64` may replace
`content`; it is decoded with strict base64 validation. The input document is
limited to 6 MiB before parsing. Use `--input -` to read the same bounded format
from standard input. CLI errors contain only a stable error code.

The result uses `cops.artifact-assessment/v1`. Findings use the repository `cops.finding/v1` contract. Evidence entries contain only an artifact ID, kind, SHA-256 digest, and byte count. Artifact bodies and credential values are never copied into a report.

## Artifact envelope and limits

Each artifact is a mapping with these required fields:

- `artifact_id`: stable opaque identifier using letters, digits, `.`, `_`, `:`, or `-`
- `kind`: one of the supported representations below
- `content`: UTF-8 text, bytes, or structured JSON data

For forensic images, `source_ref`, `sha256`, `collected_at`, collection permission, and ordered custody records with opaque actor IDs are required to establish provenance. Collection and custody times cannot be in the future. Other accepted metadata fields are `framework` and `framework_version`. Explicit credential-value keys such as `password`, `access_token`, `api_key`, `private_key`, or `secret` are rejected at any structured depth. Use opaque fingerprints for credential-history evidence.

The default request bounds are 64 artifacts, 1 MiB per artifact, and 4 MiB total. Callers can lower these bounds. Invalid and over-limit inputs fail with a stable, content-free `ArtifactAssessmentError.code`.

## Supported representations

| Capability | Artifact kinds | What is inspected |
| --- | --- | --- |
| `application_security` | `python_source`, `javascript_source`, `typescript_source`, `unified_diff`, `scanner_json` | Python syntax trees, bounded JS/TS and added-line patterns, route authorization markers, normalized scanner status |
| `foundry_security` | `foundry_test` | Direct or indirect prompt-injection expectation, decision, allowed tools and resources, and observed tool and resource IDs |
| `compliance_evidence` | `control_evidence` | Versioned SOC 2, CIS, and NIST control records, effective state, evidence references, and 90-day freshness |
| `forensic_evidence` | `disk_image`, `memory_image` | Original-byte SHA-256, declared hash, source identity, collection time and permission, and actor-attributed custody ordering |
| `malware_static` | `binary`, `powershell_encoded` | Bounded static indicators and base64 decoding up to 256 KiB; decoded bytes are never executed |
| `cloud_configuration` | `terraform_plan`, `kubernetes_rendered`, `helm_rendered_json`, `aws_export`, `azure_export`, `gcp_export` | Privileged workload settings, wildcard IAM/RBAC, public storage, and all-address ingress in structured data |
| `supply_chain` | `package_lock`, `requirements_lock`, `cyclonedx`, `spdx`, `container_sbom`, `github_actions`, `advisory_fixture` | Registry and integrity metadata, exact Python hashes, versioned SBOM components, action pins, and matches to a supplied pinned advisory fixture |
| `credential_history` | `git_history` | Synthetic exposure records correlated by opaque fingerprint, redaction, rotation, and opaque author ID |
| `network_segmentation` | `segmentation_model` | Bounded graph reachability across allow rules, expected path assertions, and structured DNS evidence |
| `transport_identity` | `tls_config`, `jwt`, `jwks` | Certificate time, chain-name continuity, SAN and mTLS settings, JWT structure and claims, and JWKS key/algorithm metadata |

Malformed supported artifacts yield unresolved findings or insufficient-evidence readiness. Unknown or heavyweight formats produce explicit limitations and versioned adapter prerequisites. For example, raw Helm templates require a pinned renderer, PCAP requires a registered flow extractor, forensic filesystem or memory parsing requires an image parser, and cryptographic trust or revocation requires a chain-validation adapter.

## Disposable acquisition adapter

`cops.assessments.acquisition.acquire_disposable_file` registers
`disposable-file-acquisition@1` for bounded regular-file acquisition on POSIX
platforms with Python's no-follow, directory-relative file APIs. It requires an
explicit disposable-laboratory assertion, collection permission, a pinned source
hash, opaque source and actor IDs, and a collection timestamp. Every ancestor and
path component is opened without following symlinks. The adapter reads at most
1 MiB, verifies stable source identity, creates an exclusive mode-0600 copy,
and emits an artifact and content-free custody receipt. Rejected or interrupted
copies remove their partial output; originals remain unchanged.

The laboratory gate exercises a real copy, denied collection, and a changed
source. This adapter acquires synthetic lab files only. Native disk, memory,
filesystem, and raw EVTX acquisition still require separately registered and
validated tools; a copied regular file does not establish those capabilities.

## Reading readiness

- `supported` means the supplied representation was parsed and no format-specific limitation was encountered. It is still an offline assessment.
- `limited` means at least one artifact was analyzed but the report records a capability limitation, such as static-only malware inspection or absence of a current registry query.
- `insufficient_evidence` means no supplied artifact could be analyzed using the supported representations.

A report always states that offline inspection cannot establish live-provider, production, runtime-enforcement, or deployment readiness. A corrected fixture means the bounded checks did not produce the corresponding finding; it is not evidence that a live control is effective.

## Safety and evidence handling

Treat all input as untrusted. The module parses data in-process with hard bounds and never interpolates content into shell commands. Malware and PowerShell artifacts are byte-scanned only. Forensic bytes are hashed without modification. Scanner messages, source text, prompt-injection text, credential occurrences, JWT contents, and advisory descriptions are omitted from output.

The pinned regression corpus is `tests/fixtures/artifact_assessment_cases_v1.json`. It includes a vulnerable, corrected, insufficient-evidence, and negative benign case for every capability.
