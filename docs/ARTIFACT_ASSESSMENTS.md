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
| `cloud_configuration` | `terraform_plan`, `kubernetes_rendered`, `helm_rendered_json`, `aws_export`, `azure_export`, `gcp_export` | Typed workload, IAM/RBAC, storage ACL, and inbound source-range observations; unsupported resources remain partial |
| `supply_chain` | `package_lock`, `requirements_lock`, `cyclonedx`, `spdx`, `container_sbom`, `github_actions`, `advisory_fixture` | Registry and integrity metadata, exact Python hashes, versioned SBOM components, action pins, token write permissions, privileged pull-request head checkout, and ecosystem-specific pinned advisories |
| `credential_history` | `git_history` | Bounded Git scan or supplied synthetic exposure records correlated by opaque fingerprint, redaction, rotation, and opaque author ID |
| `network_segmentation` | `segmentation_model`, `firewall_policy`, `kubernetes_network_policy`, `flow_evidence`, `dns_evidence` | Legacy allow graph, ordered IP firewall rules, additive Pod NetworkPolicy predictions, explicit flow observations, and TTL-bound DNS address sets |
| `transport_identity` | `tls_config`, `jwt`, `jwks`, `certificate_chain`, `jwt_verification` | Metadata checks; optional pinned adapter verifies certificate chains, authorized client fingerprints and RS256 signatures against explicit local trust |

Malformed supported artifacts yield unresolved findings or insufficient-evidence readiness. Unknown or heavyweight formats produce explicit limitations and versioned adapter prerequisites. For example, raw Helm templates require a pinned renderer, PCAP requires a registered flow extractor, forensic filesystem or memory parsing requires an image parser, and revocation requires separately collected evidence.

### Local certificate and JWT verification

Install the optional repository extra with `python3 -m pip install '.[crypto]'`
in the configured environment. Exported packages require `cryptography==50.0.2`.
The registered `cryptographic-verification/v1` adapter is limited to 256 KiB per
artifact and performs no key, intermediate, issuer or revocation discovery.
See the [typed input contract](../plugins/vulnerability-management/tls-crypto-workbench/docs/CRYPTO_INPUTS.md).

Typed verification emits content-free `verification_results` with `accepted`,
`rejected` or `unknown` status, a bounded reason code and public-key/certificate
fingerprints. Rejection is a verified observation about this local verifier, not
a verified remote vulnerability. Missing trust, unsupported inputs or a missing
pinned dependency remain unknown. Legacy metadata kinds retain their existing
behavior. Neither path establishes production service acceptance or revocation.

Supply-chain parsing supports npm lockfile `packages` records, infers package
names from nested and scoped `node_modules` paths, and excludes root/workspace
descriptions and linked local packages from registry checks. Registry identity
requires HTTPS and the exact approved hostname. Python requirements join
continuation lines and require exact versions and SHA-256 hashes. Package
matching preserves the ecosystem and normalizes Python distribution names.
Advisories match exact versions in the caller's pinned fixture; this is not a
current advisory query or version-range resolver.

Actions parsing accepts a bounded indentation and scalar subset, quoted pins,
local actions, and digest-pinned container actions. It reports token write
permissions and explicit untrusted head checkout under `pull_request_target`.
Checkout inputs must belong to that step's direct `with` mapping. Step names
and key order do not change the result; inputs from adjacent steps, nested
environment mappings and block-scalar text cannot establish a checkout finding.
Duplicate or unsupported checkout input mappings leave the assessment partial.
Includes, substitutions, YAML aliases/tags, dynamic action references, and other
unsupported constructs remain evidence gaps. No parser executes includes,
resolves variables, downloads dependencies, or runs workflow steps. A clean
subset result cannot establish safety of the complete build.

## Bounded Git history scanner

The separate [Git history scanner](../plugins/identity-access/secrets-remediation-workbench/docs/GIT_HISTORY_SCANNER.md)
enumerates an explicitly scoped ordinary checkout through a registered, executable
hash-pinned Git adapter. It detects bounded historical credential patterns without
returning values, changing repository bytes, or fetching objects. A complete
bounded scan without matches is distinct from an empty or truncated scan.
Matches are potential exposures; they do not establish credential validity.
Containment remains unknown until separate revocation evidence is collected.

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
source. It imports that copy as both raw image kinds, rejects missing permission,
missing custody and modified bytes, then verifies a restored copy. This adapter acquires synthetic lab files only. Native disk, memory,
filesystem, and raw EVTX acquisition still require separately registered and
validated tools; a copied regular file does not establish those capabilities.

## Raw disk and memory import

`cops forensic import --root evidence --manifest import.json` streams a raw
regular file through the registered `raw-forensic-image/v1` adapter on POSIX.
The manifest uses `cops.forensic-import-input/v1`:

```json
{
  "schema_version": "cops.forensic-import-input/v1",
  "artifact_id": "disk-copy-1",
  "source_relative": "disk.raw",
  "kind": "disk_image",
  "format": "raw",
  "sha256": "<expected 64 lowercase hexadecimal characters>",
  "source_ref": "lab-source-1",
  "authorization_ref": "collection-grant-1",
  "collection_authorized": true,
  "collected_at": "2026-10-15T12:00:00Z",
  "as_of": "2026-10-15T12:01:00Z",
  "custody": [{
    "actor_ref": "collector-1", "action": "acquire",
    "at": "2026-10-15T12:00:00Z",
    "sha256": "<same expected SHA-256>"
  }]
}
```

Use `memory_image` for a raw memory copy. Each later custody event must be
`transfer` or `verify`, retain the same digest, and have an ordered timestamp no
later than `as_of`. IDs are opaque; do not put names, credentials, or source paths
in them. The manifest rejects unknown fields, duplicate JSON keys, and more than
128 custody records. It is limited to 64 KiB. Images are nonempty and at most
128 MiB; `--max-bytes` can lower the bound. Reads use 64 KiB chunks.

Every source and manifest ancestor rejects symlinks. The importer verifies the
held file identity, final directory entry, byte count, and expected digest. It
opens files read-only, does not create copies, and emits no image bytes or paths.
The result explicitly separates `integrity: verified` from
`analysis: not_performed`. Identity, collection permission, and custody are
caller assertions; a matching hash does not authenticate them or grant execution
authority. Use a separately trusted digest and retain original acquisition records.

E01, AFF4, compressed images, device capture, filesystem analysis, and memory
analysis require separately registered adapters. Unsupported platforms or formats
fail explicitly. See [the contract](../specs/forensic-import.spec.md).

## Reading readiness

- `supported` means the supplied representation was parsed and no format-specific limitation was encountered. It is still an offline assessment.
- `limited` means at least one artifact was analyzed but the report records a capability limitation, such as static-only malware inspection or absence of a current registry query.
- `insufficient_evidence` means no supplied artifact could be analyzed using the supported representations.

A report always states that offline inspection cannot establish live-provider, production, runtime-enforcement, or deployment readiness. A corrected fixture means the bounded checks did not produce the corresponding finding; it is not evidence that a live control is effective.

## Safety and evidence handling

Treat all input as untrusted. The module parses data in-process with hard bounds and never interpolates content into shell commands. Malware and PowerShell artifacts are byte-scanned only. Forensic bytes are hashed without modification. Scanner messages, source text, prompt-injection text, credential occurrences, JWT contents, and advisory descriptions are omitted from output.

The pinned regression corpus is `tests/fixtures/artifact_assessment_cases_v1.json`. It includes a vulnerable, corrected, insufficient-evidence, and negative benign case for every capability.

Cloud analysis accepts Terraform plan JSON version 1.x, using effective `after` values and excluding deleted resources. It checks registered AWS IAM policies, security groups and S3 ACLs; rendered Kubernetes workloads, RBAC and NetworkPolicy; AWS security-group/IAM/ACL exports; Azure NSG and storage-account exports; and GCP firewall/IAM exports. Unknown Terraform values, unsupported resource types, malformed fields and empty unrecognized documents produce an insufficient-evidence finding. Deny statements and outbound rules do not become ingress findings. These observations do not resolve policy conditions, effective permissions, rule precedence, or live reachability. Raw Helm and other formats require registered adapters.

An IAM Allow statement containing `Condition` remains insufficient evidence,
including an empty or malformed condition. It cannot establish public storage
or effective wildcard permissions without policy evaluation and request context.
Separate unconditional statements still produce their supported observations.

## Typed network evidence

The [typed example](../plugins/vulnerability-management/network-segmentation-workbench/examples/typed-input.json)
contains four independent artifact kinds. Each requires its matching
`cops.<kind-with-hyphens>/v1` schema version and `complete: true`:

- `firewall_policy`: ordered first-match CIDR rules, TCP/UDP/ANY, numeric port
  sets (empty means all), explicit default action and expected IP paths.
- `kubernetes_network_policy`: complete Namespace, Pod and NetworkPolicy JSON
  inventory plus expected Pod-to-Pod TCP/UDP paths. Predictions implement
  additive ingress/egress rules, label selectors and expressions, namespace/pod
  selector intersection, CIDR exclusions, named destination ports and port ranges.
  Kubernetes `NotIn` matches peers missing the specified label as well as peers
  with other values. Combine it with `Exists` when the label must be present;
  `In` requires a matching value on a present label. This applies to both pod
  and namespace selectors.
- `flow_evidence`: expected IP paths and explicit allow/deny observations with
  opaque evidence references and timestamps no older than 15 minutes. Missing
  traffic cannot establish denial; contradictory observations remain unknown.
- `dns_evidence`: expected exact A/AAAA address sets and unique observed records
  with timestamps and TTLs. Expired, missing or future observations remain unknown.

Expected path lists have at most 256 entries. Firewall rules and observations
have at most 1,024 entries. Kubernetes inventories have at most 128 resources of
each supported kind; a 200,000 peer/port comparison budget bounds predictions.
Unsupported selectors, protocols, host networking, service/NAT paths or incomplete
inventories yield insufficient evidence. Pod IPs are required for CIDR peers.
These are supplied snapshots, not authenticated captures or CNI enforcement.
The semantics follow the [Kubernetes NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
Actual firewall/CNI enforcement needs independent isolated connectivity evidence.

Compliance artifacts are limited to 1,000 control records. An artifact above that
limit is insufficient evidence; no prefix is treated as a complete assessment.

GCP IAM bindings with conditions require evaluation context and produce insufficient
evidence. Independently supported unconditional bindings remain assessable.
