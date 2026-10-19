# Portable expansion packages

Portable exports use the Git index as their reviewed file inventory. Package-owned
assets under `examples/`, `playbooks/`, `walkthroughs/`, `datasets/`, `provenance/`,
and `signatures/` are included when they are present in that index. The exporter
continues to reject symlinks, unknown package-root entries, missing tracked files,
and broken relative documentation links.

New package assets can be reviewed without staging the contributor's working tree.
Copy the repository index to a temporary file, set `GIT_INDEX_FILE` to that file,
add the package paths to the temporary index, and run the portable export. This
keeps the real index unchanged while exercising the exact tracked-file behavior
used by release packaging.

## Web API workbench runtime

The Web API Assessment Workbench carries a package-local, standard-library-only
Python runtime under `vendor/`. This lets its offline demonstration run from a
clean installed package without importing the source repository. Synchronize it
after changing `cops/web_api` or one of its listed dependencies:

```console
python3 scripts/sync_web_api_runtime.py
python3 scripts/sync_web_api_runtime.py --check
```

The synchronization script copies an explicit module inventory, writes minimal
package initializers to avoid unrelated imports, and records a SHA-256 digest and
source path for every runtime file in `runtime-provenance.json`. It rejects extra
files in the managed vendor directory. The package demo must put its own `vendor/`
directory on `sys.path` before importing `cops.web_api`; repository-root fallback
is only for source-tree development.

The inventory includes the report sanitizer. Keep its report-only transformations
separate from lossless request digests when updating the portable runtime. The
OpenAPI and Swagger importers reconstruct authentication from each operation's
effective security requirement; a public override does not inherit root credentials,
and unused declarations do not create sessions. OpenAPI server paths and Swagger
`basePath` values become part of the endpoint and preview URL. Server alternatives
select the first declared value and are reported as unsupported; relative or
non-HTTPS servers, unresolved variables, empty-host or malformed-port authorities,
unrepresentable authentication, and operation-path keys containing `?` or `#` fail
closed without echoing imported content. Header credential names use case-insensitive
collision checks, while query credential names remain case-sensitive.

HAR, OpenAPI/Swagger, Postman, and raw HTTP import inputs share an 8 MiB
limit. Importers perform a bounded maximum-plus-one binary read before parsing,
retain the accepted raw-byte digest, and never fetch or execute input. Repeated
CLI inputs retain one validated, path-free provenance record per source in
`provenance_sources`; the merged inventory identity is derived from the sorted
source type, opaque source ID, and content digest records rather than endpoint
counts or timestamps. Every serialized provenance record uses
`sha256:<matching-digest>` as its source reference, so local paths and
credential-bearing references cannot enter the public inventory contract.
Saved inventories and replay reports use the same 8 MiB bounded binary reader.
Inspection validates and reserializes the recognized public model instead of
echoing parsed JSON. Inventory names and imported-source labels reject local or
credential-bearing references at both deserialization and serialization.
Endpoint and session authentication metadata is also validated when loaded and
serialized. It must be explicitly redacted, and its credential identity is
either empty for a declaration or a lowercase SHA-256 digest; plaintext or
malformed credential identities fail with a content-free error.

Imported authenticated endpoints carry an explicit `session_id`. Merge
deterministically namespaces endpoint and session IDs per source occurrence, so
duplicate inputs and distinct sources using the same scheme retain separate
credential contexts. HAR, OpenAPI/Swagger, Postman, and raw HTTP Bearer, Basic,
and API-key inputs preserve this association through serialization, preview,
action-plan construction, and offline replay. HAR Bearer and Basic metadata use
the header name `Authorization`; previews render
`Authorization: Bearer <placeholder>` or
`Authorization: Basic <placeholder>`. The CLI does not load credentials from
the environment. An approved integration replaces a Bearer placeholder with
the token only (no scheme prefix), a Basic placeholder with the RFC 7617
base64-encoded `user:password` payload only (no scheme prefix), and an API-key
placeholder with the exact header, query, or cookie value only. Suggested
environment names are `COPS_WEB_API_BEARER_TOKEN`,
`COPS_WEB_API_BASIC_CREDENTIALS_B64`, and `COPS_WEB_API_API_KEY_VALUE`.

The live integration must supply the same isolated role sessions to plan construction
and execution so the signed digest covers the effective wire request. The
standard-library transport pins each connection to its scope-checked DNS result
and keeps certificate-chain and original-hostname verification for HTTPS. It sets
an explicit TLS 1.2 minimum on default contexts, rejects caller contexts that permit
older protocols, and rechecks supplied contexts before use without changing them. Live
execution uses owned request, session, budget and destination snapshots and refuses
cross-origin redirects that retain a body or credentials; offline exports make no
live calls.

The portable expansion test builds a package through a temporary Git index,
exports it, and runs its offline demo with isolated Python path handling from the
exported tree. This verifies that reviewed playbooks and dataset provenance are
preserved and that the demo does not depend on an adjacent COPS checkout.

## Optional EVTX runtime

The EVTX adapter is a repository CLI capability. Portable plugin exports do not
silently bundle its parser. The strict laboratory source snapshot includes the
synthetic `.evtx` correction fixtures; its separately provisioned runtime pins
both parser dependencies. Missing prerequisites fail the binary acceptance case.

## Kubernetes acceptance prerequisites

Portable exports contain offline Kubernetes assessment and walkthrough assets.
They do not bundle K3s or start a privileged node. The repository's required
laboratory gate separately uses the registered, digest-pinned images for Linux
amd64 or arm64. Provision them explicitly on a dedicated lab host using
[the runbook](KUBERNETES_LABORATORY.md); missing images cannot become a skipped pass.
