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
live integration must supply the same isolated role sessions to plan construction
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

## Artifact assessment runtimes

Six portable workbenches carry a synchronized copy of the offline artifact
assessment runtime. After changing that runtime, refresh the vendor copies and
their lock files with:

```console
python3 scripts/sync_artifact_assessment_runtime.py
```

Normalized scanner lists and `findings` lists are limited to 1,000 records. A
larger collection fails before analysis instead of producing a clean result from
a truncated prefix. Repeated findings retain deterministic, unique identifiers;
the report code mapping contains one entry for every occurrence without copying
source or scanner text into identifiers.

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
