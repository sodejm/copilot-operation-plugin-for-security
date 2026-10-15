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

The portable expansion test builds a package through a temporary Git index,
exports it, and runs its offline demo with isolated Python path handling from the
exported tree. This verifies that reviewed playbooks and dataset provenance are
preserved and that the demo does not depend on an adjacent COPS checkout.
