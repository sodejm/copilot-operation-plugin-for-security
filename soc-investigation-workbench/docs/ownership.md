# Ownership and dependency updates

The investigation plugin adds case-level planning. It must not grow a second
implementation of the Sentinel Hunt Workbench's analytical workflows.

| Capability | Owner | Integration |
| --- | --- | --- |
| Case scope, evidence references, explicit associations | SOC investigation | Local case engine |
| Competing explanations, question dependencies, branch guards | SOC investigation | Planning skill and engine |
| Next-step ranking, budgets, resume, uncertainty review | SOC investigation | Two registered SOC skills |
| Hunt discovery and design | Sentinel | Canonical vendored skills |
| KQL construction, source schemas, raw telemetry joins | Sentinel | Canonical vendored skills and runtime |
| Query rendering and surface compatibility | Sentinel | Canonical vendored runtime and hunt contracts |
| Hunt analytical qualification and assurance claims | Sentinel | Canonical vendored evaluation flow |

Small boundary checks are intentional duplication: the case engine recognizes
three surface names and Hxx references, and checks that requested time intervals
stay within the case. It does not define KQL, source schemas, joins, hunt logic,
or a second hunt evaluation flow. New overlaps must be resolved by calling or
vendoring the canonical flow, not by expanding the SOC skills.

## Snapshot policy

The maintainer command copies the entire canonical `sentinel-hunt-workbench/`
package so skill-relative references retain their supporting files. It skips
Git metadata, Python caches, pytest caches, and macOS metadata in the source.
Any other Git-ignored file that would be copied, including an inherited license,
blocks the update before the installed snapshot changes. Review and remove local
content from the source before retrying.
Installed snapshots reject these entries, including executable `.pyc` files,
instead of silently ignoring them. It rejects symlinks and Windows reparse points,
including junctions, before traversing source or installed directories and before
replacing vendor destinations. This includes the inherited license and lock.
Dependency files are hashed in bounded
chunks from regular-file handles. Every
included file keeps its exact bytes. If the package has no `LICENSE`, the
repository license is included unchanged after a bounded regular-file read.
The lock is written privately and replaced atomically without following links.
Inventory paths must also be portable to Windows: invalid characters, reserved
device names, trailing dots/spaces, and case-insensitive file or directory
collisions are rejected on every host before replacing a snapshot. Development
validation permits missing vendor artifacts only; dangling junctions still block.

`vendor-lock.json` records the upstream repository, package path, base Git commit,
whether the source was a working-tree snapshot, every file's SHA-256, the aggregate
inventory hash, and every canonical skill path. A working-tree snapshot is
identified explicitly; the base commit alone does not claim to reproduce it.
Untracked source files are included in this classification even when Git's
status display is configured to hide them.
Source inspection requires the package directly under the Git repository root
and exactly one local `origin` URL identifying this canonical repository. Accepted
forms are `https://github.com/sodejm/copilot-operation-plugin-for-security`
(with or without `.git`),
`git@github.com:sodejm/copilot-operation-plugin-for-security.git`, and
`ssh://git@github.com/sodejm/copilot-operation-plugin-for-security.git`.
The same forms using the former `copilot-operations-plugin-for-security` name
remain accepted for existing source checkouts. New locks always identify the
current repository name. Fork origins, other aliases, missing origins, and
multiple origin URLs are rejected.
Git filesystem-monitor hooks and configured content filters are disabled during
inspection. These checks establish the configured repository identity; they make
no network request or authenticity attestation. Maintainers must review local
content and provenance before vendoring.
The verifier requires the exact lock schema, canonical repository and package,
40-character lowercase Git revision, declared source-state enum, fixed update
policy, and valid paths and digests. The file hashes define the exact copied content. Locks detect accidental drift,
not malicious changes to both files and lock.

Only the two SOC skills under `./skills/` are registered by this plugin. Handoff
returns POSIX skill and CLI paths relative to this plugin's installation for
explicit loading, without including the maintainer's local filesystem path. Run
the canonical Python CLI with `-B` to avoid adding bytecode caches to the verified
snapshot. This avoids registering
the same Sentinel skill names twice if the separate Sentinel plugin is installed.
No upstream manifest is registered or merged into the SOC manifest.

## Completing or refreshing the integration

Run from this plugin directory with a stable, reviewed canonical checkout:

```bash
python3 scripts/investigate.py vendor-sync /path/to/canonical/repo/sentinel-hunt-workbench
python3 scripts/investigate.py verify-vendor --source /path/to/canonical/repo/sentinel-hunt-workbench
python3 scripts/validate-package.py
python3 scripts/investigate.py handoff examples/case.json --step signin
```

The source must have skill files, the hunt catalog, and `scripts/huntwb.py`.
Both sync and verification require every hunt/surface in the shipped example
case (H01, H02, H07, and H10 on Sentinel analytics) to exist and explicitly claim
support. Each handoff also checks its requested hunt/surface. This is a consumer
dependency check, not a replacement for Sentinel's catalog qualification.
Incomplete source and invalid generated lock paths are rejected before replacing
the installed snapshot. The copied inventory and generated lock are validated
while staged, preserving the previous snapshot and lock on validation failure. Updating
the vendor directory and lock is an explicit maintenance operation; do not run
it concurrently with case work. An interrupted refresh may leave an unusable
snapshot, which integrity validation rejects until the refresh is rerun.

Review the generated lock and upstream changes, run the repository's behavior
tests and upstream's documented qualification procedure, then commit the entire
snapshot and lock together. Never patch copied skills or runtime files. Send a
needed flow change to the canonical package and refresh from there. Do not copy
secrets, local case files, or unrelated work into the canonical package.

At the implementation checkpoint the canonical package contained runtime Python
files but no skill files or hunt catalog. There is intentionally no fabricated
snapshot or replacement flow in this change. This dependency must be completed
before the package can pass its release gate. Once integrated, update the README
status with the verified snapshot and its upstream assurance limits.
