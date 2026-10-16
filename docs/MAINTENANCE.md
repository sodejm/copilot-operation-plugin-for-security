# COPS maintenance

## Routine change

1. Work in a focused branch or worktree and preserve unrelated local changes.
2. Update the specification and acceptance scenarios when observable behavior changes.
3. Keep implementation and documentation inside the owning package where possible.
4. Run the package demo and checks.
5. Regenerate derived host indexes when the catalog changes.
6. Run the complete repository gate.

```bash
python3 -m cops doctor --contributor
python3 -m cops generate
python3 -m cops generate --check
python3 -m cops check
make check-playbooks
make check
make check-docs
```

Acceptance criteria:

- catalog, manifests, package contract, and package path agree;
- generated indexes are current and were not independently edited;
- every package's declared checks pass;
- BDD scenarios cover the changed behavior and meaningful misuse boundaries;
- offline, isolated laboratory, installed-host, and live evidence claims remain distinct;
- no credentials, private investigation data, or generated caches are committed.

## Release review

For each changed package, review its maturity, limitations, input/output contract,
permission needs, deterministic results, and version. A repository check can award
structural or offline evidence only. Require a dated, reproducible evidence record
before changing host-installation or live-integration status. Laboratory readiness
also requires `make check-laboratory` with verified isolation, actual activity,
collected telemetry and restored baseline. An unavailable isolation boundary or
skipped required check leaves the affected capability incomplete; `make check`
remains portable and cannot award laboratory readiness.

CI runs the full contributor gate on supported Python versions and an operator
smoke test on Linux, macOS, and Windows. The operator checks run without test
dependencies; jobs running acceptance tests install `requirements.txt` explicitly
and verify prerequisites first. Local `make check` uses the same declaration and
stops before repository checks if prerequisites are unavailable. See
[Contributing](../CONTRIBUTING.md) for offline setup and interpreter selection.
A green CI run establishes only the scopes named by those jobs.

## Plugin qualification and maturity

Maintain each package's [verification playbook](plugin-verification.md) when its
workflow, dependencies, adapters, or supported scope changes. Retain dated,
sanitized qualification records with the tested revision, inputs, expected and
observed results, negative/recovery cases, host scope, cleanup, fresh repeat run,
and independent review.

After the reviewer accepts a maturity proposal, update the package manifest and
all public status labels together and link the accepted record from the package
README and verification page. Keep support flags and operational modes separate.
Requalify after material changes or defects affecting the accepted scope; record
the reason and lower maturity if the previous gate is no longer met.

## Generated content

- Change `catalog/plugins.json`, then run `python3 -m cops generate`.
- Change canonical contributor skills in `.agents/skills/`, then run
  `make sync-agent-adapters`.
- Change artifact-assessment or API runtime sources, then run
  `python3 scripts/sync_artifact_assessment_runtime.py` or
  `python3 scripts/sync_web_api_runtime.py` and verify their `--check` modes.
- Change package playbook inputs or catalog routing metadata, then run
  `make generate-playbooks` and `make check-playbooks`. Keep the independent
  routing evaluation fixture separate from published examples.
- Change Sentinel canonical source, then run its adapter generator and
  `python3 -m cops check sentinel-hunt-workbench`.

Generated files are reviewed in diffs but are never the source of truth.

For expansion changes, record the exact revision, fixture checksums, commands,
counts, limitations and blocked gates in the acceptance report. Re-run the routing
held-out suite when metadata, profiles, thresholds or scoring change. Do not
promote recorded fixture assertions or unsigned evidence bundles to authenticated
production observations. See [Expansion migration](EXPANSION_MIGRATION.md).

## External change review

When a host changes discovery, permissions, skills, manifests, or hooks, check its
current official documentation and repeat the host smoke test before changing
support statements. Review dependency and GitHub Action updates before merging.

For PARK upgrades, compare upstream with the revision in
[the adoption record](decisions/0001-park-adoption.md), apply a reviewed diff, and
preserve COPS-specific packages, checks, specifications, and licensing. Do not run
a project generator over this configured repository.


For network evidence, retain the inventory completeness assertion, observation
window and TTL alongside its digest. Recollect expired flow/DNS evidence before
reassessment. A parsed policy or reachable HTTP service cannot establish that a
kernel firewall or Kubernetes CNI enforced the intended packet boundary.

For cryptographic verification, retain the exact optional `cryptography` version
in `pyproject.toml`, the adapter registry and the laboratory lockfile. Revalidate
chain policy and token corrections after upgrades, synchronize the portable
runtimes, and repeat `make check-laboratory` with the rebuilt pinned image.
Do not infer remote acceptance from local verification results.
