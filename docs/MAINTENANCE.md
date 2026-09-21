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
make check
```

Acceptance criteria:

- catalog, manifests, package contract, and package path agree;
- generated indexes are current and were not independently edited;
- every package's declared checks pass;
- BDD scenarios cover the changed behavior and meaningful misuse boundaries;
- offline, host, and live evidence claims remain distinct;
- no credentials, private investigation data, or generated caches are committed.

## Release review

For each changed package, review its maturity, limitations, input/output contract,
permission needs, deterministic results, and version. A repository check can award
structural or offline evidence only. Require a dated, reproducible evidence record
before changing host-installation or live-integration status.

CI runs the full contributor gate on supported Python versions and a dependency-free
operator smoke test on Linux, macOS, and Windows. A green CI run establishes only
the scopes named by those jobs.

## Generated content

- Change `catalog/plugins.json`, then run `python3 -m cops generate`.
- Change canonical contributor skills in `.agents/skills/`, then run
  `make sync-agent-adapters`.
- Change Sentinel canonical source, then run its adapter generator and
  `python3 -m cops check sentinel-hunt-workbench`.

Generated files are reviewed in diffs but are never the source of truth.

## External change review

When a host changes discovery, permissions, skills, manifests, or hooks, check its
current official documentation and repeat the host smoke test before changing
support statements. Review dependency and GitHub Action updates before merging.

For PARK upgrades, compare upstream with the revision in
[the adoption record](decisions/0001-park-adoption.md), apply a reviewed diff, and
preserve COPS-specific packages, checks, specifications, and licensing. Do not run
a project generator over this configured repository.
