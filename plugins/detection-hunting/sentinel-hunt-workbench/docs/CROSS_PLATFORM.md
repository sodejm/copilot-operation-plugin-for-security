# Cross-platform use

The files in `skills/`, `hunts/`, and `profiles/` are the canonical product
sources. Host-specific files under `adapters/` are generated discovery layers;
they are not independent copies of product policy.

From the repository root, use the catalog-driven commands:

```bash
python3 -m cops info sentinel-hunt-workbench
python3 -m cops demo sentinel-hunt-workbench
python3 -m cops check sentinel-hunt-workbench
```

From this package directory, rebuild or verify the generated adapters with:

```bash
python3 scripts/huntwb.py build-adapters
python3 scripts/huntwb.py verify-adapters
```

`build-adapters` is an intentional write. `verify-adapters` is the normal CI and
review command because it fails when generated files differ from their canonical
sources.

## Evidence boundary

The repository validates the distinct GitHub Copilot root manifest, Codex
`.codex-plugin/plugin.json`, Claude `.claude-plugin/plugin.json`, skills,
generated adapter inventory, hashes, and offline command behavior. That evidence
does not establish that Codex, ChatGPT, GitHub Copilot, or Claude Code accepted or
activated the package in a particular product version.

Host installation remains `unverified` until a maintainer records a fresh,
version-specific smoke test. Live Microsoft integration also remains `unverified`:
the package contains no tenant connector, credentials, or network client. Treat a
host UI success, offline validation, and authorized tenant validation as three
separate gates.

## Portable fallback

If a host does not discover an adapter automatically, direct it to the relevant
canonical `skills/<skill-id>/SKILL.md` file and run the package-owned command from
the repository checkout. Never copy generated adapter text back into a canonical
skill.
