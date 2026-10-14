# Architecture

Sentinel Hunt Workbench separates authored security content, deterministic
validation, and host discovery.

```text
skills/ + hunts/ + profiles/ + fixtures/
                 |
                 v
          huntwb standard-library core
       (contracts, binding, rendering, tests)
                 |
          +------+----------------+
          |                       |
          v                       v
 machine-readable reports   generated adapters/
                                  |
                    Codex / Copilot / Claude discovery
```

## Canonical sources

- `hunts/H01.json` through `hunts/H12.json` define the release hunt library.
- `profiles/` defines per-surface tables, fields, and compatibility claims.
- `skills/` contains the six portable Agent Skills.
- `fixtures/curated/` and deterministic perturbation generation provide offline
  evidence.
- `huntwb/` implements validation, typed parameter binding, rendering, mutation
  testing, report generation, and adapter hashing.

The root `package.json` is the COPS governance contract. It identifies the safe
offline demo, the release-blocking package checks, maturity, limitations, and the
current support-evidence state. The root `plugin.json`,
`.codex-plugin/plugin.json`, and `.claude-plugin/plugin.json` provide distinct
host distribution metadata; none is proof of host installation.

## Trust boundaries

Hunt parameters are data, never executable query fragments. The renderer accepts
only declared typed values and serializes them to KQL literals. Telemetry strings,
URLs, commands, comments, and documents are untrusted content. The workbench does
not hold credentials, contact external services, execute KQL, or perform response
actions.

The reference evaluator checks declared invariants over synthetic fixtures. It is
not a Kusto parser, emulator, or Microsoft service. Any parser, engine, model-host,
human-review, or tenant evidence must be recorded as a separate evidence class.
