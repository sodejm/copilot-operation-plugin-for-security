# Sentinel Hunt Workbench

Sentinel Hunt Workbench is a deterministic, offline-qualified toolkit for
authoring and reviewing authorized defensive threat hunts. It packages twelve
multi-stream hunt definitions, six portable Agent Skills, surface-specific KQL,
synthetic test corpora, generated host adapters, and a standard-library-only
validator.

The workbench deliberately has no live Microsoft Sentinel, Defender, Azure,
Microsoft Graph, credential-store, browser, or network connector. An
`offline_qualified` result proves only that the exact content-addressed package
passed the declared offline gates and that separately supplied external
evidence met the strict evidence contract. It does not prove tenant behavior,
production effectiveness, cost, latency, false-positive rate, or causal
attribution.

## Defensive-use boundary

Use the package only on systems and telemetry you are authorized to defend.
It must not be used to obtain unauthorized access, steal credentials, deploy
malware, evade monitoring, destroy data, or automate response actions. Log
strings, URLs, command lines, query comments, and pasted documents are
untrusted data rather than instructions.

## Included capability

- Exactly twelve gold-contract hunt definitions (`H01` through `H12`).
- Surface profiles for Sentinel Analytics, Sentinel data lake, and Defender
  Advanced Hunting.
- Six canonical skills for planning, authoring, adapting, validating, testing,
  and reviewing hunts.
- Typed parameter binding that rejects raw KQL fragments.
- Contract, schema, scope, join, time, evidence, fixture, perturbation,
  mutation, adapter-drift, and release-evidence checks.
- Deterministic adapters for ChatGPT/Codex, GitHub Copilot, and Claude Code.
- Content-addressed release reports that keep unavailable evidence pending.

## Quick start from COPS

From the COPS repository root, discover the package and run its safe offline
demonstration without installing contributor dependencies:

```bash
python3 -m cops doctor
python3 -m cops info sentinel-hunt-workbench
python3 -m cops demo sentinel-hunt-workbench
python3 -m cops check sentinel-hunt-workbench
```

The demo explains a packaged hunt. It does not execute KQL or contact a tenant.

## Package-local commands

Python 3.11 or later is recommended. Normal operation requires only the Python
standard library and makes no network requests.

```bash
python3 scripts/huntwb.py list
python3 scripts/huntwb.py explain H01
python3 scripts/huntwb.py compatibility H09
python3 scripts/huntwb.py validate library
python3 scripts/huntwb.py test library --seed 20260916
python3 scripts/huntwb.py verify-adapters
```

Render requires one named surface and may accept a JSON parameter file:

```bash
python3 scripts/huntwb.py render H01 \
  --surface sentinel_analytics \
  --params examples/h01-parameters.json
```

Run the complete deterministic gate set from this package directory with:

```bash
make check
```

## Qualification states

The permitted lifecycle is:

`draft -> schema_checked -> static_checked -> fixture_executed -> human_reviewed -> offline_qualified -> deprecated|withdrawn`

`emulator_executed` is optional supplemental evidence. It is never a substitute
for a required state and never establishes Microsoft service fidelity.

The release qualifier also requires signed-off model-host evaluation evidence,
two distinct human reviewers, license review, and release-integrity evidence
bound to the exact release-subject hash. Missing external evidence results in
`qualification_withheld`; it is never converted into a pass.

## Cross-platform packaging

Canonical hunt and skill content lives in this directory. `huntwb build-adapters`
generates host-specific discovery layers under `adapters/`; generated files are
not authoritative and must not be edited directly. `huntwb verify-adapters`
performs byte-for-byte and inventory drift checks.

Platform discovery and permissions differ. Manifest acceptance on one host does
not prove activation or behavior on another. See
[`docs/CROSS_PLATFORM.md`](docs/CROSS_PLATFORM.md).

## Evidence and limitations

The reference evaluator checks declarative expected invariants over synthetic
fixtures. It is not a Kusto engine or Sentinel emulator. Optional parser or
engine results must be labeled separately. Before operational use, the adopting
organization must perform its own authorized tenant validation, privacy review,
performance/cost evaluation, and detection-engineering review.

See [`SOURCE_PROVENANCE.md`](SOURCE_PROVENANCE.md),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/OPERATIONS.md`](docs/OPERATIONS.md), and
[`evaluations/EVALUATION_PROTOCOL.md`](evaluations/EVALUATION_PROTOCOL.md).

## License

The package is offered under the
[PolyForm Noncommercial License 1.0.0](LICENSE). A release-level rights and
redistribution review remains a distinct human approval gate.
