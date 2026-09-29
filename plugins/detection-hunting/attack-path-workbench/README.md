# Attack Path Workbench

An offline plugin for evidence-linked, conditional attack-path analysis. It supports a synthetic illustrative export contract and local Azure entitlement evidence. It makes no network calls. Real Wiz field mapping and query rendering require approved documentation and representative redacted exports.

## Try the illustrative fixture

From this directory:

```sh
python3 scripts/attackpath.py analyze fixtures/illustrative/input.json --output-dir /tmp/attack-path-illustrative
python3 scripts/attackpath.py query-intent --start ILL-FINDING --target ILL-CROWN --scope ILL-SCOPE
python3 -m unittest discover -s tests -v
```

Choose a fresh output directory. The analysis writes `report.json`, `report.md`, `graph.json`, and `remediation-ledger.json`. The fixture is invented test data, not a finding or a Wiz export. A structural route is conditional on exploiting its starting finding; the candidate route has explicit gaps. Business rating stays `unrated`; ATT&CK, Attack Flow, and Wiz rendering stay pending approved local material.

## Analyze Azure entitlement evidence

```sh
python3 scripts/attackpath.py plan-azure-collection --scope-file scopes.json --output collection-plan
python3 scripts/attackpath.py analyze-azure --input bundle/manifest.json --as-of 2026-09-28T12:00:00Z --output azure-report
```

Both commands operate offline and require a fresh output directory. The planner
writes versioned Graph/ARM GET requests and Resource Graph inventory POST requests
for a separately authorized collector. The analyzer
requires checksummed COPS Evidence SDK pages and acquisition receipts; it models
permissions and explicit runtime assumptions without executing a path. Read the
[Azure entitlement guide](docs/azure-entitlements.md) for input contracts,
prerequisites, output classifications, privacy controls, and limits.

## Contracts and boundaries

- [Architecture and analysis method](docs/architecture.md) gives component responsibilities, workflow, graph rules, impact method, and review boundaries.
- [Data contract](docs/data-contract.md) explains inputs, provenance, and output schemas.
- [Decision gates](docs/gates.md) describes G1–G8, graph semantics, ranking, and confidence.
- [Integration boundaries](docs/integration-boundaries.md) lists the materials needed for Wiz, business-impact, and MITRE integration.
- [Operations](docs/operations.md) covers report review and remediation tracking.
- [Implementation status](docs/implementation-plan.md) records what runs now and what remains gated.
- [Specialist definitions](agents/README.md) define bounded advisory review.

The supplied background references are [Wiz attack-path analysis](https://www.wiz.io/academy/detection-and-response/attack-path-analysis), [Picus attack-path analysis](https://www.picussecurity.com/resource/blog/what-is-attack-path-analysis), [MITRE ATT&CK](https://attack.mitre.org/), and [MITRE Attack Flow](https://ctid.mitre.org/projects/attack-flow/). These links are context, not an installed reference bundle or executable integration.
