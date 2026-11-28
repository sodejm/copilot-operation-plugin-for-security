# COPS Secrets Remediation Workbench

Assess redacted Git history and identity evidence to plan credential exposure remediation and verify lab revocation.

Maturity: **experimental**. Offline correction playback is available. Laboratory
isolation, host installation and production integrations remain unverified.

## Usage

From the repository, inspect the package metadata, run its fixture playback,
and validate its package contract:

```console
python3 -m cops info secrets-remediation-workbench
python3 -m cops demo secrets-remediation-workbench
python3 -m cops check secrets-remediation-workbench
```

From an exported package, run `python3 scripts/demo.py`. Inspect supplied input
with `python3 scripts/assess.py --input examples/input.json --as-of
2026-10-15T12:00:00Z`.

Scan a local repository's reachable history with `python3
scripts/scan_git_history.py --root /absolute/path/to/repository`. The scanner uses
bounded, read-only Git commands and recognizes only the documented synthetic test
credential patterns. Its JSON output can be supplied directly as the sole artifact
in the assessment input. See [Git history scanner](docs/GIT_HISTORY_SCANNER.md).

Create a strict native report with `python3 scripts/report.py --input
examples/input.json --as-of 2026-10-15T12:00:00Z --report-id report-demo
--engagement-id eng-demo --scenario-id COPS-DEMO --result-id res-demo
--target fixture:secrets-demo`. The caller must supply those context identifiers;
the wrapper does not invent engagement or target provenance.

## Design

The package uses the bounded COPS artifact assessment engine and content-free
SHA-256 evidence references. An immutable copy of its runtime is included in
`vendor/runtime`; update it using the repository runtime synchronization script.
The assessment does not establish production exploitability or compliance.

## Data Contract

| Artifact | Purpose | Producer | Consumer | Validation |
| --- | --- | --- | --- | --- |
| `examples/input.json` | Supplied artifact envelope | Authorized collector | Assessment engine | Type and byte bounds |
| `examples/correction-cases.json` | Correction acceptance cases | Synthetic fixture author | Demo and package checks | Expected codes and content hashes |
| `cops.git-history-scan/v1` | Redacted reachable-history observations | `scripts/scan_git_history.py` | Credential-history assessment | Hard bounds, safe paths and content-free fingerprints |
| Assessment result | Findings, coverage and limitations | Engine | Reviewer or report exporter | Native Finding contract and SHA-256 |
| Assessment report | Strict imported-evidence report | `scripts/report.py` | Native report exporter | `cops.assessment-report/v1` semantic validation |

See the [runnable playbook](docs/PLAYBOOK.md), [verification](docs/VERIFICATION.md),
and [walkthrough](docs/offline-assessment.md).
