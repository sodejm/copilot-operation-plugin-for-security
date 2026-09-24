# Operations guide

This guide covers local, offline operation. It does not authorize tenant access
or live query execution.

## Prerequisites and safe defaults

- Python 3.11 or newer; the normal gate set uses only the standard library.
- A clean review of any supplied parameter file. Do not place credentials,
  tokens, customer logs, or personal data in fixtures or release artifacts.
- An authorized defensive objective and a named execution surface.
- No network or Microsoft tenant permission is required or requested.

Run commands from the package root:

```bash
python3 scripts/huntwb.py list
python3 scripts/huntwb.py explain H01
python3 scripts/huntwb.py compatibility H01
python3 scripts/huntwb.py validate library
python3 scripts/huntwb.py test library --seed 20260916
make check
```

## Rendering a hunt

Select one surface and provide a JSON object containing only declared, typed
parameters. Raw KQL is never an allowed parameter type.

```bash
python3 scripts/huntwb.py render H01 \
  --surface sentinel_analytics \
  --params /absolute/path/to/parameters.json
```

Rendering fails when the hunt is unsupported or unverified for the requested
surface. The workbench will not drop an unavailable stage to make a query appear
portable.

## Interpreting results

Exit codes are stable:

| Code | Meaning |
|---:|---|
| 0 | Requested checks passed within their declared offline scope |
| 2 | Content or contract validation failed |
| 3 | Surface-profile incompatibility |
| 4 | Fixture, perturbation, mutation, or adversarial test failed |
| 5 | Required tool or evidence unavailable; this is not a pass |
| 6 | Internal validator error |

`fixture_executed` means the deterministic synthetic corpus passed. It does not
mean that KQL was executed by Kusto or Microsoft Sentinel. `qualification_withheld`
is the expected release status until all external host runs, two independent
human approvals, license review, and integrity evidence are present and valid.

## Release procedure

1. Run `make check` without regenerating adapters. Resolve any drift.
2. Run `make release` to create deterministic local integrity evidence and the
   release report.
3. Verify that local gates pass and model, reviewer, or license evidence remains
   `pending` unless genuine content-addressed evidence was supplied.
4. Have two qualified reviewers inspect security, hunt quality, uncertainty
   language, residual risk, sources, and licensing.
5. Run the external 2,160-run host matrix under the evaluation protocol.
6. Rebuild the report against the exact same release-subject hash.
7. Before operational use, manually validate supported hunts in an authorized
   tenant, including schema, cost, latency, retention, and benign baselines.

Never edit an evidence wrapper to turn a pending gate into a pass. Evidence
payloads and pointers are verified by digest, exact keys, subject hash, record
counts, and gate-specific semantics.

## Incident and maintenance handling

Withdraw a hunt or profile immediately if a schema assumption, safety boundary,
or evidence interpretation becomes invalid. Review Microsoft surface profiles at
least quarterly and after announced breaking changes. Re-run every deterministic
and model-assisted gate after material content, profile, prompt, validator,
adapter, or model-configuration changes.

Validation logs should contain only hashes, versions, counts, error codes,
durations, and bounded diagnostics. Do not log raw telemetry or full sensitive
parameters. Retain immutable release reports and the exact content they cover.

