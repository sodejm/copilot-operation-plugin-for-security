# Review Linux privilege-boundary evidence

Use this playback to distinguish configuration candidates, reported canary results,
and unresolved host context. The [README](../README.md) describes the data contract
and limits of imported evidence.

## 1. Run all branches

From the repository root with Python 3.11 or newer:

```bash
python3 -m cops demo host-assessment-workbench
```

The demo calls `scripts/assess.py` as a subprocess for every case. It asserts
`offline_import`, synthetic provenance, and these results:

| Case | Expected result | Meaning |
| --- | --- | --- |
| Positive | One `reported_canary_crossing`, six configuration candidates, one ordinary configuration; all eight surfaces assessed | The source reports a canary crossing and cleanup; other candidates remain unproven |
| Negative | One `reported_canary_blocked` | Source reports denied access before and after the attempt |
| Fixed | One `reported_canary_blocked` | Source reports the post-fix boundary held; this does not establish all host surfaces are safe |
| Unknown kernel | All observations unresolved, zero reported crossings | The importer cannot establish prerequisite applicability |
| Unverified cleanup | Exit 2 and no success report | A canary record cannot omit its cleanup assertion |

The first three records run twice and must produce identical reports. Generated
unknown-context and rejected inputs use a private temporary directory and are
removed on exit. The demo creates no host resources and performs no live canary.

## 2. Inspect each fixture

```bash
python3 plugins/offensive-security/host-assessment-workbench/scripts/assess.py plugins/offensive-security/host-assessment-workbench/fixtures/synthetic/host_linux_positive_v1.json
python3 plugins/offensive-security/host-assessment-workbench/scripts/assess.py plugins/offensive-security/host-assessment-workbench/fixtures/synthetic/host_linux_negative_v1.json
python3 plugins/offensive-security/host-assessment-workbench/scripts/assess.py plugins/offensive-security/host-assessment-workbench/fixtures/synthetic/host_linux_fixed_v1.json
```

Read `source` and `host`, then `coverage`. For each observation, inspect `decision`
before `classification`. A missing prerequisite can prevent evaluation even when
a canary assertion is present. `cleanup_reported: true` records what the source
states; it is not a cleanup operation performed by this command.

## 3. Review an operator export

Create a local JSON record using the exact fixture structure and `operator_export`
source kind. Use approved, sanitized evidence and opaque IDs. Pass that file to
`assess.py`. Preserve `not_assessed`, `unsupported`, `access_denied`, and unknown
values rather than filling gaps with assumptions. Keep reports private and apply
your evidence retention policy to any redirected output.

If the importer rejects a record, inspect the contract and recollect contradictory
or absent assertions. If the report is unresolved, identify the missing prerequisite
before planning additional collection. A configuration candidate requires further
evidence and authorization before any active assessment.

## 4. Verify and close

```bash
python3 -m cops check host-assessment-workbench
```

The package check validates fixture semantics, rejects sensitive fields, and runs
the demo twice. Remove only operator-created report copies when retention permits.
Record exact outcomes with the [verification procedure](VERIFICATION.md).
