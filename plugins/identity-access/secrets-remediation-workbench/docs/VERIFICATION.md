# Verification

## Scope and prerequisites

Python 3.11 or later; supplied synthetic JSON artifacts. No credentials or network
are required for offline inspection. Git is required only for the bounded history
scanner and is declared in `org.cops/prerequisites.json`. Unsupported formats remain
explicit limitations.

## Baseline checks

Run each repository command independently:

```console
python3 -m cops info secrets-remediation-workbench
python3 -m cops demo secrets-remediation-workbench
python3 -m cops check secrets-remediation-workbench
```

## End-to-end exercise

Review the baseline demo output and compare all four fixture states.
For an exported package run `python3 scripts/validate_package.py`.
Then run `python3 scripts/report.py` with the explicit identifiers shown in the
[walkthrough](offline-assessment.md) and validate its JSON output.

For the history path, create an isolated repository containing only synthetic test
data and run `python3 scripts/scan_git_history.py --root /absolute/path/to/repository
--git-sha256 <reviewed-lowercase-sha256>`.
Confirm that the output contains fingerprints, paths, commit IDs and source
provenance without any matched credential value. Pass that object to
`scripts/assess.py` as an artifact to retain unknown rotation and revocation status.

## Acceptance criteria

Vulnerable evidence yields the pinned finding codes; corrected and benign evidence
clear those codes. Insufficient evidence retains unknown or limited coverage.
Hashes bind supplied evidence; no credential values appear in output.
The native report uses schema `cops.assessment-report/v1`, provenance `imported`,
and coverage status `partial` or `not_assessed`.

## Failure and recovery

Reject invalid types or oversized input; correct the supplied envelope and retry.
Read-only inspection leaves originals unchanged. Never infer success from a skipped check.

## Host exercise

Install an exported package on each advertised host and execute its demo. Host and
live validation remain unverified until recorded separately. Laboratory promotion
requires the repository `make check-laboratory` isolation gate.

## Record and promote

Record revision, input hashes, command, exit status, findings and limitations.
Only promote the exact readiness dimension established by that evidence.
