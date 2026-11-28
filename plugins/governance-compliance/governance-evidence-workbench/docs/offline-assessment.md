# Offline assessment walkthrough

Run these commands from the exported package directory. The walkthrough reads
the supplied JSON locally. It requires no provider connection or credentials.

Run `python3 scripts/demo.py` to compare vulnerable, corrected, insufficient and benign fixtures.

## `compliance_evidence`

Run `python3 scripts/assess.py compliance_evidence --input examples/input.json --as-of
2026-10-15T12:00:00Z` for the bounded assessment.

Run `python3 scripts/report.py compliance_evidence --input examples/input.json --as-of
2026-10-15T12:00:00Z --report-id report-demo --engagement-id eng-demo
--scenario-id COPS-DEMO --result-id res-demo --target fixture:compliance-demo`
for a strict assessment report.

Confirm that the report uses `cops.assessment-report/v1` and records
`imported` coverage with status `partial` or `not_assessed`. Keep the
artifact envelope private. The report references the supplied bytes by
hash. The evidence source, authorization, and live state need independent verification.
