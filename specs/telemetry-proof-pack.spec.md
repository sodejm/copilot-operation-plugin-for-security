# Telemetry Proof Pack Correlation Specification

## Scope

The Telemetry Proof Pack compares operator-supplied, offline records for one
synthetic marker across source emission, Cribl routing, destination indexing,
query evaluation, and alert creation. It does not collect records from those
systems or establish that a live pipeline or detection is healthy.

## Inputs and evidence boundaries

- A run manifest identifies the marker, expected tenant or workspace, route,
  detection rule, capture window, allowed clock skew, and retention policy.
- Each stage file contains one JSON record or a `{"records": [...]}` envelope.
  A marker repeated in fields of one record counts as one match; distinct
  matching records count separately.
- Stage timestamps must have a timezone and fall within the manifest capture
  window expanded by the allowed clock skew at both ends. The destination
  timestamp must represent indexing time if collection delay is being assessed.
- The report hashes supplied evidence content for comparison. It cannot
  authenticate the export, verify collection completeness, or enforce the
  manifest's retention policy. Operators sanitize exports and restrict access
  to exports and reports before use.

## Correlation outcomes

1. A stage with one matching, in-window record and a passing stage-specific
   check is `observed`.
2. A stage with no matching supplied record is `missing`. That state describes
   the export, not the live service.
3. A stage with multiple matching records, an invalid or missing timestamp, or
   an out-of-window timestamp is `unresolved`. Preserve its evidence ID, matching
   IDs when duplicated, source timestamp, details, and evidence hash. Preserve
   the independent outcomes of other stages.
4. The report is `healthy` only when all five stages are observed. It is
   `degraded` when a destination marker record was supplied but the trace is
   incomplete. It is `broken` when no destination marker record was supplied.
   These are labels for supplied evidence, not infrastructure uptime.
5. `detection_fired` in the JSON report is true only when an in-window alert
   record is observed. The Markdown report calls this an observed alert record.
   The reported interval spans only observed stage timestamps.

## Acceptance evidence

- `tests/test_workbench.py` exercises healthy routes, existing failure modes,
  duplicate marker records, delayed indexing, timestamp boundaries, and
  preservation of unaffected stage evidence.
- `scripts/validate_package.py` checks both healthy routes and the dedicated
  duplicate and delayed fixtures.
- The package README, playbook, and tracing skill document collection rights,
  source timestamp limits, privacy, and the distinct role of the Detection
  Quality & Regression Workbench.
