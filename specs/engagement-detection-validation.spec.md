# Offline engagement detection validation

## Goal and evidence boundary

Join a completed, identified engagement action to the pinned ATT&CK coverage
catalog and supplied telemetry, alert, and search evidence. This is an offline
import. It does not run a detection, query a provider, authenticate an evidence
source, or establish that an action was authorized. Catalog mappings describe
expected telemetry; they never establish a measured outcome by themselves.

## Input and classification

`cops.detection-validation-input/v1` carries an engagement and tenant ID, a
bounded set of action/check rows, and `cops.evidence/v1` envelopes. Each check
names one action, ATT&CK mapping, and rule, a bounded clock-skew and ingest-lag
allowance, declared collection and correlation states, and record IDs for the
execution observation, telemetry, alerts, and completed search receipt. All
referenced envelopes must be internally valid, tenant-matched, and linked by
their typed payloads to the same action and rule. The ATT&CK mapping must match
the action technique.

The report uses four measured labels:

- `detected`: a completed action has an execution observation and an in-window
  alert explicitly linked to the rule and action under exact correlation.
- `missed`: a completed action and in-window telemetry from an expected product
  and log with required fields have linked evidence,
  exact correlation and complete collection are declared, and a completed
  zero-result search receipt covers the action window plus skew and ingest lag.
  Alerts outside that expanded window remain visible but do not contradict the
  covering zero-result search.
- `ambiguous`: supplied signals exist but their timing, correlation, or search
  completeness cannot establish either of the above outcomes.
- `unavailable`: the action was not completed, its in-window execution
  observation is absent, or collection is declared unavailable.

The expected product, log, and fields are imported assertions rather than
independent source verification. The receipt is a supplied search result, not a guarantee of provider-wide
completeness. Missing telemetry never means prevention or a successful defense.
The private JSON report preserves expected products and logs, each imported
execution/telemetry/alert observation with its record ID, timestamp, and
in-window classification, plus the search receipt result and window coverage.
The Markdown report shows in-window signal counts, classification limits, and a
concrete next action for each result without copying evidence payloads or source
locations. Imported evidence
hashes establish only internal integrity; source trust remains unverified.

## Acceptance

The persisted synthetic corpus is executable through the public CLI and covers
detected, missed, ambiguous, and unavailable outcomes. It includes exact
in-window correlation, a complete zero-result search covering the expanded
window, and an alert outside the expanded window. Negative fixtures cover
cross-tenant evidence; executable scenarios also cover mismatched action evidence
and the zero-result/full-window rule. The CLI reads at most 4 MiB, creates new
owner-only JSON and Markdown files, and makes no network request. User text and
evidence payloads never appear in the Markdown report. This acceptance validates
offline import and classification only. Native SIEM or EDR validation requires
separately authorized runtime evidence.

## Pinned source traceability

`catalog/detection_validation_source_traceability.json` records the E17.02
disposition of every pinned S01 through S13 source in `catalog/provenance.json`.
Each row carries the source's exact pinned revision, a JSON Pointer to its
file-or-section inventory, and the canonical scenario, guidance, or decision
identifiers represented by that inventory. S02 is direct detection-validation
guidance because its pinned inventory contains `COPS-E17.02-GUIDE`; the other
sources provide action context whose observed activity may be evaluated by this
workflow.

This catalog is static, offline traceability. It does not contain action IDs,
time windows, telemetry, alerts, searches, or measured outcomes. Native SOC
validation remains pending until separately authorized execution evidence is
correlated to source-authenticated telemetry and search receipts with explicit
clock, ingest, collection, and correlation limits. Missing telemetry never
proves prevention.
