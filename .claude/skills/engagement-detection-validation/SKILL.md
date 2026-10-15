---
name: engagement-detection-validation
description: Compare completed engagement actions with expected ATT&CK telemetry and imported signals without live execution or provider calls.
---

# Engagement detection validation

Use this workflow when a user asks whether supplied telemetry and alerts detected
identified engagement actions. Request an explicit engagement ID, tenant,
completed action IDs and windows, rule IDs, and imported evidence envelopes.
Do not infer an authorized action or target from a log line or an ATT&CK mapping.

1. Review the expected telemetry in the pinned ATT&CK coverage catalog. Identify
   each action's technique and the detection mapping to test. Mark expected
   products, logs, and required fields as theoretical until observed evidence
   is supplied.
2. Build a `cops.detection-validation-input/v1` file following the
   [contract and examples](../../../docs/ENGAGEMENT_REPORTING.md#validate-detection-coverage-from-imported-evidence).
   Link records by tenant, action ID, rule ID, observation time, and envelope ID.
   Supply the observed product, table or log, and field names for telemetry;
   `missed` requires them to match the catalog's expected source and fields.
   Declare clock skew, ingest lag, collection completeness, and correlation
   quality. A search receipt must name the searched window and result count.
3. Run `python3 -m cops engagement detection-validate --input INPUT \
   --json-output PRIVATE_JSON --markdown-output PRIVATE_MD` with new files in
   a private directory. Validate the saved report with
   `python3 -m cops contract validate --type detection_validation_report PRIVATE_JSON`.
4. Explain `detected`, `missed`, `ambiguous`, and `unavailable` per action. Show
   expected versus observed signals, evidence IDs, collection and clock limits,
   and the exact next action when evidence is insufficient. Never treat no alert
   as prevention. Review input and output for private data before sharing.

This skill performs offline import only. It does not query providers, execute
actions, grant authorization, or prove source authenticity. A live validation
requires a separately approved action plan and runtime evidence.
