---
name: attack-path-report
description: Produce a reproducible offline attack-path report and local remediation ledger with citations, gaps, and closure criteria.
---

# Reporting

Use the deterministic CLI output as the canonical report. Keep source assertions, derived relationships, hypotheses, and recommendations labeled. Include source pointers for material claims, a coverage statement, supported and candidate paths, excluded transitions, `unrated` impact when applicable, pending mappings, actions, alternatives, and human decisions.

Do not mark remediation closed from a recommendation or a later export alone. Closure needs an owner and the stated validation evidence. Never overwrite an existing output directory. Compare run IDs and canonical JSON bytes for identical inputs, rules, and profiles. See `docs/operations.md`.
