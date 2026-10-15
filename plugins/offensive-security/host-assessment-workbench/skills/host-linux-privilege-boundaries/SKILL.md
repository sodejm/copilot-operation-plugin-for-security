---
name: host-linux-privilege-boundaries
description: Review bounded local Linux privilege-boundary exports without host execution or live validation claims.
---

# Linux privilege-boundary review

1. Confirm that the input is a local synthetic or operator export using the v1
   contract in `docs/IMPORT_CONTRACT.md` in this package. Do not acquire
   secrets or run host commands to fill missing fields.
2. Run `scripts/assess.py` on the export. Read per-surface coverage, host
   context, and prerequisite decision before discussing an observation.
3. Treat `configuration_candidate` as an interesting configuration only.
   `reported_canary_crossing` is an imported positive canary assertion, not an
   independently verified privilege boundary crossing. Verify source
   provenance separately before making a stronger claim.
4. Keep `not_assessed`, `unsupported`, `access_denied`, `unresolved`, and
   `inapplicable` visible. Do not convert them into clean results.
5. For live testing, stop at a reviewable plan until authorization, isolated
   disposable host, canary privilege, and ownership-aware cleanup are available.
   This package has no collector or live executor.
