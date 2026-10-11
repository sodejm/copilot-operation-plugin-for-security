---
name: host-windows-privilege-boundaries
description: Review bounded local Windows privilege-boundary exports without host execution or live validation claims.
---

# Windows privilege-boundary review

1. Confirm that the input is a local synthetic or operator export using the
   `windows-1.0` contract in `specs/host-windows-privilege-boundaries.spec.md`.
   Do not acquire credentials or run host commands to fill missing fields.
2. Run `scripts/assess.py` on the export. Check declared bridge capability,
   coverage, OS build, architecture, token, protections, and per-observation
   prerequisite decision before discussing a result.
3. Treat `configuration_candidate` as a configuration observation only.
   `reported_canary_crossing` is an imported source assertion, not independently
   verified privilege crossing or restoration. Verify provenance separately.
4. Keep `not_assessed`, `unsupported`, `access_denied`, `unresolved`, and
   `inapplicable` visible. None establishes a safe host.
5. Live testing requires approved scope, an isolated worker, disposable Windows
   host, Windows-capable adapter, assessment-owned canary, and ownership-aware
   cleanup evidence. This package has no collector or live executor.
