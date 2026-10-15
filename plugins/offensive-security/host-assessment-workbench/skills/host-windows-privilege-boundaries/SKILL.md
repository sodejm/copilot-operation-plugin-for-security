---
name: host-windows-privilege-boundaries
description: Review bounded Windows privilege-boundary exports and, when explicitly authorized, run the read-only native Windows collector.
---

# Windows privilege-boundary review

1. Confirm that the input is a local synthetic or operator export using the
   `windows-1.0` contract in `specs/host-windows-privilege-boundaries.spec.md`.
   Do not acquire credentials or run unrelated host commands to fill missing fields.
2. When the operator explicitly requests native collection on an authorized local
   Windows host, require new output files and an existing empty assessment-owned
   local canary directory. Run `scripts/collect-windows.ps1` without elevation.
   The collector reads bounded metadata only; do not add privilege crossing,
   credential-value access, execution, or control changes.
3. Run `scripts/assess.py` on the export. Check declared bridge capability,
   coverage, OS build, architecture, token, protections, and per-observation
   prerequisite decision before discussing a result.
4. For native collection, run `scripts/validate-windows-bridge.py` against the
   receipt, exact export, and supplied canary root. Require the root to remain
   empty. Delete only the operator-created run directory after evidence retention.
5. Treat `configuration_candidate` as a configuration observation only.
   `reported_canary_crossing` is an imported source assertion, not independently
   verified privilege crossing or restoration. Verify provenance separately.
   The native lifecycle receipt verifies cleanup of the assessment-owned marker,
   not a privilege-boundary crossing.
6. Keep `not_assessed`, `unsupported`, `access_denied`, `unresolved`, and
   `inapplicable` visible. None establishes a safe host.
7. Any active privilege-boundary test remains outside this skill. It requires
   separately approved scope, an isolated disposable Windows host, a capable
   adapter, and ownership-aware cleanup evidence.
