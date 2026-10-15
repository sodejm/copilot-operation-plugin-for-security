---
name: host-windows-privilege-boundaries
description: Review bounded Windows privilege-boundary exports and, when explicitly authorized, run the read-only native Windows collector.
---

# Windows privilege-boundary review

1. Confirm that the input is a local synthetic or operator export using the
   `windows-1.0` contract in `docs/WINDOWS_CONTRACT.md` within this package.
   Do not acquire credentials or run unrelated host commands to fill missing fields.
2. When the operator explicitly requests native collection on an authorized local
   Windows host, use a new run path beneath an existing local, non-reparse
   directory and run `scripts/exercise-windows-bridge.ps1` without elevation.
   This is the practitioner and hosted-CI entry point. The collector reads bounded
   metadata only; do not add privilege crossing, credential-value access,
   execution, or control changes.
3. Review the retained report. Check declared bridge capability,
   coverage, OS build, architecture, token, protections, and per-observation
   prerequisite decision before discussing a result.
4. For native collection, retain the exercise's export, receipt, report, and
   validated receipt. Require canonical root and child identity binding,
   ownership verification before deletion, and an empty canary root. Delete only
   the operator-created run directory after evidence retention.
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
