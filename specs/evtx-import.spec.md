# Bounded offline EVTX import

## Contract

`cops telemetry import-evtx --input FILE --sha256 EXPECTED` imports a read-only
snapshot through the registered `sysmon-evtx/v1` artifact adapter. It returns
`cops.evtx-import/v1` JSON. Import is separate from native acquisition and active
execution; it does not consume an ActionPlan approval or invoke a connector.

The adapter accepts clean, non-wrapped EVTX 3.1/3.2 exports with valid file,
chunk, and record structure and checksums. It requires the caller's expected
SHA-256, a regular non-symlink source, and an unchanged source identity during
the bounded read. Unsupported layouts fail explicitly rather than recovering
or silently dropping records. Core framing validation uses only the standard
library. The optional parser is exactly `python-evtx==0.8.1` with `hexdump==3.3`.
The fixed artifact registry permits Linux parsing only; other platforms return
`unsupported_parser_platform`. Framing validation remains portable.

Before parsing, enforce 8 MiB input, 4,096 records, a 10 second deadline,
512 MiB address-space limit, 5 second CPU limit, and 2 MiB output limit. These
are upper bounds; callers may lower input, record, and deadline budgets. The
parser runs in a fresh child interpreter against a private snapshot. It never
executes event content. This resource boundary is not an OS or network sandbox.
The strict laboratory gate additionally supplies verified network isolation.

Normalize only Sysmon event IDs 1, 3, and 10. Retain source digest, record ID,
UTC event timestamp, and evidence references. Export only fixed image families,
validated addresses, and derived flags; never raw command lines, users, or
filesystem paths. Reject XML entities, duplicate event fields, oversized XML,
and malformed supported events. Unknown providers/events and missing required
fields produce partial evidence, never a successful detection assessment.

The result records every input record as normalized or unsupported/incomplete.
An empty or partially supported source is indeterminate for detection coverage.
An indicator match is an observation, not proof of malicious activity. Absence
of an indicator in a fully supported fixture is not a clean-host assessment.

## Acceptance

Deterministic generated binary EVTX fixtures contain vulnerable, corrected, and
insufficient evidence counterparts. They are synthetic EVTX containers, not
Windows-acquired evidence. Record their provenance, checksums, expected counts,
and regeneration command. An independent pinned parser must read the fixtures.
Reject changed bytes, bad CRCs, record truncation, count mismatches, unsupported
layouts, symlinks, budgets, unavailable/wrong parser versions, and parser failure.
Verify source immutability, redaction, timeout cleanup, and no content execution.
The required laboratory case cannot skip an unavailable parser.

See [executable acceptance scenarios](features/evtx_import.feature).
