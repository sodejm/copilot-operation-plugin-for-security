# COPS Host Assessment Workbench

This experimental package reviews **local Linux privilege-boundary exports**. It
does not collect host data or attempt privilege escalation. The versioned import
contract is `specs/host-linux-privilege-boundaries.spec.md` in the source repository.

## Use

From the repository root:

```bash
python3 -m cops demo host-assessment-workbench
python3 -m cops check host-assessment-workbench
python3 plugins/offensive-security/host-assessment-workbench/scripts/assess.py path/to/export.json
```

The last command reads at most 1 MiB of JSON from a local file and writes a
deterministic JSON report to standard output. The export must use the exact v1
schema. Use opaque, non-sensitive IDs; do not include credentials, free-form
evidence, or filesystem paths. The importer rejects unsupported fields and
contradictory canary assertions, but cannot independently establish whether a
source's statements are true.

The report includes coverage for permissions, services, scheduled tasks,
capabilities, sudo, SUID, credential exposure, and container context. A
configuration candidate is distinct from a **reported** canary crossing. A
positive canary requires denied-before/granted-after access to an
assessment-owned resource on a disposable host, plus a reported cleanup
verification. Negative and fixed cases require denied-before/denied-after.
Unassessed, unsupported, denied, or unknown coverage never establishes safety.

Any live assessment needs a separate approved scope, canary privileges,
isolated worker, disposable host, and ownership-aware cleanup evidence. This
package supplies none of those execution capabilities. E06.01-S01/S02 are
planning references pending exact source mapping under E01.1.
