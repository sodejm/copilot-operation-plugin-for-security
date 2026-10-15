# Linux privilege-boundary import contract v1

The workbench reads an already-produced, sanitized local JSON export. It does not
collect host data, execute commands, test privileges, or verify the exporter's
assertions. Run `python3 scripts/assess.py <export.json>` from this package.
Valid input produces a deterministic JSON report on stdout; invalid input exits
with status 2 and no report.

The root object has exactly `schema_version`, `source_kind`, `source_id`, `host`,
`coverage`, and `observations`. `schema_version` is `"1.0"`; `source_kind` is
`synthetic_lab` or `operator_export`. `source_id`, observation IDs, resource IDs,
and evidence IDs are bounded opaque identifiers, never paths or raw evidence.
The [positive fixture](../fixtures/synthetic/host_linux_positive_v1.json) is a
complete example; the negative and fixed fixtures use the same contract.

| Field | Required value |
| --- | --- |
| `host.kernel_release`, `host.distribution_version` | Version identifiers, or `unknown` |
| `host.distribution_id` | Opaque identifier, or `unknown` |
| `host.namespace` | `host`, `container`, or `unknown` |
| `host.protections` | Exactly `selinux`, `apparmor`, `no_new_privs`, `seccomp`, `user_namespaces`; each may be `unknown` |
| `coverage` | Exactly the eight surfaces below, each `assessed`, `not_assessed`, `unsupported`, or `access_denied` |
| `observations[]` | `id`, `surface`, `configuration`, `evidence_ids`, `requirements`, and optional `canary` |
| `observations[].requirements` | Exact kernel release, distribution ID and version, namespace (`host` or `container`), and a `protections` map of relevant controls |
| `observations[].canary` | `case`, `resource_id`, `disposable_host`, `assessment_owned`, `before_access`, `after_access`, `evidence_ids`, `cleanup_verified` |

The eight surfaces are `permissions`, `services`, `scheduled_tasks`,
`capabilities`, `sudo`, `suid`, `credential_exposure`, and `container_context`.
An observation requires `assessed` coverage for its surface. Its configuration
is `interesting`, `ordinary`, or `unknown` and needs at least one evidence ID.
Requirements need concrete values; `unknown` is only valid in host context.

Protection states are control-specific. SELinux accepts `enforcing`,
`permissive`, or `disabled`; AppArmor accepts `enforcing`, `complain`, or
`disabled`; no-new-privileges, seccomp, and user namespaces accept `enabled`
or `disabled`. A known prerequisite mismatch yields `inapplicable`; an unknown
host prerequisite yields `unresolved`. Neither is selected for a canary result.

A canary is allowed only on a reported disposable host with assessment-owned
resource and verified cleanup; those three fields must be `true`. `case` is
`positive`, `negative`, or `fixed`. `before_access` must be `denied`. Positive
requires `after_access: granted`; negative and fixed require
`after_access: denied`. At least three canary evidence IDs are required. A
selected positive is labeled `reported_canary_crossing`; selected negative or
fixed is `reported_canary_blocked`. These remain imported assertions. Without a
canary, selected observations are `configuration_candidate`,
`ordinary_configuration`, or `insufficient_evidence`. Unselected observations
are `not_evaluated`.

Input is limited to 1 MiB, JSON depth 64, 256 observations, and 32 evidence IDs
per list. IDs are at most 64 ASCII letters, digits, underscores, or hyphens and
begin with a letter or digit. Version fields also allow dots, plus, and minus.
Unknown fields and versions, duplicate JSON keys or IDs, nonfinite or oversized
JSON numbers, raw credentials, free-form evidence, and paths are rejected. A
rejected or unassessed surface cannot be interpreted as safe. Independently
observed host behavior, source provenance, and cleanup require separate evidence.
