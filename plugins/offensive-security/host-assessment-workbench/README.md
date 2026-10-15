# COPS Host Assessment Workbench

Review sanitized Linux privilege-boundary exports and identify which observations
apply to the reported host context. This experimental package imports local JSON;
it does not collect host data or attempt privilege escalation.

## Start here

Use Python 3.11 or newer and run from the repository root:

```bash
python3 -m cops info host-assessment-workbench
python3 -m cops demo host-assessment-workbench
python3 -m cops check host-assessment-workbench
```

The demo checks positive, negative, fixed, unknown-context, and invalid-cleanup
inputs through the public importer. Follow the [practitioner playback](docs/PLAYBOOK.md)
for individual commands and result interpretation. Use the
[verification playbook](docs/VERIFICATION.md) to record qualification evidence.

## Design and evidence theory

A configuration observation can suggest a privilege boundary worth investigating,
but it does not prove that the boundary was crossed. The importer first compares
the observation's kernel, distribution, namespace, and protection requirements
with the reported host. A known mismatch is `inapplicable`; an unknown prerequisite
is `unresolved`. Neither selects the observation for a canary conclusion.

A selected configuration can be a `configuration_candidate`,
`ordinary_configuration`, or `insufficient_evidence`. A canary record adds explicit
before/after access assertions, ownership, disposable-host status, evidence IDs,
and cleanup. A positive case requires denied-before/granted-after access; negative
and fixed cases require denied-before/denied-after. The resulting labels are
`reported_canary_crossing` and `reported_canary_blocked`: the importer checks the
contract but does not independently verify the source's claims.

## Data contracts

The [positive](fixtures/synthetic/host_linux_positive_v1.json),
[negative](fixtures/synthetic/host_linux_negative_v1.json), and
[fixed](fixtures/synthetic/host_linux_fixed_v1.json) fixtures are complete runnable
inputs. The [Linux privilege-boundary import contract](docs/IMPORT_CONTRACT.md)
defines the exact schema.

| Record or field | Purpose and producer | Consumer and validation |
| --- | --- | --- |
| Input `schema_version` | Exporter selects contract `1.0` | Importer rejects unknown versions or fields |
| `source_kind`, `source_id` | Exporter labels `synthetic_lab` or `operator_export` and an opaque provenance ID | Copied to report `source`; this is not independent provenance verification |
| `host` | Kernel release, distribution ID/version, `host`/`container`/`unknown` namespace, protection states | Compared with each observation's prerequisites; unknown values remain unresolved |
| `host.protections` | `selinux`, `apparmor`, `seccomp`, `no_new_privs`, `user_namespaces` | Required host context; selected requirements must agree |
| `coverage` | Status for permissions, services, scheduled tasks, capabilities, sudo, SUID, credential exposure, container context | Each surface is `assessed`, `not_assessed`, `unsupported`, or `access_denied`; observations require assessed coverage |
| `observations[]` | ID, surface, configuration assertion, evidence IDs, requirements, optional canary | Importer rejects duplicate IDs, unsupported fields, and contradictory claims |
| `observations[].canary` | Case, resource ID, before/after access, evidence IDs, ownership and cleanup assertions | At least three evidence IDs; disposable host, assessment ownership, and cleanup must all be true |
| Report `mode`, `source`, `host`, `coverage` | Importer preserves import context | Analyst sees `offline_import` and explicit coverage limits |
| Report `observations`, `counts` | Importer supplies decisions, classifications, prerequisites, and totals | Analyst distinguishes candidates from reported crossings and unresolved observations |

The importer bounds input to 1 MiB, JSON depth 64, and 256 observations. Use opaque,
non-sensitive IDs. Credentials, free-form evidence, paths, duplicate JSON keys,
and non-finite numbers are rejected. Unassessed or denied coverage never establishes
that a host is safe.

## Operations and limits

Valid input produces deterministic JSON on stdout. Invalid input exits 2 with no
success report. Fix the input contract or preserve a missing-evidence outcome;
do not change assertions merely to obtain a selected result. See the playback for
repeatability and cleanup checks.

A live assessment requires separately approved scope, canary privileges, an isolated
worker, a disposable host, and ownership-aware cleanup evidence. This package
provides none of those execution capabilities. Host installation and live integration
remain unverified.
