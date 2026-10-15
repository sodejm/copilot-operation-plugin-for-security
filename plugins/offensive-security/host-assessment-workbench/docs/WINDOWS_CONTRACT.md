# Windows privilege-boundary assessment (E06.02)

## Capability and limits

The host-assessment-workbench accepts bounded `windows-1.0` JSON through two
explicit bridge modes. `offline_windows_export` classifies a synthetic or
operator-provided export. `native_windows_bridge` is produced on Windows by
`scripts/collect-windows.ps1`, which performs seven bounded, read-only probes and
records host build, architecture, token, and protection context. Neither mode
attempts privilege escalation, crosses a privilege boundary, reads a credential
value, changes a service or task, or proves that a configuration is exploitable.

The seven surfaces are `service_permissions`, `scheduled_task_permissions`,
`token_privileges`, `registry_controls`, `filesystem_controls`,
`local_credential_references`, and `versioned_escalation_families`. Each has
coverage `assessed`, `not_assessed`, `unsupported`, or `access_denied`. The last
three never imply safety. A failed, excessive, or unavailable native probe is
reported as `access_denied` or `not_assessed`; it is never converted to an
ordinary configuration.

| Native surface | Bounded observation |
| --- | --- |
| Service permissions | At most 1,024 `Win32_Service` records; identifies an unquoted executable path containing spaces. It does not test service control or file write access. |
| Scheduled-task permissions | At most 512 files under the fixed Windows task directory; checks ACL allow rules for explicit data/attribute writes, child deletion, deletion, permission changes, or ownership changes by Everyone, Authenticated Users, or Users SIDs. Read-only rules do not match. |
| Token privileges | Fixed `%SystemRoot%\System32\whoami.exe /priv /fo csv /nh`; records enabled privilege names and whether the list completed. |
| Registry controls | Reads the two fixed AlwaysInstallElevated policy values. |
| Filesystem controls | At most 128 unique PATH directories; checks ACL allow rules for the same explicit mutation rights by broad principals. Read-only rules do not match. |
| Local credential references | Tests for the `DefaultPassword` value name and two fixed unattend-file locations. It never reads registry or file values. |
| Versioned families | Relates the measured build and token privilege context to the opaque `token_impersonation_family`; it does not invoke a technique. |

The collector creates one harmless marker beneath a caller-supplied, empty,
local, non-reparse canary root. Before deletion it confirms that the canonical
root and child identities are unchanged, both remain ordinary local filesystem
objects, and the marker content matches its assessment-owned SHA-256. An identity
or ownership mismatch fails closed without deletion. A separate process running
under the same Windows token observes the resource absent before creation,
readable with the exact owned marker after creation, and absent after deletion.
It emits a SHA-256-bound receipt containing the canonical root and child
identities, ownership digest, observer kind, and those three lifecycle states.
`scripts/validate-windows-bridge.py` independently checks the receipt, rehashes
the export, revalidates the assessment, binds the receipt identities to the exact
supplied root, and requires that root to be empty. This lifecycle canary validates
assessment-owned cleanup and same-token process visibility only; it is not a
cross-identity or privilege-crossing canary.

## Import contract

The top-level object has exactly `schema_version`, `source_kind`, `source_id`,
`bridge`, `host`, `coverage`, and `observations`. `schema_version` is
`windows-1.0`; source kind is `synthetic_lab` or `operator_export`. `bridge` has
exactly `mode`, `platform: windows`, a bounded unique `capabilities` list, and
Boolean `canary_assertions`. Mode is `offline_windows_export` or
`native_windows_bridge`. Native mode requires `operator_export` and forbids
privilege-crossing canary assertions. An assessed surface must be declared as a
capability.

`host` has exactly `os_build`, `architecture`, `token`, and `protections`. The
build is a numeric dotted version with two to four components, or `unknown`.
Architecture is `x86`, `x64`, `arm64`, or `unknown`. `token` contains integrity
(`low`, `medium`, `high`, `system`, or `unknown`), elevation (Boolean or
`unknown`), unique opaque privilege IDs, and a Boolean `privileges_complete`.
Protection states for `uac`, `wdac`, `credential_guard`, `vbs`, and `applocker`
are `enabled`, `disabled`, or `unknown`.

An observation has exactly `id`, `surface`, `configuration`, `evidence_ids`, and
`requirements`, with optional `canary`. Only a `versioned_escalation_families`
observation also has a required opaque `family_id`. No unstructured technique
narrative, paths, or raw secret values are accepted. Requirements contain
inclusive `build_min` and `build_max`, an architecture, token requirements, and
a subset of required protection states. A known mismatch is `inapplicable`;
unknown context or an incomplete privilege list is `unresolved`. Selection
requires every prerequisite to match. Version comparison is numeric.

Offline canaries use the Linux v1 safety contract: positive, negative, or fixed
case; disposable host; assessment ownership; denied-before access; case-consistent
after access; at least three opaque evidence IDs; and source-asserted cleanup.
The importer reports `reported_canary_crossing` or `reported_canary_blocked` and
`cleanup_reported`; it does not claim independent restoration. Native exports do
not contain these canaries. Selected configuration-only observations are
candidates, ordinary configuration, or insufficient evidence.

The importer rejects unknown fields, duplicate keys or IDs, unsupported versions,
nonfinite values, malformed UTF-8 JSON, input over 1 MiB, more than 256
observations, excessive nesting, and contradictory canaries. Identifiers are
opaque, bounded, and non-sensitive. Output is deterministic and reports
`offline_import` or `native_bridge_import`.

## Acceptance evidence and live gate

Synthetic vulnerable, protected, remediated, and unsupported fixtures exercise
classification, context matching, coverage, and source-asserted cleanup. Unit and
BDD tests also reject credential-bearing fields, capability contradictions,
malformed input, false canary outcomes, and invalid native cleanup receipts.
These tests establish deterministic classification; they do not prove live
Windows collection.

The repository-contract Windows job runs `scripts/exercise-windows-bridge.ps1`
on a disposable `windows-latest` runner. That shared practitioner entry point
exercises the explicit ACL mutation predicate with read-only and writable rights,
runs the native collector and importer, validates the SHA- and identity-bound
lifecycle receipt, and runs the separate same-token observer before creation,
after creation, and after deletion. The after-creation observer independently
reads and hashes the owned marker; the final observer and receipt validator each
require an empty canary root. That job establishes native execution and
assessment-owned cleanup only at the commit SHA it runs.
Every surface remains governed by its emitted coverage; a Windows job can pass
while an individual probe truthfully reports `access_denied` or `not_assessed`.
Live integration remains unverified until that exact-SHA hosted job succeeds.

## Source mapping

| Evidence surface | Pinned reference | Native E01.1 mapping |
| --- | --- | --- |
| AlwaysInstallElevated registry policy | `s01-120` `win-privesc/always-install-elevated.md` | Direct: `always_install_elevated` |
| Unquoted service paths | `s01-121` `win-privesc/unquoted-service-path.md` | Direct: `unquoted_service_path` |
| Service permissions | `s01-122` `win-privesc/service-permissions.md` | Excluded: service ACL permissions are not collected |
| Registry run keys | `s01-123` `win-privesc/registry-run-keys.md` | Excluded: Run-key ACLs are not collected |
| Token/version family context | `s01-124` `win-privesc/juicypotato.md`; `s01-125` `win-privesc/godpotato.md` | Supporting: `token_privileges` |
| Credential Manager reference | `s01-126` `win-privesc/credman-dump.md` | Excluded: Credential Manager is not accessed |
| Autologon reference | `s01-127` `win-privesc/autologon-creds.md` | Direct: `autologon_default_password_presence` |
| Unattended-install reference | `s01-128` `win-privesc/unattended-install.md` | Direct: `unattend_file_presence` |
| DLL search/path context | `s01-129` `win-privesc/dll-hijacking.md` | Supporting: `path_directory_acl` |
| Windows build and token context | `s02-016` `wmic-queries.txt` | Supporting: `windows_build_token_context` |
| Scheduled-task ACL inventory | None | Unmapped: no pinned E01.1 source covers the bounded task-file ACL inventory |

The executable mapping is
`plugins/offensive-security/host-assessment-workbench/docs/windows-native-source-map.json`.
Its test binds every mapped source to `catalog/provenance.json`, requires every
collector probe to have one `E01.1` anchor, and records unmapped probes and
excluded source families. The repository-contract Windows job invokes
`scripts/exercise-windows-bridge.ps1`, which reaches the mapped collector and the
import and receipt validators.

No collected observation claims the referenced technique succeeded. The source
mapping explains the assessment premise and keeps the evidence claim at the
configuration and prerequisite level.
