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
| Scheduled-task permissions | At most 512 files under the fixed Windows task directory; checks ACL allow rules for write, modify, or full control by Everyone, Authenticated Users, or Users SIDs. |
| Token privileges | Fixed `%SystemRoot%\System32\whoami.exe /priv /fo csv /nh`; records enabled privilege names and whether the list completed. |
| Registry controls | Reads the two fixed AlwaysInstallElevated policy values. |
| Filesystem controls | At most 128 unique PATH directories; checks ACL allow rules for broad-principal write, modify, or full control. |
| Local credential references | Tests for the `DefaultPassword` value name and two fixed unattend-file locations. It never reads registry or file values. |
| Versioned families | Relates the measured build and token privilege context to the opaque `token_impersonation_family`; it does not invoke a technique. |

The collector creates one harmless marker beneath a caller-supplied, empty,
local, non-reparse canary root and removes the assessment-owned directory in a
`finally` block. It emits a SHA-256-bound receipt containing before, creation,
removal, and cleanup evidence IDs. `scripts/validate-windows-bridge.py`
independently checks the receipt, rehashes the export, revalidates the assessment,
and requires that the canary root is empty. This lifecycle canary validates
assessment-owned cleanup only; it is not a privilege-crossing canary.

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

The repository-contract Windows job runs the native collector on a disposable
`windows-latest` runner, assesses its export, validates the SHA-bound lifecycle
receipt, and independently requires an empty canary root. That job establishes
native execution and assessment-owned cleanup only at the commit SHA it runs.
Every surface remains governed by its emitted coverage; a Windows job can pass
while an individual probe truthfully reports `access_denied` or `not_assessed`.
Live integration remains unverified until that exact-SHA hosted job succeeds.

## Source mapping

| Evidence surface | Pinned reference | Scenario |
| --- | --- | --- |
| AlwaysInstallElevated registry policy | `s01-120` `win-privesc/always-install-elevated.md` | `COPS-E06.02-S01` supporting registry evidence |
| Unquoted service paths | `s01-121` `win-privesc/unquoted-service-path.md` | `COPS-E06.02-S01` exact scenario source |
| Service permissions | `s01-122` `win-privesc/service-permissions.md` | `COPS-E06.02-S01` supporting service evidence |
| Registry run keys | `s01-123` `win-privesc/registry-run-keys.md` | `COPS-E06.02-S01` supporting registry evidence |
| Token/version family context | `s01-124` `win-privesc/juicypotato.md`; `s01-125` `win-privesc/godpotato.md` | `COPS-E06.02-S01` supporting versioned-family evidence |
| Credential Manager reference | `s01-126` `win-privesc/credman-dump.md` | `COPS-E06.03-S01` supporting local-credential evidence |
| Autologon reference | `s01-127` `win-privesc/autologon-creds.md` | `COPS-E06.03-S01` supporting registry/local-credential evidence |
| Unattended-install reference | `s01-128` `win-privesc/unattended-install.md` | `COPS-E06.03-S01` exact scenario source |
| DLL search/path context | `s01-129` `win-privesc/dll-hijacking.md` | `COPS-E06.02-S01` supporting filesystem evidence |
| Windows build and token context | `s02-016` `wmic-queries.txt` | `COPS-E06.02-S01` platform-gating context |

No collected observation claims the referenced technique succeeded. The source
mapping explains the assessment premise and keeps the evidence claim at the
configuration and prerequisite level.
