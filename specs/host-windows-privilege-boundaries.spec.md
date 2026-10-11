# Windows privilege-boundary assessment (E06.02)

## Capability and limits

The host-assessment-workbench imports a bounded, local `windows-1.0` JSON export. It does not run a Windows collector, execute commands, read credentials, change a host, or independently verify canary access or cleanup. The Linux `1.0` contract remains unchanged. This stage provides an explicit offline Windows adapter/bridge capability declaration for a Linux worker; live capability and disposable-host evidence remain separate acceptance gates.

The seven surfaces are `service_permissions`, `scheduled_task_permissions`, `token_privileges`, `registry_controls`, `filesystem_controls`, `local_credential_references`, and `versioned_escalation_families`. Each has coverage `assessed`, `not_assessed`, `unsupported`, or `access_denied`. The last three never imply safety.

## Import contract

The top-level object has exactly `schema_version`, `source_kind`, `source_id`, `bridge`, `host`, `coverage`, and `observations`. `schema_version` is `windows-1.0`; source kind is `synthetic_lab` or `operator_export`. `bridge` has exactly `mode: offline_windows_export`, `platform: windows`, a bounded, unique `capabilities` list of supported surface names, and Boolean `canary_assertions`. An assessed surface must be declared as a capability. The declaration reports exporter capability only; it does not grant host access or prove collection.

`host` has exactly `os_build`, `architecture`, `token`, and `protections`. The build is a numeric dotted version with two to four components, or `unknown`. Architecture is `x86`, `x64`, `arm64`, or `unknown`. `token` contains integrity (`low`, `medium`, `high`, `system`, or `unknown`), elevation (Boolean or `unknown`), unique opaque privilege IDs, and a Boolean `privileges_complete`. Protection states for `uac`, `wdac`, `credential_guard`, `vbs`, and `applocker` are `enabled`, `disabled`, or `unknown`.

An observation has exactly `id`, `surface`, `configuration`, `evidence_ids`, and `requirements`, with optional `canary`. Only a `versioned_escalation_families` observation also has a required opaque `family_id`. No unstructured technique narrative, paths, or raw secret values are accepted. Requirements contain inclusive `build_min` and `build_max`, an architecture, token requirements (`min_integrity`, Boolean `elevated`, and unique opaque privilege IDs), and a subset of required protection states. Minimum build must not exceed maximum. A known mismatch is `inapplicable`; unknown build, architecture, integrity, elevation, protection, or an incomplete privilege list with a missing required privilege is `unresolved`. Selection requires every prerequisite to match. Version comparison is numeric, not lexical.

A canary uses the Linux v1 safety contract: positive, negative, or fixed case; disposable host, assessment ownership, denied-before access, case-consistent after access, at least three opaque evidence IDs, and source-asserted cleanup. `canary_assertions` must be true. A selected positive case is `reported_canary_crossing`; a selected negative or fixed case is `reported_canary_blocked`. Importer output includes `cleanup_reported`, never a claim that restoration was independently verified. Unselected observations are `not_evaluated`; selected configuration-only observations are candidates, ordinary configuration, or insufficient evidence.

The importer rejects unknown fields, duplicate keys or IDs, unsupported versions, nonfinite values, malformed UTF-8 JSON, input over 1 MiB, more than 256 observations, excessive nesting, and contradictory canaries. Identifiers are opaque, bounded, and must be non-sensitive; do not put credentials, paths, or private host information in them. Output is deterministic and explicitly marked `offline_import`.

## Acceptance evidence and live gate

Synthetic vulnerable, protected, remediated, and unsupported fixtures exercise classification, context matching, coverage, and cleanup assertions. Tests also reject credential-bearing fields, capability contradictions, malformed input, and false canary outcomes. These fixtures do not prove a Windows host can be assessed. Live use requires an authorized scope, disposable Windows host, isolated worker and Windows-capable adapter, build/token/architecture/protection attestation, assessment-owned canary, before/after proof, and ownership-aware restoration receipt. E06.02-S01/S02 are planning references pending exact pinned section mapping under E01.1.
