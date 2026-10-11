# Linux privilege-boundary assessment (E06.01)

## Scope and capability state

`host-assessment-workbench` imports a versioned, local JSON export. It does not
inspect a host, invoke a shell, read credentials, or cross a privilege boundary.
Imported canary results are **reported** outcomes; synthetic fixtures are labeled
as such. A live adapter and disposable-host execution evidence are separate gates.

The workflow covers permissions, services, scheduled tasks, Linux capabilities,
sudo, SUID, credential exposure, and container context. Every import states
coverage for each surface. `not_assessed`, `unsupported`, and `access_denied`
never mean a surface is secure.

## Import contract v1

The top-level object has exactly `schema_version`, `source_kind`, `source_id`,
`host`, `coverage`, and `observations`. `source_kind` is `synthetic_lab` or
`operator_export`. `source_id` and all observation and evidence IDs are opaque
identifiers, not paths or raw evidence. Unknown keys, duplicate keys, malformed
JSON, oversized files, and unsupported versions fail closed.

`host` records a kernel release, distribution ID and version, namespace
(`host`, `container`, or `unknown`), and five protection states: SELinux,
AppArmor, no-new-privileges, seccomp, and user namespaces. Unknown is explicit.
No observation is selected without this context.

Each observation names one surface, a configuration state (`interesting`,
`ordinary`, or `unknown`), evidence IDs, and exact prerequisites for kernel
release, distribution ID and version, namespace, and relevant protections. The
importer selects a check only when all supplied prerequisites match known
host context. A known mismatch is `inapplicable`; missing or unknown context
is `unresolved`.

An optional canary report has a `positive`, `negative`, or `fixed` case; a
disposable-host assertion; an assessment-owned canary resource ID; explicit
before/after access observations; evidence IDs; and a cleanup verification
assertion. The `positive` case requires denied before and granted after, while
`negative` and `fixed` require denied before and after. Incomplete or
contradictory reports fail closed. The output uses `reported_canary_crossing`
for a valid positive report and `reported_canary_blocked` for negative/fixed
reports. Neither is independently verified by the importer.

Configuration-only observations are `configuration_candidate` or
`ordinary_configuration`; unknown configuration is `insufficient_evidence`.
Unselected observations cannot become successful assessments.

## Observable behavior

- A deterministic report includes source label, host prerequisite context,
  per-surface coverage, each observation's selection decision and classification,
  and aggregate counts.
- The schema rejects raw credential fields, arbitrary input text, file
  contents, and evidence paths. The report emits IDs, which operators must
  ensure are non-sensitive and opaque.
- A positive synthetic fixture, negative synthetic fixture, and fixed synthetic
  fixture exercise the classification and cleanup contract. They do not prove
  executable capability or live host behavior.
- The importer performs no process execution, network access, or host changes.
  Live privilege testing requires a separately approved action plan, runtime
  authorization, isolated worker, disposable host, canary privilege, and
  ownership-aware cleanup receipt.

## Compatibility and traceability

The contract rejects unknown schema versions rather than interpreting them as
v1. Existing package, evidence, and specialist IDs are unchanged. E06.01-S01
and E06.01-S02 are planning references only; E01.1 must map exact pinned
file/section IDs before any specific technique is attributed to those sources.
