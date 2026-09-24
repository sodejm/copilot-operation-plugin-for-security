# Specification: Sentinel Hunt Workbench

## 1. Goal and boundary

Sentinel Hunt Workbench is an offline-qualified, defensive threat-hunt authoring
plugin. It provides a canonical library of twelve multi-stream hunt definitions,
six portable Agent Skills, and a model-independent Python command line tool. The
tool may validate local content and synthetic data, but it never connects to a
Microsoft tenant or claims tenant, service, production, efficacy, cost, latency,
precision, recall, or false-positive validation.

The deterministic contracts, profiles, fixtures, and validator are authoritative.
Model-authored prose and KQL are proposals until those contracts accept them and a
qualified human reviews the result.

## 2. Required outcomes

The package MUST:

- contain exactly twelve release hunts (`H01` through `H12`), each with at least
  three logical streams, two correlation hops, two entity classes, a falsifiable
  hypothesis, disconfirming evidence, benign confounders, stopping rules, ATT&CK
  mapping rationale, references, and provenance;
- declare support independently for Sentinel Analytics, Sentinel data lake, and
  Defender Advanced Hunting, using only `supported`, `unsupported`, or
  `unverified`;
- render only typed, bounded parameters and reject raw KQL fragments;
- fail closed for unknown tables, fields, operators, profiles, parameters, or
  adapter drift;
- preserve UTC, tenant, workspace, entity, event-time, and evidence semantics;
- provide static, curated-fixture, generated-perturbation, semantic-mutation,
  metamorphic, hostile-content, and bounded scale checks;
- distinguish reference-evaluator evidence from Kusto-engine evidence and from
  unavailable live-service evidence;
- generate deterministic GitHub Copilot and standalone Codex adapters from the
  canonical skills and keep Claude Code and OpenAI plugin manifests explicit;
- produce machine-readable reports containing versions, hashes, seeds, gates,
  limitations, and unmet human or external-host requirements; and
- remain standard-library-only in its runtime and make no network requests.

## 3. Qualification language

The only content lifecycle states are `draft`, `schema_checked`,
`static_checked`, `fixture_executed`, `emulator_executed`, `human_reviewed`,
`offline_qualified`, `deprecated`, and `withdrawn`. `emulator_executed` is
optional additional evidence. It is never a substitute for a required state.

The following claims MUST be rejected in qualification state, report status, or
compatibility evidence: `target_verified`, `tenant_validated`,
`sentinel_validated`, `production_ready`, `production_proven`, and
`effective_detection` (including normalized space/hyphen variants).

`offline_qualified` requires all deterministic gates, recorded cross-platform
model-evaluation evidence, and two independent human approvals. The repository
may test the qualification mechanism without shipping a fabricated approval.

## 4. Security and privacy requirements

- All packaged telemetry is synthetic and uses reserved documentation domains,
  addresses, tenants, accounts, devices, and resource identifiers.
- Telemetry, URLs, command lines, file names, query comments, and documents are
  always untrusted data. Embedded instructions never expand permissions.
- Validation logs contain hashes, counts, error codes, versions, and timings, not
  raw event values or bound sensitive parameters.
- Parameter serializers validate type, length, count, encoding, and range, then
  produce KQL literals without free-form interpolation.
- Skills refuse requests whose primary purpose is unauthorized access,
  credential theft, malware, destructive activity, defense evasion, or log
  clearing. They may retain the minimum behavioral detail needed for authorized
  defensive observability and test design.
- Normal operation has no cloud credentials, MCP server, host hook, background
  service, persistent database, or dependency download.

## 5. Test corpus and gates

Each hunt has 48 curated scenarios: eight positive variants, ten benign
counterfactuals, eight entity/correlation cases, eight temporal/data-quality
cases, four schema/surface cases, four scale/resource cases, three hostile/privacy
cases, and three mutation/metamorphic cases. Each release also runs 250 seeded
perturbations per hunt and twelve semantic mutations per hunt.

Release-blocking gates are:

1. 100% schema and contract checks.
2. 100% security and authorization checks.
3. 100% critical semantic mutations caught.
4. 100% curated expected-result checks.
5. 100% manifest and generated-adapter drift checks.
6. 100% generated invariants.
7. At least 95% overall mutation score.
8. The separately recorded cross-platform model thresholds.
9. Two qualified human approvals.

No aggregate score may compensate for gates 1 through 5. A missing optional
parser or execution engine is recorded as `not_available`, never as a pass.

## 6. Command contract

The command line exposes `list`, `explain`, `render`, `validate`, `test`,
`compatibility`, `build-adapters`, `verify-adapters`, and `release-report`.
Exit codes are `0` for success, `2` for content/contract failure, `3` for surface
incompatibility, `4` for fixture/mutation/adversarial failure, `5` for an
unavailable required tool or evidence source, and `6` for an internal validator
error.

## 7. Acceptance criteria

- `python3 sentinel-hunt-workbench/scripts/huntwb.py validate library` passes.
- `python3 sentinel-hunt-workbench/scripts/huntwb.py test library` executes 576
  curated and at least 3,000 seeded generated cases and catches every critical
  semantic mutation with an overall score of at least 95%.
- `python3 sentinel-hunt-workbench/scripts/huntwb.py verify-adapters` proves that
  all generated adapters match canonical hashes.
- Unsafe parameter payloads, unknown schema fields, unsupported surface requests,
  missing scope markers, and prohibited assurance claims fail closed.
- A release report remains non-qualified until external-host evaluation evidence
  and two human approvals exist.
- `make check` covers the package validator, unit tests, executable scenarios,
  adapter drift, and repository contracts.

