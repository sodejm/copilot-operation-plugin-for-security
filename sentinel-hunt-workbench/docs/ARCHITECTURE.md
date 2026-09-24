# Architecture

Sentinel Hunt Workbench is an offline, deterministic content system. The
canonical hunts, surface profiles, schemas, fixtures, and skills are the source
of truth. Host adapters are generated views, and release evidence is bound to a
hash of every non-release package artifact.

## Security boundary

The package accepts local JSON files and command-line parameters and emits local
JSON, Markdown, and KQL. It has no cloud client, credential path, browser,
background service, hook, or network dependency. It never executes KQL against
Microsoft services. Telemetry strings, URLs, command lines, comments, and pasted
documents are untrusted data and cannot issue instructions to the validator.

The offline boundary is deliberate: deterministic tooling can establish content
shape, declared schema compatibility, parameter safety, fixture expectations,
correlation invariants, mutation resistance, and adapter integrity. It cannot
establish service behavior, tenant schema availability, query cost, latency,
precision, recall, false-positive rate, or operational effectiveness.

## Components

1. `hunts/` contains exactly twelve versioned hunt definitions. Each hunt names
   one surface per query variant and records hypothesis, telemetry, entities,
   stages, joins, evidence, confounders, stopping rules, ATT&CK rationale, and
   source provenance.
2. `profiles/` contains dated schemas and restrictions for Sentinel Analytics,
   Sentinel data lake, and Defender Advanced Hunting. The validator never infers
   compatibility from KQL syntax alone.
3. `fixtures/curated/` contains 48 synthetic oracle cases per hunt. The
   reference evaluator also creates 250 seeded perturbations and 12 semantic
   mutations per hunt.
4. `schemas/` documents the machine contracts. The standard-library validator
   remains authoritative when an optional JSON Schema implementation is absent.
5. `huntwb/` implements strict JSON parsing, typed KQL serialization, contract
   checks, reference-invariant evaluation, rendering, adapter generation, and
   fail-closed release evidence.
6. `skills/` contains the six canonical Agent Skills. `adapters/` is generated
   from those canonical inputs and checked byte-for-byte for drift.
7. `release/evidence/` contains content-addressed local integrity evidence plus
   explicit pointers for external model evaluation, human approval, and license
   review. Missing evidence remains pending.

## Data flow and trust transitions

```text
authorized intent + environment facts
                |
                v
        canonical skill workflow
                |
                v
hunt/profile + typed parameter file --reject--> raw KQL fragments
                |
                v
 renderer -> surface-specific KQL bundle
                |
                v
 contract validator -> curated/generated/mutation evaluator
                |
                v
 evidence report -> mandatory human tenant transfer and validation
```

The typed parameter boundary validates type, length, range, and list bounds
before serialization. The renderer substitutes only declared placeholders. The
validator fails on missing scope, unknown schema elements, unsafe join semantics,
or silent stage loss. The reference evaluator checks synthetic invariants rather
than parsing or emulating KQL.

## Qualification semantics

Local gates cover contracts, static policy, reference evaluation, adapter drift,
and release integrity. Model-host runs, independent human approvals, and license
review use separate content-addressed evidence contracts. A release can be
`offline_qualified` only when every required gate is bound to the same release
subject. In their absence, the status is `qualification_withheld`; unavailable
tools never count as a pass.

The following claims are outside the architecture and prohibited without a
separately governed live-validation capability: tenant validated, Sentinel
validated, production ready, production proven, or effective detection.

## Change control

A material change to a hypothesis, join, time window, surface profile, evidence
interpretation, fixture oracle, validator, adapter generator, or skill requires a
new content hash and complete requalification. Generated adapters must never be
edited directly. Release outputs are excluded from the release-subject hash to
avoid a self-referential digest, but every evidence pointer and payload is hashed.

