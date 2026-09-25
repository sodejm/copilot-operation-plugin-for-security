# Data contract

All decision-bearing JSON objects reject unknown fields. The untrusted export envelope can contain undocumented rows; these are counted and quarantined, never converted into graph facts. Runtime validators are authoritative for the illustrative profile; the JSON schemas in `schemas/` document the versioned interchange contract.

| Record | Input | Output | Failure or uncertainty |
|---|---|---|---|
| `attackpath.input/v1` | Source file path and SHA-256, UTC export time, scope, coverage declaration, synthetic profile ID, crown-jewel refs, optional priority and service | Validated manifest and source coverage | Hash, scope, identifier, timestamp, unknown decision field, or unsupported profile blocks intake; declared completeness is never independently confirmed. |
| `illustrative_canonical/v1` | Local JSON `records` envelope | Accepted node, finding, and edge rows | Unknown, malformed, out-of-scope, or out-of-window row is quarantined with a JSON pointer. This is **not** a Wiz field mapping. |
| `attackpath.evidence/v1` | Accepted row plus source hash and pointer | Stable evidence ID, typed claim, observation time, scope, transform, support label | Missing provenance prevents use as a graph fact. An observed label means the source asserted it, not independent confirmation. |
| `attackpath.graph/v1` | Normalized evidence and crown-jewel refs | Typed nodes, findings, and directed edges with evidence refs | Missing or mistyped endpoints and unsupported joins are excluded and explained. |
| `attackpath.path/v1` | Graph, starting findings, crown jewels, preconditions | Ordered steps, supported or candidate class, gaps, confidence basis, dedup key | Missing capability or hypothetical relation stays candidate. Depth-limited or dead-end routes become partial records. |
| `attackpath.impact/v1` | Path steps, supported segment, observed direct service dependencies, supplied business profile | Distinct evidenced assets and directly dependent services, potential CIA, and rating | Rating remains `unrated` until an approved profile and business context exist. Unknown coverage is not extrapolated; a dependency alone does not establish a service consequence. |
| `attackpath.query_intent/v1` | Start, target, scope | Structured requested relationships and fields | `blocked_pending_docs`; no valid Wiz syntax is claimed. |
| `attackpath.report/v1` | Validated outputs and gate results | Canonical JSON and readable projection | Unsupported material claims block publication; unresolved interpretations remain visible. |
| `attackpath.ledger/v1` | Proposed path actions and later user updates | Local remediation proposals and validation criteria | Owner and closure evidence remain null until supplied; a later export alone does not close an action. |

Source paths are relative to the input manifest and cannot resolve outside its directory. IDs are stable hashes of canonical records and source pointers. The report stores input, source, profile, rule, and reference versions; current reference and prompt version lists are empty because neither is invoked by the offline CLI.

The current confidence labels assess **support for a claim**: `high` for non-conflicting direct source support, `medium` for fully traceable deterministic derivation, `low` for explicit hypothesis, and `undetermined` for missing or conflicting required evidence. A path takes the weakest required-step label, capped at `medium` because a path is derived. None of these labels is an exploit probability. Source conflict detection beyond duplicate identifiers is a future mapping requirement; contradictory source assertions must be withheld from a supported conclusion when a real mapping profile is installed.
