# AI asset inventory

The AI inventory is a local, import-only evidence projection in `cops.evidence.ai_inventory`. It does not connect to providers, discover assets, execute tools, retain raw traces, or make exploitability claims.

## Supported input and adapter

The versioned `cops.ai-inventory/v1` generic JSON contract supports agents and observed agent runs, untrusted documents, model endpoints, MCP servers and tools, retrieval/memory/cache stores, service identities and destinations. Assets declare a bounded trust level (`untrusted`, `trusted`, `privileged` or `unknown`) plus selected `permissions` and `scopes` when the source makes those facts available. It represents authentication, delegation, reads, writes, tool invocation, outbound transfer and parent-child lineage as observed or declared. Every record supplies selected-record provenance and completeness. Provider and tenant identifiers cannot contain `/`, keeping the provider/tenant namespace unambiguous.

`adapt_entra_service_principals` maps a previously collected Microsoft Graph service-principal export containing only `id`, `appId` and optional `displayName`. It never calls Graph. A generic source can reconcile an agent to that Entra service principal with an `identity_links` record: `asset`, a stable Entra `identity`, a matching `reason` (`sponsor`, `alias`, `merge` or `split`) and provenance. This preserves both source records, preserves unresolved records as unknowns, and avoids identity conflation.

## Operation and security

Use `import_inventory(document, engagement_id=...)`, retain snapshots in an `InventoryRegistry`, compare snapshots with `compare_inventories`, and summarize them with `inventory_report`. Comparisons emit explicit `permission_changes` and `scope_changes`, separate from generic graph changes. Reports include selected authentication, delegation, tool-invocation and outbound-transfer trust boundaries plus bounded, cycle-free paths from an agent or run to a destination. `privileged_document_paths` requires the ordered sequence untrusted document, agent or run, privileged MCP tool, then destination. Each path keeps observed/declared support and completeness. Reports and comparisons rebuild and validate public snapshot mappings before use. Registry reads and reports require the same engagement identifier and may require the exact source namespace. Missing, stale, opaque, inaccessible or conflicting records stay explicit unknowns; absence does not prove removal.

## Capability matrix

| Capability | Current evidence and bound |
| --- | --- |
| Versioned import | `cops.ai-inventory/v1` JSON Schema and representative import fixture validate the bounded projection. |
| Graph and uncertainty | Source/tenant-qualified assets, observed or declared edges, per-record provenance, completeness and explicit unknowns. |
| Access comparison | Explicit asset `permissions` and `scopes`; deterministic comparison returns each changed value. |
| Identity lineage | Provenance-backed Entra sponsor, alias, merge and split links preserve source records. |
| Trust path report | Bounded report identifies only untrusted-document → agent/run → privileged-tool → destination paths. |
| Privacy boundary | No raw trace, prompt, input/output, argument or credential field is accepted. |

Imports are bounded to 512 KiB, 1,000 assets, 5,000 relationships, 1,000 identity links and 1,000 unknowns. Path reporting caps output paths, depth and graph expansions. Convert retained documents to the current schema before import; unsupported versions are rejected with no partial state. The registry is in memory only. Persist only normalized projections and restricted references under the engagement's retention policy.

Provider exports and trace metadata are untrusted. The contract rejects unrecognized record keys and has no fields for prompts, inputs/outputs, raw trace payloads, tool arguments or credentials. Restricted snapshot references stay scoped to one engagement. Inventory connectivity is not evidence of authorization, compromise, or exploitability.
