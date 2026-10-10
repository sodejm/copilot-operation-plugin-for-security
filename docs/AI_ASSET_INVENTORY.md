# AI asset inventory

The AI inventory is a local, import-only evidence projection in `cops.evidence.ai_inventory`. It does not connect to providers, discover assets, execute tools, retain raw traces, or make exploitability claims.

## Supported input and adapter

The versioned `cops.ai-inventory/v1` generic JSON contract supports agents and observed agent runs, untrusted documents, model endpoints, MCP servers and tools, retrieval/memory/cache stores, service identities and destinations. Assets declare a bounded trust level (`untrusted`, `trusted`, `privileged` or `unknown`) plus selected `permissions` and `scopes` when the source makes those facts available. It represents authentication, delegation, reads, writes, tool invocation, outbound transfer and parent-child lineage as observed or declared. Every record supplies selected-record provenance and completeness. Provider and tenant identifiers cannot contain `/`, keeping the provider/tenant namespace unambiguous.

`adapt_entra_service_principals` maps a previously collected Microsoft Graph service-principal export containing only `id`, `appId` and optional `displayName`. It never calls Graph. A generic source can reconcile an agent to that Entra service principal with an `identity_links` record: `asset`, a stable Entra `identity`, a matching `reason` (`sponsor`, `alias`, `merge` or `split`) and provenance. This preserves both source records, preserves unresolved records as unknowns, and avoids identity conflation.

### Offline LangSmith v2 query-runs adapter

`adapt_langsmith_query_runs` accepts one fixed wrapper version, `cops.langsmith-query-runs/v2`, around a selected-field response from LangSmith `POST /api/v2/runs/query`, documented in the [official LangSmith API reference](https://eu.api.smith.langchain.com/redoc). The request's `selects` list must contain exactly these provider enum values:

```text
ID,NAME,RUN_TYPE,START_TIME,PARENT_RUN_IDS,TRACE_ID,PROJECT_ID
```

The provider response uses the lowercase keys `id`, `name`, `run_type`, `start_time`, `parent_run_ids`, `trace_id` and `project_id` within `items`, plus `next_cursor` at the response root. `parent_run_ids` is ordered from the trace root to the direct parent. The COPS wrapper adds `schema_version`, `source.tenant`, `source.collection_id`, `source.exported_at` and an opaque restricted `source.reference`. It is a selected-field projection wrapper, not a literal raw LangSmith export; only the nested `response.items` and `response.next_cursor` shape comes from the provider response. The JSON Schema is `cops/evidence/schemas/langsmith-query-runs-v2.schema.json`. Other wrapper, response or run keys are rejected. This excludes inputs, outputs, events, errors, metadata, manifests, attachments, share URLs and other trace content. User-defined run names are validated as part of the pinned provider shape and discarded during normalization because they can contain private data. The pagination cursor is likewise never retained.

The mapping is deterministic:

| LangSmith run type | Inventory asset kind | Relationship to the last present `parent_run_ids` entry |
| --- | --- | --- |
| `CHAIN` | `agent_run` with `chain_run` identity | observed `parent_child` |
| `LLM`, `EMBEDDING` | `agent_run` with `llm_run` or `embedding_run` identity | observed `parent_child` and `delegation` |
| `RETRIEVER` | `agent_run` with `retriever_run` identity | observed `parent_child` |
| `TOOL` | `agent_run` with `tool_run` identity | observed `parent_child` and `tool_invocation` |

All imported records remain generic, restricted `agent_run` assets with unknown trust. The semantic edge describes the selected child operation in relation to its present parent run. It does not establish a model endpoint, retrieval store, MCP resource, provider identity, privilege, authorization or target resource. A missing parent produces an unknown fact and no invented node or edge. A non-null `next_cursor` marks all imported provenance partial and adds a pagination unknown. Equal duplicate runs collapse, while conflicting duplicates, parent cycles and present parent links across traces or projects reject the whole import. Source and tenant qualify every run ID, so equal provider IDs in different tenants remain separate.

Use `import_langsmith_query_runs(document, registry=...)` to retain the normalized snapshot. Use `export_langsmith_inventory(...)` only with an injected privacy boundary implementing `ExportBoundary.export` and a caller-provided sink. Boundary refusal propagates without writing through a fallback path. This is an offline adapter: it does not fetch pages, verify source authenticity, establish owner or permission facts, determine a tool's effect, prove authorization, or make trust or exploitability claims. The fixed field selection covers only the relationships represented by those fields; unsupported run types and provider response changes require a new schema version.

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
| LangSmith response import | One offline, selected-field LangSmith v2 query-runs response maps observed run lineage into the generic registry; missing pages and parents stay unknown. |
| Privacy boundary | No raw trace, prompt, input/output, argument or credential field is accepted, and LangSmith report export requires the injected boundary and caller sink. |

Generic imports are bounded to 512 KiB, 1,000 assets, 5,000 relationships, 1,000 identity links and 1,000 unknowns. The LangSmith wrapper is additionally capped at 512 KiB, 240 runs and 32 parent IDs per run. Path reporting caps output at 100 paths, depth at 8 relationships and graph work at 10,000 expansions. `path_coverage` reports these limits for each path family and sets `limit_reached` when a result reaches a path or expansion cap; treat that result as incomplete coverage. Convert retained documents to the current schema before import; unsupported versions are rejected with no partial state. The registry is in memory only. Persist only normalized projections and restricted references under the engagement's retention policy.

Provider exports and trace metadata are untrusted. The contract rejects unrecognized record keys and has no fields for prompts, inputs/outputs, raw trace payloads, tool arguments or credentials. Restricted snapshot references stay scoped to one engagement. Inventory connectivity is not evidence of authorization, compromise, or exploitability.
