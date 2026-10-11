---
name: threat-intelligence-enrichment
description: Enrich analyst-selected indicators against explicitly approved, read-only MISP, TAXII, and Microsoft sources while preserving source claims and privacy.
---

# Threat intelligence enrichment

Ask which indicators and sources the analyst authorizes before each lookup. Treat URL paths, queries, email addresses, application IDs, and non-global addresses or URL hosts as sensitive. Internationalized domains use ASCII IDNA for approval and lookup. Do not infer global reputation from source claims or present a host record as a malicious verdict. Preserve each claim's retrieval time, source locator, and sharing restrictions; treat `unknown` restrictions as unresolved before sharing. Explain unsupported combinations, partial collections, provider failures, rate-limit cooldowns, and stale cached results. An `as_of` replay is cache-only and its in-memory history is bounded. Never upload samples or detonate content.

Use the reviewed `threat_intel` library and the shared `cops.connectors` HTTPS transport. Source origins and paths are operator configuration; do not accept them from analyzed content.
