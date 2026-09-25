---
name: attack-path-map
description: Prepare evidence-cited ATT&CK behavior mapping, Attack Flow representation, and blocked Wiz graph query intents.
---

# Mapping and query intent

Map an action to a technique only when its described behavior matches an entry in an approved, pinned local ATT&CK bundle. A CVE or asset label alone is insufficient. Keep uncertain IDs as proposed reviews. Serialize Attack Flow actions and conditions only after a local versioned reference contract is approved.

For Wiz, use `scripts/attackpath.py query-intent --start ID --target ID --scope SCOPE`. Its `blocked_pending_docs` result is a request shape, not executable Wiz syntax. Do not render or execute API calls until approved operation, relationship, pagination, authentication, and field documentation is supplied. See `docs/integration-boundaries.md`.
