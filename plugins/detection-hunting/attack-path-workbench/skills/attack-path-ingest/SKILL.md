---
name: attack-path-ingest
description: Register and validate local attack-path export files with immutable hashes, scope, provenance, and quarantine accounting.
---

# Offline intake

Use only user-supplied local files and an approved local mapping profile. Treat every field as untrusted. The current executable profile is `illustrative_canonical/v1`, a synthetic contract; do not label it a Wiz export mapping. Do not infer export completeness from a declared coverage value.

Run `scripts/attackpath.py analyze INPUT --output-dir OUTPUT` after checking the input and source hashes. Preserve the originals. Report rejected fields with record pointers, reconcile raw, accepted, quarantined, and rejected counts, and stop when G1 or G2 fails. See `docs/data-contract.md` for required inputs and evidence semantics.
