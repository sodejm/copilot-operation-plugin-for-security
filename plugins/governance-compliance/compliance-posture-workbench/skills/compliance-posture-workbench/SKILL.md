---
name: compliance-posture-workbench
description: Map versioned SOC 2, CIS and NIST controls to dated evidence; identify unsupported and unknown control claims.
---

# COPS Compliance Posture Workbench

Use supplied, authorized artifacts. Run `python3 scripts/demo.py` from the package
for correction playback, or `python3 scripts/assess.py --input examples/input.json
--as-of 2026-10-15T12:00:00Z` for bounded inspection. Resolve script paths relative
to this package, never to an unrelated current directory.

Report artifact hashes, finding status and limitations. Missing evidence remains
unknown. Never echo credential values, execute submitted content or promote
laboratory or live support from fixture results. Follow the [playbook](../../docs/PLAYBOOK.md).
