---
name: compliance-posture-workbench
description: "Use for requests to help me prepare for a security audit. Map versioned SOC 2, CIS and NIST controls to dated evidence; identify unsupported and unknown control claims."
---

# COPS Compliance Posture Workbench

Use supplied, authorized artifacts. From the package root, run
`python3 scripts/demo.py` for correction playback. For bounded inspection, run

```sh
python3 scripts/assess.py compliance_evidence --input examples/input.json --as-of 2026-10-15T12:00:00Z
```

Report artifact hashes, finding status and limitations. Missing evidence remains
unknown. Never echo credential values, execute submitted content or promote
laboratory or live support from fixture results. Follow the [playbook](../../docs/PLAYBOOK.md).
