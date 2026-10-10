# Existing-code human review coverage

Baseline commit: `42cb017012934839702ce0b939a5cbc9193271ea`. Status: initial inventory; no completed human
review is asserted. Scope includes all tracked first-party code, infrastructure,
CI, agent instructions and build/release tooling, including paths outside the
subsystem rows below. The maintainer must expand rows to exact file inventories;
these subsystem entries are prioritization, not proof of exhaustive review.

| ID | Scope | Status | Human owner | Deadline |
| --- | --- | --- | --- | --- |
| R1 | Plugin source → validators/generator → marketplace → installed agent and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R2 | Operator decision → approval store → tool execution and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R3 | Cloud integration → remote API / telemetry → agent and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R4 | Canonical hunt skills → generated host adapters and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-CI | All CI, dependencies, packaging, release, scripts and agent/tool authority | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-REST | All remaining tracked first-party files; enumerate and reconcile against Git inventory | Pending independent human review | Maintainer assignment pending | First pass within 90 days |

For each reviewed row add exact paths, reviewed SHA, reviewer identity/date,
checks/evidence, findings, disposition, residual risk acceptance/expiry and next
review trigger. Record third-party provenance and review separately. Changed
behavior invalidates prior scope approval. Follow the
[engineering review policy](../ENGINEERING_REVIEW.md). No automated result or
threat-model entry closes this human-review backlog.
