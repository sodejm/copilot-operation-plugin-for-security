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
| R-MODEL | Model catalog parser and advisor (`cops/routing/model_advisor.py`), both route CLIs, model-routing skills, issue preflight policy and associated tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-LAB | `cops/laboratory/**`, laboratory CLI and schemas, scenario-laboratory skill, and focused tests for durable evidence, atomic authorization replay, post-dispatch recovery, and cleanup/result binding | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-PLAYBACK | Catalog demo declarations, `cops/portable.py`, package playback entry points and documentation, declared-input staging, sanitized dispatch evidence, Git configuration isolation, temporary artifact cleanup, retry-count assertions, Attack Path Windows handle-based I/O, and source/export semantic acceptance tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-VENDOR | SOC investigation workbench Sentinel snapshot, `vendor-lock.json`, synchronization and validation boundary, and focused tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-REST | All remaining tracked first-party files; enumerate and reconcile against Git inventory | Pending independent human review | Maintainer assignment pending | First pass within 90 days |

For each reviewed row add exact paths, reviewed SHA, reviewer identity/date,
checks/evidence, findings, disposition, residual risk acceptance/expiry and next
review trigger. Record third-party provenance and review separately. Changed
behavior invalidates prior scope approval. Follow the
[engineering review policy](../ENGINEERING_REVIEW.md). No automated result or
threat-model entry closes this human-review backlog.
