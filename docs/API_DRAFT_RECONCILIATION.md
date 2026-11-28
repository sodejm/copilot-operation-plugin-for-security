# API draft reconciliation and acceptance repair

## Scope

This local completion unit addresses the preserved E05.01 draft and a reproduced
authorization-assessment regression. It does **not** close issue
[#100](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/100),
implement live WebSocket replay, qualify isolation or change production providers.
The parent remains
[#66](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/66).

Fresh implementation base: `6848fd97a7620fae74566c0afb3d50ff35fb911d`.
The original draft remains on `codex/e05-01-web-api-inventory-request-replay` at
`d090c6ad51e65ae739b247a55733390c38a5d5bd`. New work is isolated on
`codex/api-completion-reconciliation`.

## Preserved draft disposition

A private archive outside Git contains all 22 modified/untracked files, the
binary tracked patch, source status and per-file modes and SHA-256 hashes.
The archive files were byte-verified and source files, status, patch and HEAD
were checked unchanged. No original file was removed or silently stashed.
All paths already exist in the implementation base: 4 byte-identical and 18
different. Path existence is not proof of semantic equivalence; the table below
records the reconciliation rather than authorizing deletion.

| Draft paths | Disposition |
| --- | --- |
| `.agents/skills/web-api-inventory-and-replay/{SKILL.md,tests/test_skill.py}` and matching `.claude` adapter files | Four different files. Use current contributor skill and generated adapter; retain draft as historical evidence. |
| `catalog/plugins.json`, `cops/cli.py` | Both different. Current main already registers the package and dispatches via expansion CLI integration. Do not add duplicate registrations or replace the newer catalog. |
| `cops/web_api/{__init__,cli,importer,models,replay}.py` | Five different files. Current runtime adds approved transport, input/provenance/session validation and report privacy. Do not transplant the older ungated live path. Repair current code with focused regressions instead. |
| Package `.claude-plugin/plugin.json`, `org.cops/prerequisites.json`, `package.json`, `plugin.json` | Four identical files; no change needed. |
| Package `.codex-plugin/plugin.json` | Different; retain current portable manifest, not the old duplicated host manifest. |
| Package `README.md`, `docs/PLAYBOOK.md`, `skills/web-api-inventory-and-replay/SKILL.md` | Three different files. Keep current limitations and verification guidance; do not restore unsupported live-protocol claims. |
| Package `scripts/{demo.py,validate-package.py}`, `tests/test_workbench.py` | Three different files. Keep current package-owned runtime and offline checks. Require the separate pytest local-service gate for authorized-assessment evidence. |

Here “Package” means `plugins/offensive-security/web-api-assessment-workbench`.
The archive manifest SHA-256 is
`ccdb626b9d9d46921817c5f252f69bc82112527955eea95aeaeb8d60b385e748`.
Archive paths and source contents are intentionally not committed.

## Reproduction and correction

Before implementation, the offline package check passed, but direct execution
of the seven authorized-assessment cases produced one failure: the corrected
GraphQL case became `insufficient_evidence`. `_report` sanitizes responses through
serialization before assessment; digest-only body redaction therefore removed
the GraphQL `data`/`errors` semantics the assessor needed.

`ReplayResponse` now derives an optional Boolean `graphql_object_access` before
body redaction. Exact digest markers can retain this observation across report
round trips. Raw payloads override conflicting metadata; invalid non-Boolean
metadata fails closed. Missing legacy digest-only observations remain unknown.
Object disclosure alongside an authorization error remains an access observation,
not a denial. No raw payload, object value or error message is restored to reports.

Repository `make check` now requires `scripts/check_web_api_acceptance.py`.
`make check-web-api-acceptance` exposes that same gate independently. It requires
the named real-service cases, refuses skipped/incomplete runs and propagates
subprocess failure, missing prerequisites and timeout. The portable package gate
stays offline and standard-library-only. Successful local-service output explicitly
states that isolation is **not** qualified.

## Validation and limits

Validation uses the declared contributor dependencies in Python 3.13.16:

- Focused API/OpenAPI, BDD and package suite: **590 passed**, no skips; one expected
  TLS 1.1 deprecation warning from a negative TLS-policy test.
- `make check-web-api-acceptance`: **7 required cases passed**; loopback-only,
  `isolation_qualified: false`.
- `make check`: **passed**, including all 25 package gates, repository tests,
  the new required acceptance gate, portable contracts and contributor skills.
  Platform-specific skips in the full suite are not native-platform evidence.
- `scripts/sync_web_api_runtime.py --check`, package check, adapter freshness,
  marketplace freshness and documentation gate: **passed**; 59 documentation
  pages verified by the documentation gate.
- Focused Ruff lint/format checks and `git diff --check`: **passed**.

No hosted CI, independent review, remote merge, release, production-provider
exercise or new isolated laboratory qualification is claimed here. See the
[implementation plan](superpowers/plans/2026-10-25-api-completion.md) for remaining
work and the package [verification guide](../plugins/offensive-security/web-api-assessment-workbench/docs/VERIFICATION.md)
for acceptance boundaries.

## Cleanup and resumption

The abandoned OpenCode installation worktree was clean at the exact base, with
zero commits ahead of main and no tree differences. It and its task branch were
removed through ordinary non-force Git commands. No agent installation was resumed.

The original API draft, all correction branches and unrelated worktrees remain.
Do not globally prune registrations or force-delete branches whose linearized
delivery cannot be established from ancestry alone. The private archive remains
available for recovery; restore into a new isolated checkout, never over a dirty
worktree. It contains raw draft source and must remain private under an appropriate
retention policy.

Next safe action: review this independent repair, then specify and implement a
bounded WebSocket replay workstream through the existing approval/scope/worker
boundary. Complete isolated-worker and independently administered approval-provider
qualification before closing #100; do not reinterpret loopback acceptance as those
missing guarantees.

### WebSocket continuation

The subsequent local workstream continues on `codex/bounded-websocket-replay`,
preserving this repair's uncommitted changes. It implements the
[bounded WebSocket text subset](BOUNDED_WEBSOCKET_REPLAY.md) through the existing
approval/scope/worker integration and expands mandatory local-service acceptance
to both role-session profiles. The original draft remains untouched. Isolation,
production-provider qualification, independent review and remote delivery remain
separate outstanding gates; this continuation does not close #100.
