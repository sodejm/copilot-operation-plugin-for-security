# Skills

## Canonical location and format

Author reusable project workflows under `.agents/skills/<skill-name>/SKILL.md`.
Each file begins with:

```yaml
---
name: skill-name
description: A precise statement of when the skill should be used.
---
```

Keep the entrypoint focused. Put large examples, reference material, or helper
scripts beside it and load them only when needed. A skill should describe a bounded
workflow, evidence expectations, and safety boundaries—not repeat `AGENTS.md`.

Run `make sync-agent-adapters` after a skill change. COPS copies canonical skill
entrypoints and supporting resources to `.claude/skills/` for environments that do
not discover the open location. Local JSON settings and generated churn reports
are excluded. Do not edit generated copies.

## Included baseline

- `repository-orientation`: safe startup in an unfamiliar checkout.
- `repository-check`: deterministic validation and evidence reporting.
- `github-state-audit`: focused, read-only hosted-state inspection.
- `repository-delivery-gate`: readiness without conflating delivery states.
- `resumable-worktree-run`: isolated, recoverable issue-sized work.
- `agent-workboard`: durable local coordination and reconciliation for bounded
  parent/subagent or resumable work.
- `gitignore-audit`: narrow evidence-based ignore recommendations.
- `session-usage-audit`: local Git churn and workflow opportunities, with optional
  Codex session evidence for editing activity and token usage.
- `security-review`: generic defensive change review.
- `documentation-impact`: documentation mapping and validation.

## Local churn and usage audits

The [session-usage-audit skill](../.agents/skills/session-usage-audit/SKILL.md) uses
Python's standard library and Git. Any agent environment can run a Git-only audit:

```bash
python3 .agents/skills/session-usage-audit/scripts/codex_churn_audit.py \
  --repo . --git-only --days 7 --output-dir ../churn-reports
```

Select repositories explicitly with repeatable `--repo`. The bundled example
configuration has no repository defaults. To reuse private settings, copy the
example to `churn.local.json` and pass it with `--config FILE`. Use `--days 28` for
an initial baseline with weekly breakdowns, explicit `--start`/`--end` timestamps
for fixed windows, and `--compare FILE` for saved-report comparisons.

Omit `--git-only` to include local Codex session evidence. Session parsers for
other providers are not included. Git-only mode never opens session logs and
cannot attribute Git changes to agents or measure task tokens. Missing evidence
remains unknown in both modes. Git history and recorded agent changes are
overlapping views; they are never added together.

Both Markdown and versioned JSON reports are saved outside audited repositories
and session directories. Reports omit source and transcript bodies, but paths,
task identifiers, and usage metadata can still disclose private work. Keep
reports and local settings private; COPS excludes `*.local.json`, `churn-v*.json`,
and `churn-v*.md` from Git and skill adapters. Review
renamed or separately exported files before sharing. Recommendations are advisory
text targeting existing contracts and planning sections; the helper does not
change workflows or make model calls.

## COPS-specific workflows

- `plugin-validator`: validates the distributed plugin package.
- `local-repo-scanner`: runs the local product scanner using its canonical path.
- `agentskills-frontmatter-enforcer`: checks skill authoring conventions.
- `git-workflow-manager`: scopes Git transitions and preserves unrelated work.

The `milestone-delivery` baseline skill is available for explicitly authorized
milestone work. PARK's template-project-creator skill is not part of COPS.

## Global-skill selection rationale

COPS carries reusable ideas from a broader personal skill set but intentionally
does not copy machine- or account-level automation.

| Global pattern | COPS treatment | Reason |
| --- | --- | --- |
| GitHub state audit | included, rewritten | Generic, read-only, and portable |
| Delivery gate | included, rewritten | Durable evidence and lifecycle discipline |
| Resumable worktrees | included, simplified | Useful Git primitive for isolated, recoverable work |
| Agent workboard | included, rewritten | Portable SQLite state and explicit handoffs; optional hook support stays isolated in its helper |
| `.gitignore` audit | included, simplified | Generic and safe |
| Session usage and churn audit | included, portable inputs | Agent-independent Git evidence, optional local Codex sessions, no account defaults or services |
| GitHub workflow guard | principles in `AGENTS.md` and skills | Require explicit authorization for remote writes |
| GitHub authentication guard | excluded | Machine/account hook, not repository policy |
| Model router and issue model recommender | excluded | Vendor catalog and account specific |
| Issue prioritizer | excluded | Optional live-service workflow, not every project's baseline |
| COPS contributor skills | retained | Project-specific validation and Git workflows |
| Machine-installed third-party skills | excluded | Their licensing, versioning, and runtime remain external |

Projects may add optional skills after reviewing their license, provenance,
permissions, maintenance model, and whether repository-level sharing is appropriate.
