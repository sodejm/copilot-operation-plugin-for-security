# Squad contributor workflow

COPS uses [GitHub Squad](https://github.com/github/squad) for contributor
coordination across Copilot, Claude, Kiro, OpenCode, Cursor, Codex and Antigravity.
This is development tooling, not a change to installed security-plugin execution.
The canonical policy is [AGENTS.md](../AGENTS.md#automatic-squad-orchestration).

## Installation and startup

Requires Node.js 22.5 or newer. The reviewed initialization command is:

```sh
npx --yes --ignore-scripts --package=@bradygaster/squad-cli@2.0.0 squad init --client all
```

Do not use bare `npx squad`: that unscoped package belongs to another project.
The committed all-client configuration pins the official CLI to 2.0.0. npm still
resolves transitive dependencies; this is not a fully locked dependency closure.
Review package changes before upgrading. Host trust and MCP approval remain
required. No global configuration, credential, paid worker or hosted Copilot
assignment is provisioned by this policy. Restart the relevant client to discover
new agents and MCP configuration; a current session does not gain tools merely
because files were added. Codex can use its `squad` custom agent or the current
lead session can coordinate using its actual subagent tools and the same roster.

Normal implementation requests automatically use the [team](../.squad/team.md)
and [routing](../.squad/routing.md). Lead integrates; Builder implements; Validator
checks; Sentinel reviews security boundaries; Documenter maintains docs/evidence.
Use only the specialists the task needs. Simple edits stay direct. Missing host
support is reported, not simulated. Native operation in all seven clients still
requires client-by-client acceptance; generated configuration is not that proof.

## Parallel work and integration

1. Inspect the exact checkout, preserve dirty work, fetch the default branch and
   create a task integration branch. Record its base SHA and authorized scope.
2. Decompose independent items with explicit file ownership and dependencies.
   Use the installed model router and agent workboard before every Codex launch.
   Bind each worker to a unique branch/worktree and a bounded acceptance contract.
3. Workers commit only their own staged changes after relevant checks, aiming at
   5 minutes and at most 10 minutes between coherent active-edit checkpoints.
   Report exceptions rather than manufacturing empty or broken commits.
4. The coordinator keeps one factual progress record on each existing issue:
   status, exact SHA, local/pushed distinction, checks, blocker and next step.
   New material progress is updated at checkpoints; no unchanged heartbeat spam.
5. Review named worker commits, then integrate them in dependency order. Only
   the lead edits shared contracts and canonical Squad state. Resolve conflicts,
   run focused checks and `make check` on the combined tree, and inspect the diff.
6. Merge separate work-item PRs only within the recorded user-authorized delivery
   batch, after live required checks, review findings and protection checks. Do
   not infer release authority. Close issues only when acceptance and delivery
   evidence support closure. Preserve unmerged branches and dirty worktrees.

A progress comment can use:

```text
Status: in progress
Evidence: <exact SHA> (local checkpoint, not pushed); <checks and results>
Next: <specific integration or validation step>
Blocker: <only if present>
```

The cadence is an active-session obligation, not an operating-system timer.
These instructions cannot run agents, create commits or post issue comments
while no host session is running. Long checks and unavailable services must be
reported honestly. Hosted issue triage is separate from local swarm execution.

## Maintaining upstream scaffolding

Initialization used CLI 2.0.0 from github/squad. Stock templates and optional
skills remain in `.squad/`; they are subordinate to the COPS root contract.
Upstream generated Claude-only skills were moved into `.squad/skills/` to keep
`.claude/skills/` an exact generated mirror of `.agents/skills/`. Do not add them
to the COPS runtime or canonical contributor skill inventory implicitly.

The four generated GitHub workflows are retained under
`.squad/optional-workflows/` for review, outside `.github/workflows/`. They do not
run: their broad repository triage and Copilot assignment differ from scoped
active-session orchestration. Enabling them needs an explicit scope and separate
review. No token has been configured. Automatic union merging of decision files
and broad generated Claude permission grants were removed; integrate policy
conflicts explicitly and retain normal host approvals.

`init`, `upgrade`, `cast` and `client sync` can regenerate client projections,
permissions and skills. After using them, reapply these customizations, verify
pinned MCP commands, review every diff, run `make sync-agent-adapters` and
`make check`. Keep `.codex/config.toml` portable and secret-free; machine-specific
configuration belongs in the user's host configuration, not this tracked file.

Recovery: revert the setup commits through the ordinary branch workflow, restart
clients, and preserve any active worker branches and unmerged commits. Removing
configuration does not undo remote issue updates or merged PRs.
