---
name: agent-workboard
description: Coordinate bounded subagent or resumable work through a durable, private per-project SQLite workboard. Use only from a running parent agent when orchestration needs explicit task state and reconciliation.
---

# Agent Workboard

Use this skill from a running parent agent to coordinate bounded subagent or
resumable work. It supplies durable, project-local task state; it does not replace
the parent agent's judgment, complete subagent prompts, repository policy, or final
reconciliation.

## Storage and safety

- In a Git project, the board is stored at
  `<git-common-dir>/codex/workboard.sqlite3`. Linked worktrees share this board,
  and Git does not track it.
- Outside Git, the board is stored beneath the local agent configuration directory,
  keyed by a hash of the canonical project path.
- Markdown handoffs live in the board directory's `handoffs/` folder.
- The CLI creates board directories with owner-only permissions where the platform
  supports them. Use temporary databases only in automated tests.
- Store bounded contracts, concise progress, validation summaries, and file
  references. Never store credentials, tokens, personal secrets, full transcripts,
  raw tool output, or large code and log dumps.

Run the packaged helper with the active Python interpreter:

```text
python3 .agents/skills/agent-workboard/scripts/workboard.py
```

Every command accepts `--cwd <project>` or `--db <exact-path>` before the
command and `--json` for machine-readable output.

## Parent workflow

1. Initialize the board:

   ```text
   workboard.py --cwd <project> --json init
   ```

2. Create a run owned by the current parent session:

   ```text
   workboard.py --cwd <project> --json run start \
     --title "<bounded orchestration>" --session-id "<session-id>"
   ```

3. Route every task with the repository's subagent-routing policy, then add its
   complete contract: goal, allowed scope, inputs, expected output, acceptance
   checks, selected model and effort, dependencies, worktree, and branch.

4. Put these literal fields in each child prompt:

   ```text
   WORKBOARD_DB=<resolved path>
   WORKBOARD_RUN_ID=<run id>
   WORKBOARD_TASK_ID=<task id>
   ```

   Direct the child to claim before it works, heartbeat during long work, and
   finish with `task complete` or `task block`.

5. Launch the subagent according to that environment's supported mechanism, then
   immediately bind its returned agent identifier:

   ```text
   workboard.py --db <path> task bind \
     --task-id <task-id> --agent-id <agent-id> --agent-type <type>
   ```

6. Before reporting orchestration complete, run `reconcile`, inspect
   `status --run-id`, read every generated handoff, and resolve all
   `pending`, `ready`, `launched`, `running`, `blocked`, or `stale`
   tasks. Never infer completion solely from a child's final message.

## Child workflow

Read the three `WORKBOARD_*` values from the launch prompt, then atomically claim
the assigned task before beginning:

```text
workboard.py --db <path> task claim \
  --task-id <task-id> --agent-id <agent-id>
```

For work lasting more than a few minutes, renew the 30-minute lease and record only
a concise checkpoint:

```text
workboard.py --db <path> task heartbeat \
  --task-id <task-id> --agent-id <agent-id> \
  --progress "<short checkpoint>"
```

Finish exactly once:

```text
workboard.py --db <path> task complete \
  --task-id <task-id> --agent-id <agent-id> \
  --summary "<result>" --validation "<check and result>" \
  --changed-file "<path>" --validation-file "<path>"
```

or:

```text
workboard.py --db <path> task block \
  --task-id <task-id> --agent-id <agent-id> \
  --reason "<concrete blocker>" --next-action "<one next action>"
```

If the board is temporarily unavailable, do not fabricate state. Preserve the run
and task IDs in the child prompt or handoff, report the failure to the parent, and
retry only safe idempotent operations.

## State rules

- States: `pending`, `ready`, `launched`, `running`, `blocked`,
  `completed`, `cancelled`, `stale`.
- Dependencies move from `pending` to `ready` only after all prerequisites
  complete.
- Claims use `BEGIN IMMEDIATE`; exactly one agent owns a contested task.
- Leases last 30 minutes and are renewable. Only `reconcile` turns expired
  running tasks into `stale`.
- Never reassign stale work automatically.
- `block`, `complete`, and `cancel` write a Markdown handoff automatically.
- `complete` and `block` accept repeatable `--changed-file` and
  `--validation-file` references. Put only a small result in `--validation`.
- `export --task-id <id> --to <repository-path>` is the only supported way to
  copy a handoff into a repository.
- `gc --older-than <days>` is explicit; history is never deleted automatically.

## Environment integration

This portable skill does not require a particular agent harness or hook system. A
harness that supports the helper's optional `hook` command may inject board and
agent details at subagent start; otherwise the parent places those values directly
in the child prompt. In either case, the parent remains responsible for launch
policy, reconciliation, and repository state.
