---
name: resumable-worktree-run
description: Plan and hand off issue-sized work in an isolated Git worktree with an evidence-bearing checkpoint and safe cleanup boundary.
---

# Resumable worktree run

Use for substantial or interruptible Git work when worktree isolation is helpful.

1. Inspect existing branches, worktrees, changes, and the intended base revision.
2. Create one clearly named branch and worktree for one workstream only when the
   user or project workflow authorizes it.
3. Keep a concise checkpoint containing outcome, scope, branch/worktree, base and
   head commits, completed validation, current step, blocker, and next action.
4. Before resuming, recheck that the worktree and hosted state still match the
   checkpoint; treat drift as new evidence.
5. At handoff, include exact paths and commands without private machine details in
   public artifacts.

Never remove a worktree or branch with unique or uncommitted work. Cleanup requires
fresh verification and the authority specified by the project workflow.
