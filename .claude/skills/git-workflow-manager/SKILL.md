---
name: git-workflow-manager
description: Manage scoped COPS branches, commits, and authorized GitHub delivery transitions while preserving unrelated work.
---

# COPS Git workflow

Read root `AGENTS.md`, inspect `git status --short --branch`, and preserve unrelated
changes. Work on a focused branch; use `codex/<short-description>` for Codex work
unless the user names a branch. An isolated worktree may be used when needed.

Run `make check` and review the diff before a handoff or an authorized commit.
Use Conventional Commits (`docs(cops): ...`, `chore(repo): ...`, `fix(scanner): ...`).
Stage only the explicitly reviewed paths; do not use blanket staging on a dirty tree.

Commit, push, PR creation, merge, release, and deployment are separate transitions.
Apply the user's authorization to each requested transition and report exact
evidence. Do not automatically merge or push to the default branch. Do not delete
branches or worktrees containing unmerged work; perform cleanup only within the
authorized scope after checking their current state.
