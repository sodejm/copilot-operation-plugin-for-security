---
name: repository-orientation
description: Establish the repository contract, relevant files, Git state, commands, and constraints before starting unfamiliar work.
---

# Repository orientation

Use this skill at the start of substantive work in an unfamiliar checkout.

1. Read the root and nearest `AGENTS.md` files plus the task-relevant README or docs.
2. Inspect `git status --short --branch`, the current branch, worktree, and remotes.
3. Locate project-owned entry points such as `Makefile`, task runners, manifests,
   lockfiles, CI workflows, and relevant tests.
4. Identify unrelated changes and avoid overlapping them.
5. State the requested outcome, smallest likely scope, validation plan, and any
   assumption that could materially change the work.

Do not install dependencies, change files, contact external services, or execute
unknown scripts merely to orient. Report environmental blockers separately from
repository defects.
