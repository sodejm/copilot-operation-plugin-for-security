---
name: github-state-audit
description: Produce a focused, read-only snapshot of GitHub issues, pull requests, reviews, checks, branches, and mergeability when hosted state matters.
---

# GitHub state audit

Use only when current GitHub state is relevant and network access is authorized.
This workflow is read-only.

1. Confirm the repository and smallest relevant issue, PR, branch, or workflow.
2. Query live GitHub state with `gh` or the GitHub API; do not substitute local or
   remembered state for current hosted evidence.
3. Reconcile head/base commits, PR state, review decision, unresolved threads,
   required checks, mergeability, and branch protection as applicable.
4. Distinguish missing evidence from a negative result and note the observation
   timestamp when the state may change.
5. Report concise evidence and the next decision. Do not comment, rerun, label,
   close, merge, or otherwise mutate GitHub.

Never expose authentication output or credentials.
