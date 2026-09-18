---
name: gitignore-audit
description: Inspect a repository and recommend narrow evidence-backed ignore patterns without modifying files or hiding tracked artifacts.
---

# Gitignore audit

This workflow is read-only unless a later request explicitly asks for edits.

1. Read all applicable ignore files and `git status --ignored --short`.
2. Identify untracked generated output, caches, local settings, credentials, editor
   state, or platform files using file contents and project tooling as evidence.
3. Check whether each candidate is already tracked or intentionally committed.
4. Prefer the narrowest stable pattern; avoid broad extension or directory rules
   that could hide source, fixtures, documentation, lockfiles, or migrations.
5. Report candidates grouped as high confidence, project decision, and do not
   ignore. Include the evidence and risk for each.

Never display secret values and never use ignore rules as remediation for a secret
that is already committed.
