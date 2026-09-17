# Hooks

Hooks are not portable policy. Their event names, configuration, trust prompts,
shell semantics, and permission models differ across environments.

COPS therefore follows three rules:

1. Canonical invariants live in `scripts/agent/` and CI.
2. Local hooks call those scripts; they do not contain unique policy.
3. Hooks are opt-in, inspectable, deterministic, and unable to publish or deploy.

## Optional pre-commit hook

If the project uses `pre-commit`:

```bash
pre-commit install
```

The checked-in configuration runs `python3 scripts/agent/check.py`. Installing it
is optional; CI repeats the same contract.

## Vendor hooks

Do not commit active Claude, Codex, Antigravity, or IDE hook settings merely to gain
convenience. First document:

- the lifecycle event and exact command;
- supported operating systems and shells;
- files and network resources it can access;
- timeout and failure behavior;
- how users opt in and disable it;
- the CI control that independently enforces the invariant.

Never use a hook to authorize commands, inject secrets into prompts, modify hosted
state, or execute newly downloaded content.
