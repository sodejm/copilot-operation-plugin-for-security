# Local pre-push validation

Contributor tooling requires Python 3.11 or newer. The installed policy validates
each proposed branch tip from Git's pre-push input, using committed files in an
isolated checkout. Dirty and untracked files cannot supply validation inputs.

## Required behavior

- Scanner findings, missing executables, malformed policy and failed canonical
  checks stop the push before the remote branch changes.
- Semgrep uses reviewed repository rules and a pinned scanner version. Trivy
  blocks HIGH and CRITICAL vulnerabilities, secrets and misconfigurations,
  including findings without a published fix.
- Implementation changes across the entire feature branch require changed
  executable test assertions. Comments and deletion alone do not qualify.
  Non-behavioral exceptions bind an explanation to exact before/after file hashes.
  This is a test-development check; it cannot establish development chronology,
  test relevance or test-driven development.
- The installer retains prior hook configuration for recovery, forwards other
  executable hooks and pins the reviewed policy. Policy changes require explicit
  reinstallation. Hooks never fix, stage, commit or push files.

## Acceptance evidence

`specs/features/local_push_gate.feature` executes the disposable-remote regression
cases in `tests/test_local_push_gate.py`. They verify exact-tip selection, missing
tool and check failures, and the branch-wide requirement after a previous push.
Scanner doubles test orchestration; real scanner canaries must separately establish
scanner behavior. Run `make check` and the installed gate against the final commit.

## Security and operations

Repository validation commands execute trusted code with the developer's OS
permissions; a temporary checkout is not a sandbox. Inherited application and
scanner overrides are removed, but PATH, HOME and SSH agent access remain trusted.
Local hooks are bypassable, so CI remains required. Installation, prerequisites,
recovery and coverage limits are documented in `docs/LOCAL_PUSH_GATE.md`.
