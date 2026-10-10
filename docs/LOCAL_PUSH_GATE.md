# Local pre-push gate

This optional installation blocks a push when a prerequisite, policy check, scanner or canonical validation command fails. CI remains required: Git hooks are local, can be removed or bypassed with `--no-verify`, and are not a server-side security boundary.

## Install and update

Review the committed `tools/push_gate/` code and rules first. On a feature branch containing the reviewed commit:

```sh
python3 tools/push_gate/gate.py install
python3 .git/push-gate/gate.py check HEAD
```

If an existing pre-push hook is present, inspect it first, then explicitly use `install --replace`. The installer backs it up in Git metadata, records the old local `core.hooksPath`, and forwards other executable hooks at their original paths. It never edits tracked hook files. The replaced pre-push hook is not chained because it may validate dirty files or invoke unrelated scanners. Its required checks must be represented by the reviewed profile.

To install from another reviewed local commit while preserving a dirty checkout, run that commit's installer with `install --revision <full-commit-id> [--replace]`. It extracts only committed policy. Run the installed copy for checks. In a linked worktree, find its metadata with `git rev-parse --git-path push-gate` rather than assuming `.git` is a directory. Each clone/worktree needs installation. The recorded Python executable must remain installed.

Policy is pinned to committed Git blob IDs. Any change under `tools/push_gate/` requires reviewing and reinstalling the new committed revision before pushing. No environment variable disables checks. Direct pushes to the configured default branch, tags and deletions are blocked. Publish feature branches through the normal reviewed GitHub workflow; do not force-push.

## Prerequisites and checks

Install Semgrep **1.179.0** and Trivy **0.75.0** from their official distributions; the gate rejects other versions. Also install Git, Python >=3.10 and uv. `requirements.txt` pins direct Python validation dependencies; project dependency locks and canonical manifests govern project installs. Transitive validation dependencies are resolved by uv and are not a fully frozen toolchain. Network/package/provider access and sufficient temporary disk space are required. When relevant files exist, install actionlint, ShellCheck, bash and hadolint: all workflows, tracked shell scripts and Dockerfiles are checked. Missing tools fail closed. Scanner overrides inherited from the caller are removed.

Python >=3.10, uv, make; requirements.txt.

make check; branch-wide issue coverage; repository-wide Ruff lint and branch-changed Python formatting (matching the existing lint-only CI and avoiding unrelated formatting churn); pytest with branch coverage report; pip-audit.

Every profile also validates the gate with Ruff lint/format and its disposable Git regression tests, checks whitespace, and runs the scanners before dependency installation or generated build artifacts. Checks never apply automatic fixes, stage, commit or push. Builds, dependency downloads and generated files stay in disposable snapshots or tool caches. Canonical tools may use caches outside the snapshot.

## Security rules and reproducibility

`semgrep.yml` is a committed, reviewed small ruleset covering high-confidence Python command/deserialization hazards, JavaScript/TypeScript dynamic execution and TLS verification, Go shell/TLS hazards, shell TLS bypasses, workflow insecure Node overrides and Terraform TLS bypasses. Language-specific AST rules are used where supported; generic shell/workflow/HCL rules deliberately have narrower coverage. Rules are local; no mutable registry rules are downloaded. Inline Semgrep suppression and repository ignore files cannot hide findings. Any reported parser/analysis error fails the gate. This ruleset is not an exhaustive vulnerability audit.

Trivy scans the complete committed filesystem for vulnerabilities, secrets and misconfiguration, including development dependencies. HIGH and CRITICAL findings block, including suppressed findings returned by Trivy. The runner supplies empty config/ignore paths, rejects inline Trivy suppression and does not use `--ignore-unfixed`. Secret matches are never printed by the scanner wrapper; only finding IDs and paths appear. Raw reports are temporary and removed after execution. Trivy's vulnerability database and official misconfiguration checks update independently of the pinned executable. Results are reproducible for the same rules, tool versions and feed/cache state, not forever across changing advisories. An unavailable feed or scanner error blocks; do not suppress findings to publish.

## Branch-wide test development

The actual push URL's configured default branch is fetched into the disposable clone. The full branch is compared with its merge base, including changes already pushed earlier. Each affected policy area needs a changed executable assertion in its recognized test paths. Python assertions are compared as AST nodes; JavaScript/TypeScript/Go/BDD and Terraform assertions use limited syntax heuristics. Comments, deleted assertions and unchanged tests do not satisfy this check.

Reviewers must establish that assertions exercise the changed behavior and are meaningful: the heuristic can accept irrelevant assertions and can reject valid unconventional tests. This is evidence of test updates alongside implementation, **not proof of test-driven development**, chronological test-first work or complete coverage.

For a genuinely non-behavioral implementation change, commit `push-gate-nonbehavioral.json`, mapping the exact path to `before_sha256`, `after_sha256` and a concrete reason of at least 40 characters. Hash the UTF-8 decoded base and pushed file contents as used by the runner (an absent file is the empty string). Use only for formatting, comments or equivalent mechanical changes after review. Any content change invalidates the hashes; refresh or remove stale entries when rebasing. Behavioral changes must have tests; there is no blanket skip flag. The authoritative patterns are in `policy.json`.

## Exact commit and trust boundary

Git supplies each pushed object ID on pre-push stdin. The gate validates that commit, not HEAD, the index or dirty files. It clones without hardlinks, checks out the exact SHA with hooks disabled and enumerates every Git tree blob, including export-ignored files. Scanners run before generated files are created. Private untracked files are not copied or scanned. Symlinks, submodules, non-UTF-8/newline filenames and unsupported refs fail closed rather than silently omitting content. Every pushed branch tip is checked; intermediate historical commits are not individually scanned. Review outgoing history before first publication or when secrets were previously committed.

Repository validation executes committed code with the user's permissions. The disposable directory is **not an OS sandbox**: HOME, PATH, SSH agent and tool caches remain available for dependency access. Review untrusted commits before installing or running; use a separate restricted machine/container for hostile code. The local trusted policy copy prevents a proposed commit from silently weakening its installed checks, but a user controlling the local machine can bypass it. No production cloud credentials are needed by the profiles. CI and review remain the authority for merge/release.

## Recovery and limitations

A failure leaves remote refs unchanged. Resolve the named finding/check or install its prerequisite, commit the fix with relevant tests, then retry. For detailed canonical output, rerun the named command in a separate clean clone of the failed SHA. Do not run automatic fixes from the hook or print raw secret reports. Most subprocesses have no global timeout; network-dependent checks can be slow or interrupted, and interruption fails the push. Trivy has a 15-minute scan timeout. Remote default-branch movement after it is fetched requires CI to reconcile; validation is of the exact tip against the observed baseline.

To restore the prior hooks configuration:

```sh
python3 .git/push-gate/gate.py uninstall
```

Use `git rev-parse --git-path push-gate` in worktrees. Recovery refuses if another tool changed hooksPath after installation; reconcile the recorded installation JSON and backup manually. Backups remain for review. An emergency bypass requires a separately reviewed decision and equivalent CI evidence; it does not constitute a passing local gate. Do not remove rules, lower severities or ignore findings to make a baseline green.
