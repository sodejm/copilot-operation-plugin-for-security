# Specification: Issue Documentation and Test Case Coverage Gate

## Purpose

The Issue Documentation and Test Case Coverage Gate ensures that every development change addressing an issue or feature is accompanied by corresponding documentation and executable test cases prior to push or pull request merge. This enforces the root repository contract (`AGENTS.md`) and project constitution (`.specify/memory/constitution.md`), preventing unverified or undocumented behavior from entering repository history.

## Architecture

The gate is implemented as a deterministic Python standard-library script (`scripts/agent/check_issue_coverage.py`), ensuring offline operability, zero external runtime dependencies, and instant verification in both local Git hooks and GitHub Actions workflows.

### Identification Strategy

The gate inspects the active change context:
1. **Branch Name**: Extracts issue numbers or feature slugs matching:
   - `issue-<id>`, `issues/<id>`
   - `codex/<slug>`, `feature/<slug>`, `feat/<slug>`, `fix/<slug>`
   - Numeric branch identifiers `<id>-<slug>`
2. **Commit Range Messages**: Inspects commit messages between `--base` and `--head`:
   - Conventional Commits (`feat(...)`, `fix(...)`, `refactor(...)`)
   - Issue references (`#<id>`, `Fixes #<id>`, `Resolves #<id>`, `Issue #<id>`)
   - COPS scenario references (e.g. `COPS-E05.02-S01`)

### Verification Rules

1. **Documentation Verification**:
   - The diff between `--base` and `--head` (or `--staged` files) must contain at least one modified or newly created documentation file:
     - `docs/**/*.md`
     - `specs/**/*.spec.md`
     - Root documents: `README.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
     - Plugin-specific docs: `plugins/**/README.md`, `plugins/**/docs/**/*.md`
   - *Exemption*: Allowed when the commit message or command argument includes `[skip-docs: <rationale>]` (per `AGENTS.md` allowance for documented rationale).

2. **Test Case Verification**:
   - The diff must contain at least one modified or newly created test or executable scenario file:
     - `tests/**/*.py`
     - `specs/features/**/*.feature`
     - Plugin tests: `plugins/**/tests/**/*.py`
   - *Exemption*: Allowed when the commit message or command argument includes `[skip-tests: <rationale>]`.

3. **Behavioral Test Execution**:
   - When `--run-tests` is passed, the gate executes the detected test files using the active Python interpreter. All tests must exit with code 0.

## Exit Codes & Diagnostic Reporting

- `0`: All required issue coverage checks passed (or valid exemptions documented).
- `1`: Missing documentation, missing test cases, unparseable git range, or failing test executions. Diagnostic output lists exact inspected files, detected issue context, and actionable remediation steps.
