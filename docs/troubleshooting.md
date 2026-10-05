---
layout: documentation
title: "Troubleshooting Guide"
description: "Diagnose and resolve common setup, environment, test, and catalog issues across the COPS plugin suite."
---

# Troubleshooting Guide

This guide covers common issues encountered when running, testing, or contributing to COPS, along with step-by-step resolution instructions.

---

## First Step: Run `cops doctor`

Whenever unexpected behavior occurs, run the built-in diagnostic tool first:

```bash
python3 -m cops doctor
```

For contributor environments with test dependencies, run:

```bash
.venv/bin/python scripts/agent/doctor.py
```

`cops doctor` inspects your Python version, verifies catalog synchronization, checks test dependencies, and validates tool paths.

---

## Common Issues & Solutions

### 1. Python Version Mismatch (< 3.11)

**Symptom**:
```text
error: Python 3.11 or newer is required (found 3.10.x)
```

**Cause**:
Your system's default `python3` points to an older version of Python. COPS requires Python 3.11+ for modern standard-library features (such as `tomllib` and enhanced typing).

**Resolution**:
1. Check available Python versions on your system:
   ```bash
   python3.11 --version || python3.12 --version || python3.13 --version
   ```
2. Create your virtual environment with Python 3.11 or newer:
   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```
3. When running `make`, explicitly pass your Python interpreter:
   ```bash
   make check PYTHON=.venv/bin/python
   ```

---

### 2. Missing Test Dependencies (`pytest`, `pytest-bdd`, `jsonschema`)

**Symptom**:
```text
"python3" scripts/agent/check_prerequisites.py
error: pytest: missing
error: pytest-bdd: missing
error: jsonschema: missing
Create and activate a Python 3.11+ virtual environment, then run:
  python -m pip install -r requirements.txt
make: *** [check-prerequisites] Error 1
```

**Cause**:
The core CLI (`cops list`, `cops demo`, `cops doctor`) uses only standard-library Python and requires no external packages. However, contributor verification gates (`make check`) require test dependencies.

**Resolution**:
1. Activate your virtual environment:
   ```bash
   source .venv/bin/activate
   ```
2. Install test dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
3. Run the checks using the virtual environment interpreter:
   ```bash
   make check PYTHON=.venv/bin/python
   ```

---

### 3. Catalog and Marketplace Drift

**Symptom**:
```text
Error: Generated host marketplace indexes are out of date with catalog/plugins.json.
Run: python3 -m cops generate
```

**Cause**:
A plugin was added or modified in `catalog/plugins.json`, but the synchronized manifests for GitHub Copilot (`.github/plugin/marketplace.json`), Claude Code (`.claude-plugin/marketplace.json`), or Codex (`.agents/plugins/marketplace.json`) were not updated.

**Resolution**:
Regenerate all host manifests with a single command:
```bash
python3 -m cops generate
```
Verify synchronization:
```bash
python3 -m cops generate --check
```

---

### 4. Broken Relative Markdown Links

**Symptom**:
```text
error: docs/EXAMPLE.md:42: Markdown target does not exist: foo.md
```

**Cause**:
`scripts/agent/validate_contract.py` enforces link integrity across all Markdown documents in the repository. If a link points to a non-existent file, the contract check fails.

**Resolution**:
1. Check the file and line number cited in the error.
2. Verify whether the target file exists, was renamed, or requires a path adjustment (e.g. `../plugins/...`).
3. External web URLs (starting with `https://`) and intra-page anchors (starting with `#`) are ignored by this check.

---

### 5. Machine-Specific Home Path Violations

**Symptom**:
```text
error: scripts/my_script.py: contains a machine-specific home path
```

**Cause**:
The repository portability contract strictly forbids hardcoded personal user directories in committed code or evidence to ensure reproducible execution across different machines and CI.

**Resolution**:
Replace absolute paths with repository-relative paths:
```python
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
data_path = ROOT / "catalog" / "plugins.json"
```

---

### 6. Windows PowerShell Execution Policy

**Symptom**:
```text
.\.venv\Scripts\Activate.ps1 : File cannot be loaded because running scripts is disabled on this system.
```

**Cause**:
PowerShell's default execution policy restricts unsigned script execution.

**Resolution**:
Temporarily allow local script execution in your active PowerShell session:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

---

### 7. Air-Gapped / Offline Pip Install Failures

**Symptom**:
```text
WARNING: Retrying after connection broken... Could not find a version that satisfies the requirement...
```

**Cause**:
In an air-gapped or offline environment, pip cannot contact PyPI.

**Resolution**:
1. On an internet-connected machine with matching OS and Python version, pre-download the wheelhouse:
   ```bash
   python -m pip download --dest wheelhouse -r requirements.txt
   ```
2. Copy the `wheelhouse` directory to the offline system.
3. Install using the offline find-links flag:
   ```bash
   python -m pip install --no-index --find-links wheelhouse -r requirements.txt
   ```

---

### 8. Push Blocked: Direct Push to `main` Prohibited

**Symptom**:
```text
❌ [PUSH BLOCKED] Direct push to 'main' is prohibited per AGENTS.md.
   Please create a dedicated branch (e.g. codex/<description>) and open a Pull Request.
```

**Cause**:
The local pre-push hook (`.git/hooks/pre-push`) prevents accidental direct pushes to `main`.

**Resolution**:
1. Create a dedicated task branch:
   ```bash
   git checkout -b codex/my-task
   ```
2. Push your dedicated branch and open a pull request:
   ```bash
   git push -u origin codex/my-task
   ```

---

### 9. Push Blocked / CI Failed: Issue Documentation or Test Coverage Missing

**Symptom**:
```text
[FAILED] Issue coverage requirements not met:
  - Missing documentation changes for issue 42
  - Missing test case changes for issue 42
```

**Cause**:
Per repository governance (`AGENTS.md` and Constitution), every change addressing an issue or feature must include updated documentation (in `docs/` or `specs/`) and executable tests (in `tests/` or `specs/features/`).

**Resolution**:
1. Check changed files with `make check-issue-coverage`.
2. Add or update documentation in `docs/` or `specs/`.
3. Add or update behavioral test cases in `tests/` or Gherkin features in `specs/features/`.
4. If the commit is purely administrative (e.g. minor typo or internal refactor with no behavioral changes), include an explicit exemption in the commit message:
   ```text
   git commit -m "chore: fix typo in comment [skip-docs: comment typo only] [skip-tests: no logic change]"
   ```

---

### 10. Secret Scanner Detection

**Symptom**:
Gitleaks or repository scanner identifies a possible secret or token pattern.

**Cause**:
A committed or staged file contains an API key, private key header, password, or connection string.

**Resolution**:
1. Never commit real credentials or private endpoints.
2. Replace real secrets with synthetic, mock placeholders (e.g. `mock-api-key-fixture`).
3. If an existing commit contains a secret, amend or rebase to remove the secret before pushing:
   ```bash
   git commit --amend
   ```

---

## Still Need Help?

- Check the [Getting Started Guide](getting-started.md) for basic setup steps.
- Review [Contributing Guidelines](contributing.md) for repository standards.
- Open a GitHub issue with the full output of `python3 -m cops doctor`.
