---
layout: documentation
title: "Contributor Guide"
description: "Guidelines, environment setup, testing standards, and step-by-step instructions for contributing to the COPS plugin suite."
---

# Contributor Guide

Thank you for contributing to COPS! Whether you are fixing a bug, improving documentation, adding an agent skill, or creating an entirely new security plugin, this guide provides the setup and standards you need.

---

## Code & Evidence Standards

All contributions adhere to the canonical [Repository Contract (AGENTS.md)](../AGENTS.md):

1. **Offline-First & Deterministic**: Offload data parsing, schema checks, and evidence evaluations to standard-library Python scripts. Reserve LLM context for reasoning and synthesis.
2. **Standard-Library Core**: The core runner, CLI, scanner, and plugin validator must use only the Python standard library. External dependencies are strictly reserved for testing (`requirements.txt`).
3. **Dedicated Branches**: Always implement changes on a dedicated task branch based on a fresh fetch of `origin/main`.
4. **Honest Evidence Reporting**: Never claim a check passed unless it ran in the local checkout. Clearly distinguish between offline validated tests, unverified cloud claims, and live-tested results.
5. **No Secrets or Private Paths**: Never commit API keys, personal credentials, private tenant data, or machine-specific home paths.

---

## Environment Setup

### 1. Create a Dedicated Virtual Environment

COPS requires **Python 3.11 or newer**:

```bash
# Clone the repository
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate
```

*(On Windows PowerShell, run `.\.venv\Scripts\Activate.ps1` to activate).*

### 2. Install Development & Test Dependencies

Install the test runners and schema validators:

```bash
python -m pip install -r requirements.txt
```

Verify that all test prerequisites are satisfied:

```bash
make check-prerequisites
```

### 3. Install Local Push Protections

Install local Git hooks to protect against accidental direct pushes to `main`, credential leakage, and missing issue coverage:

```bash
make setup-hooks
```

---

## Running Tests and Checks

Before pushing or opening a pull request, run the complete validation gate and verify that your changes satisfy documentation and test coverage for the active issue:

```bash
# Run full repository checks
make check PYTHON=.venv/bin/python

# Verify issue documentation & test coverage
make check-issue-coverage
```

Python changes must also pass `ruff check .`; YAML changes must pass `yamllint -s .`, matching the hosted quality gate. Install these tools in the development environment before running them. After changing canonical skills or portable evidence sources, regenerate adapters with `make sync-agent-adapters` and the evidence bundle with `python scripts/agent/bundle_evidence.py`, then rerun validation.

Security lint exceptions must describe the concrete reason at the narrowest applicable scope. Offline tests use synthetic credentials and noncryptographic seeded fuzzing; standalone scripts may set up the repository import path before imports. Public string-enum behavior is preserved rather than migrated solely to satisfy a style rule. Production authorization storage errors must propagate, and XML imports must reject entity declarations before parsing imported data.

### Issue Documentation & Test Coverage Requirements
Every branch addressing an issue or feature must include:
1. **Documentation**: Updated or newly created markdown files in `docs/`, `specs/`, or root guides.
2. **Behavioral Test Cases**: Automated tests in `tests/` or Gherkin BDD scenarios in `specs/features/`.

If an administrative change, refactor, or typo fix requires an exemption, provide a rationale in the commit message using:
- `[skip-docs: <rationale>]`
- `[skip-tests: <rationale>]`


### What `make check` executes:
1. **Python Source AST Parsing**: Validates that all Python files parse cleanly without syntax errors.
2. **Contract Validation** (`scripts/agent/validate_contract.py`): Checks skill frontmatter, ensures no machine-specific paths exist, and verifies that all relative Markdown links resolve on disk.
3. **Agent Adapter Synchronization** (`scripts/agent/sync_adapters.py --check`): Ensures that `.claude/` and other host adapters are perfectly synchronized with `.agents/`.
4. **Marketplace Index Integrity** (`scripts/agent/validate_marketplace.py`): Checks that plugin manifests conform to the Agent Plugins v1.0.0 specification.
5. **Prerequisite Verification** (`scripts/agent/install_prerequisites.py --validate`): Ensures system and library prerequisites are correctly met.
6. **Portable Export Validation** (`scripts/agent/export_portable.py --check`): Verifies standard packaging boundaries.
7. **Evidence Bundle Validation** (`scripts/agent/bundle_evidence.py --check`): Ensures evidence receipts adhere to schema constraints.
8. **Host Marketplace Synchronization** (`python3 -m cops generate --check`): Verifies that `.github/`, `.claude-plugin/`, and `.agents/` marketplace files match `catalog/plugins.json`.
9. **ATT&CK Coverage Check** (`python3 -m cops coverage --check`): Validates MITRE ATT&CK matrix mappings.
10. **Plugin Test Suites** (`python3 -m cops check`): Runs declared offline verification suites across all 13 plugins.
11. **Pytest & Unittest Suites**: Executes all acceptance scenarios (`pytest tests`) and skill unittests.
12. **Git Diff Check**: Confirms no trailing whitespace or corrupt line endings exist.

---

## Adding a Plugin

To contribute a new cybersecurity capability to COPS:

1. **Choose Exactly One Primary Category**:
   - `logging-telemetry`
   - `detection-hunting`
   - `identity-access`
   - `vulnerability-management`
   - `offensive-security`
   - `incident-response`

2. **Register the Package in `catalog/plugins.json`**:
   Add the plugin definition including its ID, name, version, category, maturity (`experimental`, `beta`, `stable`), and operational mode (`planned`, `import`, `laboratory`, `live-validated`).

3. **Create the Package Directory Structure**:
   Place the package at `plugins/<category>/<plugin-id>/` with:
   - `plugin.json`: Core Agent Plugins v1.0.0 manifest.
   - `README.md`: Overview, target practitioners, and prerequisites.
   - `docs/PLAYBOOK.md`: Step-by-step practitioner playbook.
   - `scripts/`: Standard-library Python validation and demo scripts.
   - `tests/`: Offline synthetic test data and unit tests.
   - `skills/`: Reusable agent skills conforming to `agentskills.io`.

4. **Regenerate Host Marketplaces**:
   ```bash
   python3 -m cops generate
   ```
   This updates `.github/plugin/marketplace.json`, `.claude-plugin/marketplace.json`, and `.agents/plugins/marketplace.json` automatically.

5. **Verify the New Package**:
   ```bash
   python3 -m cops validate <plugin-id>
   python3 -m cops demo <plugin-id>
   python3 -m cops check <plugin-id>
   make check PYTHON=.venv/bin/python
   ```

For complete authoring details, review [Adding a Plugin (docs/ADDING_A_PLUGIN.md)](ADDING_A_PLUGIN.md).

---

## Offline Dependency Setup

For air-gapped or restricted network development environments:

1. **On a connected machine** (matching OS, architecture, and Python version):
   ```bash
   python -m pip download --dest wheelhouse -r requirements.txt
   ```

2. **Transfer `wheelhouse` and `requirements.txt`** to the offline machine.

3. **Install from local wheelhouse**:
   ```bash
   python -m pip install --no-index --find-links wheelhouse -r requirements.txt
   make check-prerequisites
   make check PYTHON=.venv/bin/python
   ```

Workflow maintenance keeps checkout actions aligned with the current hosted runner runtime. The dependency pull requests update the remaining Python, CodeQL, and Pages actions; shell values used by issue summaries are quoted before passing them to the GitHub CLI.
