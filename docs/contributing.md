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
2. **Standard-Library Core**: The core runner, CLI, scanner, plugin validator,
   and unsigned workflow discovery, validation, and playback must use only the
   Python standard library. Signed laboratory receipt verification uses the
   optional `laboratory` extra; Ed25519 workflow evidence signing uses the
   optional `crypto` extra only when a caller requests signing. Contributor test
   dependencies are in `requirements.txt`.
3. **Dedicated Branches**: Always implement changes on a dedicated task branch based on a fresh fetch of `origin/main`.
4. **Honest Evidence Reporting**: Never claim a check passed unless it ran in the local checkout. Clearly distinguish offline fixture results from laboratory evidence. No live-evidence verifier is currently registered, so filenames, flags, manifests, and receipt labels cannot support a `live-validated` claim.
5. **No Secrets or Private Paths**: Never commit API keys, personal credentials, private tenant data, or machine-specific home paths.

The [offline engagement reporting guide](ENGAGEMENT_REPORTING.md) defines the
input bundle, assessment labels, and privacy review for findings reports.
Changes to its joins or claims need focused tests for missing evidence,
partial outcomes, contradictory findings, and sensitive text.

### Issue model and effort preflight

Before implementing an issue, apply the [model routing guide](model-effort-routing.md)
and [contributor routing skill](../.agents/skills/route-security-specialist/SKILL.md).
Read the issue, assess whether Daybreak would materially help, and verify the
current model/effort against fresh exact host evidence. Pause for a supported
change when needed; an authorized subagent override must satisfy the applicable
launcher routing and workboard rules and does not switch the parent.

Model advisor changes need focused coverage for catalog validation, freshness,
access, capabilities, effort limits, current settings, and both CLI entry points:

```bash
python -m pytest tests/test_model_advisor.py tests/step_defs/test_model_effort_routing.py tests/test_routing.py -q
```

The full repository gate still applies. Provider access and host installation
remain separate from offline test evidence.

---

## Authenticated Execution Changes

Changes to Action Plans, execution authorizations, trust stores, approval storage, or worker dispatch must preserve these invariants:

- secret bytes enter only through the environment variable named by verifier-owned trust configuration;
- signatures cover the full approved Action Plan snapshot and expected worker identity;
- key, authorization, and Engagement identities and validity windows agree;
- worker capability inventories are owner-provisioned measurements, loaded only from
  current-user-owned non-symlink files without group or other permission bits, and
  never described as runtime host capability discovery;
- external adapter dispatch verifies an operator-provisioned platform SHA-256 and
  the adapter's pinned upstream revision, then binds version probe and operation to
  the same held executable inode on supported Linux workers;
- raw stdout and stderr are bounded during collection, timeout and overflow remain
  explicit partial outcomes, and evidence writes reject symlinks and workspace
  escapes;
- compatibility failures happen before authority is consumed;
- the approval authority alone holds verifier trust and the protected approval store;
  the worker submits only an authorization identifier and exact plan through a
  peer-credential-checked local control channel;
- SSH requests bind a pinned host key and exact host and worker identities, and
  required Linux process-isolation controls fail closed before consumption;
- consumption is atomic and replay fails closed; and
- migrated unsigned or digest-only rows remain `legacy-untrusted`.

Add focused acceptance tests for tampering, unknown/revoked/expired keys, operator and worker mismatches, replay, migration, inventory ownership and permissions, exact tool/platform compatibility, authority peer credentials, SSH identity binding, and sandbox readiness. Update the [Authenticated Execution Guide](AUTHENTICATED_EXECUTION.md), Security Model, compatibility/migration guidance, and affected plugin operator docs when an interface or trust assumption changes. Never add live secrets, private paths, or realistic credential material to fixtures or evidence.

For purple-team handoff changes, preserve the four documented result states and
require every `expected_telemetry` field path to be unique. Tests must cover
equal and conflicting duplicate values, valid multi-field predicates, and
insufficient or malformed input. Duplicate fields must fail before handoff
output, detection classification, or Sigma/KQL proposal generation; do not test
or document predicate collapsing as supported behavior.

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

`make check` is the portable repository baseline. Changes to laboratory behavior or readiness claims must also pass the mandatory laboratory gate:

```bash
make check-laboratory
```

That gate exercises local service activity and verifies telemetry, isolation, and restoration. Offline fixtures, generated playbooks, and generated walkthroughs validate deterministic logic and documentation; they do not establish laboratory readiness.

For changes to integrated service chains, first run
`python -m pytest -q tests/test_integrated_service_laboratory.py tests/test_check_laboratory.py tests/test_laboratory_container.py`.
These checks cover typed prior outputs, exact service destinations, changed plans,
wrong workers, approval replay, and restoration. The Docker gate additionally
proves the network boundary and executes all twelve acceptance cases.

Python changes must also pass `ruff check .`; YAML changes must pass `yamllint -s .`, matching the hosted quality gate. Install these tools in the development environment before running them. After changing canonical skills or portable evidence sources, regenerate adapters with `make sync-agent-adapters` and the evidence bundle with `python scripts/agent/bundle_evidence.py`, then rerun validation.

Linux sandbox changes must also pass the real bubblewrap integration gate:

```bash
sudo apt-get install apparmor-profiles apparmor-utils bubblewrap util-linux
sudo install -m 0644 /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
python -m pytest -m linux_bubblewrap tests/integration/test_linux_bubblewrap_sandbox.py -q
```

These setup commands target Ubuntu 24.04, whose AppArmor user-namespace policy
otherwise blocks bubblewrap while it configures the isolated loopback interface.
Run the gate as a non-root user with unprivileged user namespaces enabled.
The hosted Ubuntu job treats a missing bubblewrap installation, blocked user
namespaces, or a failed readiness probe as a failure because production dispatch
must fail closed when these boundaries are unavailable.
The sandbox also requires the root-owned `/usr/bin/prlimit` from `util-linux`.
It applies the process-count limit inside the new namespace, immediately before
the adapter starts, so the host account's existing tasks cannot block namespace
creation on a shared runner.

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
10. **Plugin Test Suites** (`python3 -m cops check`): Runs declared offline verification suites across all 25 plugins.
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
   - `governance-compliance`

2. **Register the Package in `catalog/plugins.json`**:
   Add the plugin definition including its ID, name, version, category, maturity (`experimental`, `beta`, `stable`), and operational mode (`planned`, `guidance`, `import`, `laboratory`, `live-validated`).

3. **Create the Package Directory Structure**:
   Place the package at `plugins/<category>/<plugin-id>/` with:
   - `plugin.json`: Core Agent Plugins v1.0.0 manifest.
   - `README.md`: Overview, target practitioners, and prerequisites.
   - `docs/PLAYBOOK.md`: Step-by-step practitioner playbook.
   - `playbooks/offline-assessment.json`: Generated offline workflow contract.
   - `walkthroughs/offline-assessment.md`: Generated operator walkthrough.
   - `scripts/`: Standard-library Python validation and demo scripts.
   - `tests/`: Offline synthetic test data and unit tests.
   - `skills/`: Reusable agent skills conforming to `agentskills.io`.

4. **Generate Package Playbooks and Walkthroughs**:
   ```bash
   python3 scripts/generate_plugin_playbooks.py
   python3 scripts/generate_plugin_playbooks.py --check
   ```
   The generator refreshes package-owned offline workflow assets and their `docs/PLAYBOOK.md` links for all 25 packages. Generated files must be tracked by Git to appear in a portable export. Their presence documents an offline workflow; it is not evidence of laboratory execution or live integration.

   Portable packages may include approved, tracked assets under `examples/`, `playbooks/`, `walkthroughs/`, `datasets/`, `provenance/`, and `signatures/`. The exporter rejects symlinks and broken or escaping Markdown links.

5. **Regenerate Host Marketplaces**:
   ```bash
   python3 -m cops generate
   ```
   This updates `.github/plugin/marketplace.json`, `.claude-plugin/marketplace.json`, and `.agents/plugins/marketplace.json` automatically.

6. **Verify the New Package**:
   ```bash
   python3 -m cops validate <plugin-id>
   python3 -m cops demo <plugin-id>
   python3 -m cops check <plugin-id>
   make check PYTHON=.venv/bin/python
   ```

For complete authoring details, review [Adding a Plugin (docs/ADDING_A_PLUGIN.md)](ADDING_A_PLUGIN.md).

---

## Plugin verification and maturity

Every package also needs a [runnable practitioner workflow](plugin-playbacks.md).
Its README must explain the problem it solves, usage, design choices, and data
flow. Include schema tables that describe each artifact's purpose, fields,
producer, consumer, validation, and example. Link `docs/PLAYBOOK.md` and
`docs/VERIFICATION.md` from the README.

The manifest demo must run the actual package tools and assert expected domain
results, including a control or evidence-gap case and invalid-input behavior.
Document its exact `python3 -m cops demo <plugin-id>` command in the playbook and
link it from the shared workflow index. The catalog acceptance scenario runs
every demo twice; new entries are included automatically. Use package tests for
semantic comparisons when timestamps or workspace paths vary between runs.

Each package has a [verification playbook](plugin-verification.md) for its complete
user workflow. Include `docs/VERIFICATION.md` in new packages and link it from the
package README and shared index. Update its exercise, acceptance criteria,
negative/recovery cases, cleanup, and host instructions alongside behavior changes.

Use the [record template](templates/PLUGIN_VERIFICATION_RECORD.md) and shared
maturity gates before proposing a status update. The documentation check rejects
missing playbooks and public maturity labels that disagree with package manifests.
A passing CLI suite does not qualify a host installation or live integration.

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


Typed network changes require `tests/test_network_policy_inputs.py` and the
package correction demo, including vulnerable, corrected and incomplete inputs.
Synchronize all artifact runtimes after shared parser edits. Keep policy
predictions distinct from measured enforcement when recording laboratory readiness.

For typed TLS/JWT evidence, install the declared `crypto` extra and run
`python -m pytest -q tests/test_crypto_inputs.py tests/test_jwt_verification.py`.
Use ephemeral keys and public certificate fixtures; never commit private key
material or usable credentials. Run `tests/test_service_laboratory.py` and the
strict laboratory gate to compare offline outcomes with actual requests.

Workflow signing is also an explicit `crypto`-extra path. Do not add a runtime
crypto import to workflow startup: use a subprocess with site packages disabled
to cover workflow listing, catalog validation, and every unsigned fixture
playback profile. Keep real Ed25519 signing, invalid-key/signature, and
redaction tests in an environment where the extra is installed.

For Actions parser changes, run `tests/test_supply_chain_corrections.py` with
named, reordered and adjacent steps, block scalars, corrected refs and unsupported
input mappings. Regenerate portable artifact runtimes after changing the parser.
