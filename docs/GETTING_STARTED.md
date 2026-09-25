# Getting started with COPS

This guide gets a security engineer from a fresh clone to a useful, reviewable
offline result. It does not require an assistant host, cloud account, or tenant.

## 1. Verify the local environment

Install Python 3.11 or newer, clone the repository, and run:

```bash
python3 -m cops doctor
```

Acceptance criteria:

- the command exits successfully;
- it reports Python 3.11 or newer;
- it reports four catalog packages and current generated indexes;
- it states that host installation and live-service behavior are separate gates.

## 2. Choose a capability

```bash
python3 -m cops list
python3 -m cops info security-logging-advisor
python3 -m cops info soc-investigation-workbench
python3 -m cops info sentinel-hunt-workbench
python3 -m cops info attack-path-workbench
```

The table deliberately separates four questions: whether the package structure is
valid, whether its offline workflow is validated, whether installation in an
assistant host is validated, and whether a live integration is validated.

Choose based on the task:

| Goal | Package |
| --- | --- |
| Inspect repository technology and logging signals | `security-logging-advisor` |
| Plan and review a bounded investigation from redacted evidence | `soc-investigation-workbench` |
| Explain or stress-test Microsoft Sentinel hunt content offline | `sentinel-hunt-workbench` |
| Trace conditional paths from illustrative local exports to a user-defined crown jewel | `attack-path-workbench` |

Acceptance criteria:

- all four IDs appear in `list`;
- each `info` result includes purpose, maturity, limitations, and all support states;
- no package is presented as live or host-validated unless evidence supports it.

## 3. Run a safe demonstration

```bash
python3 -m cops demo security-logging-advisor
python3 -m cops demo soc-investigation-workbench
python3 -m cops demo sentinel-hunt-workbench
python3 -m cops demo attack-path-workbench
```

Each command is declared by its package, invokes a repository-owned Python script
without a command shell, stays inside the package directory, and has a bounded
timeout. The examples use the repository or synthetic data. Review output before
using it in an investigation or sharing it with another system.

Acceptance criteria:

- each demo exits successfully on a clean clone;
- the logging demo emits repository context JSON;
- the SOC demo validates the synthetic case and prints its content-addressed state;
- the Sentinel demo explains hunt `H01` and its evidence contract;
- the attack-path demo prints a blocked query intent without contacting Wiz;
- no demo requires credentials or writes to a security service.

## 4. Validate what you intend to use

Validate package metadata only:

```bash
python3 -m cops validate sentinel-hunt-workbench
```

Run all deterministic checks declared by one package:

```bash
python3 -m cops check sentinel-hunt-workbench
```

Run all package checks:

```bash
python3 -m cops check
```

The Sentinel check validates 12 hunt definitions, runs the deterministic curated,
perturbation, and semantic-mutation suites, and verifies generated adapter hashes.
It is still an offline reference evaluation, not a Kusto engine or tenant test.

## 5. Use a package with an assistant

Start with the selected package's `README.md` and the relevant `skills/*/SKILL.md`.
Generated marketplace files can help compatible hosts discover package locations,
but cloning the repository does not automatically install or enable a plugin. Check
the current documentation for your host, review requested permissions, and record a
host-specific smoke test before changing `host_installation` evidence.

## Contributor setup

Third-party dependencies are needed only for the full test suite:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m cops doctor --contributor
make check
```

On Windows, activate `.venv\Scripts\Activate.ps1`. If Make is unavailable, run
`python3 scripts/agent/check.py`. Contributor validation includes contract checks,
generated-index drift checks, package checks, unit tests, and executable BDD
acceptance scenarios.

When adding a capability, follow [Adding a Plugin](ADDING_A_PLUGIN.md). When changing
a canonical contributor skill under `.agents/skills/`, also run:

```bash
make sync-agent-adapters
make check
```

No local hook, model provider, MCP server, marketplace publication, or hosted
integration is enabled automatically by cloning COPS.
