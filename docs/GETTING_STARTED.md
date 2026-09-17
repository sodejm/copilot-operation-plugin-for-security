# Getting started with COPS

Install Python 3.11 or newer and Git. Make is optional; each target has a direct
Python equivalent in the [Makefile](../Makefile). No Node.js runtime is needed for
the scanner or validator.

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
make doctor
make check
```

On Windows use `.venv\Scripts\Activate.ps1` in PowerShell, then invoke
`python3 scripts/agent/check.py` if Make is unavailable. The complete check includes
pytest-bdd scenarios as well as standard-library tests. Python-only source,
contract and adapter checks need no third-party packages.

Read the [contributor contract](../AGENTS.md),
[plugin installation guide](../security-logging-advisor/docs/INSTALL.md), and
[compatibility boundaries](COMPATIBILITY.md). Start a focused branch, update
affected specifications before behavioral changes, and keep reports free of secrets.

After changing a canonical contributor skill, run:

```bash
make sync-agent-adapters
make check
```

No local hook, model provider, MCP server or publishing workflow is automatically
enabled by cloning COPS. Review example configurations before opting in.
