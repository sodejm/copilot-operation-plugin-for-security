# Troubleshoot COPS Security Logging Advisor

## Local commands fail

Check `python3 --version` and confirm the target exists and is readable. Use
Python 3.11+ for contributor tooling. Invoking the scanner through Python does
not require an executable bit. From the COPS repository root:

```bash
python3 plugins/logging-telemetry/security-logging-advisor/scripts/validate-plugin.py
python3 plugins/logging-telemetry/security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py /path/to/repository
```

From a standalone portable package root, run `python3 scripts/validate-plugin.py`
and `python3 skills/repository-context/scripts/collect-repository-context.py
/path/to/repository`.

If `make check` reports missing pytest packages, activate the development virtual
environment and install `requirements.txt`. If adapters drift, edit the canonical
source in `.agents/skills/`, then run `make sync-agent-adapters`.

## The host does not discover the plugin

Check the installed host's current discovery rules and permissions. The local
validator checks repository structure; it cannot prove host compatibility. Use
the [local fallback](INSTALL.md) while recording a version-specific integration
issue. Do not assume organization-wide settings or automatic installation exist.

## Context or recommendations are incomplete

The scanner skips excluded directories and files over 1 MB, and limits the scan
to 10,000 files. Check target scope and permissions. Pattern-based detection can
miss technologies or secrets. The scanner emits JSON only; a report requires the
advisor instructions and a host with appropriate model and file-write access.
Review evidence and assumptions before acting on the report.
