# Security model

## Assets

- source code, history, releases, and package integrity;
- credentials and hosted-service authority;
- user, customer, and test data;
- developer machines and CI runners;
- agent instructions, skills, MCP servers, hooks, and generated evidence.

## Trust boundaries

Repository content crosses into agent context; agent output crosses into files and
commands; tools cross into the local machine and external services; pull requests
and dependencies cross from external contributors; CI crosses into protected
tokens and release systems.

## Primary threats

- prompt injection in issues, documentation, dependencies, web pages, or tool data;
- malicious or compromised skills, plugins, hooks, MCP servers, and actions;
- secret or private-data disclosure through logs, prompts, diffs, or evidence;
- excessive permissions and unauthorized external mutations;
- dependency substitution, mutable automation references, and generated-file drift;
- destructive commands, path traversal, shell injection, or unsafe target handling;
- false assurance from source reasoning, skipped tests, stale hosted state, or a
  pushed-but-unmerged artifact.

## Baseline controls

- human instructions and repository policy bound authority;
- canonical files are reviewable and protected with CODEOWNERS as the project grows;
- contributors inspect and preserve existing work before scoped changes;
- adapters are generated and drift-checked;
- workboard state stays outside the working tree, uses owner-only local permissions
  where supported, and is limited to bounded coordination metadata;
- hooks are optional while CI repeats invariants;
- secrets remain outside Git and evidence is sanitized;
- MCP tools use strict schemas and least privilege;
- validation and delivery states are reported precisely;
- dependency, action, and plugin provenance is reviewed before adoption.

## Local audit data

The `session-usage-audit` helpers treat Git and session content as untrusted
evidence. They statically parse supported edits without evaluating transcript
code or running recorded commands. Audits are read-only against source
repositories and sessions, and require no network service or model calls.
Git-only mode does not discover or read session files.

Reports exclude raw code, patch bodies, commands, prompts, and transcript bodies.
They still include local paths, repository and task identifiers, and usage
metadata. Keep them and local configuration private. New report files use
owner-only permissions on POSIX systems; stdout and caller-managed redirection
follow the caller's permissions. Audited worktrees, shared Git directories, and
the configured Codex session trees cannot be report destinations. When selecting
individual session files with `--path`, keep reports outside their source
directories as well.

The distributed skill has an empty repository configuration and synthetic tests.
COPS ignores `*.local.json`, `churn-v*.json`, and `churn-v*.md` in Git and excludes
them from generated skill copies. These filename rules are accidental
disclosure guards, not content sanitizers: renamed reports, excerpts, and other
exports still require review before sharing.

## Residual risk

The [SOC investigation case engine](../soc-investigation-workbench/docs/workflow.md)
accepts analyst-redacted observations without executing their text or running
queries. It enforces tenant/workspace/time scope, rejects conflicting provenance,
and writes new snapshots with owner-only permissions. Reports omit evidence prose.
These controls do not sanitize inputs, establish truth, or secure the host model.
Vendored Sentinel integrity gates handoffs; file hashes detect drift, not a
malicious replacement of both the snapshot and its lock. Actual Sentinel
integration and hunt qualification remain pending.

COPS cannot control a client's hidden system instructions, model behavior, sandbox,
account permissions, context truncation, or support for a standard. Human review,
branch protection, CI, environment isolation, and least-privileged credentials
remain necessary.
