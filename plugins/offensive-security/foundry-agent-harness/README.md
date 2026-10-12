# Foundry Agent Harness

The Foundry Agent Harness provides offline, synthetic exercises for agent tool authorization. It does not connect to Microsoft Foundry, Semantic Kernel, a model, or a live MCP server. Its results describe the bundled fixtures and gates; they do not measure a deployed agent's prompt injection resistance.

The package has two workflows:

| Workflow | Command | Evidence |
| :--- | :--- | :--- |
| Scenario simulator | `evaluate` | A deterministic scenario decision, authorization decision, and in-memory mock ledger. This legacy workflow does not execute an agent process or model. |
| Local agent and MCP laboratory | `lab` | A deterministic agent fixture proposes calls to a separate, fixed MCP stdio fixture. The runner records proposals, gate denials, calls actually forwarded, observed state effects, and reset verification. |

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.

## Run the local laboratory

From the repository root:

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab
```

Generate a versioned JSON report:

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py lab \
  --json --output /tmp/cops-agent-mcp-lab-report.json
```

Use `--cases path/to/case.json` for one case, or `--cases path/to/directory` for a directory. Case inputs follow `schemas/lab-case.schema.json`; output follows `schemas/lab-report.schema.json`. The 13 bundled cases cover retrieved content, tool responses, tenant boundaries, peer messages, state change, exfiltration, memory, context, tool permission, and authorized controls. A permissive synthetic baseline executes a resource change; its paired strict case denies the same proposed call.

For each case, read `model_text`, `attempted_calls`, `denied_calls`, `executed_calls`, and `executed_effects` separately. A proposed call is not an executed call. An executed read need not change state. Effects come from the fixture's observed before and after state. The runner resets and compares the complete MCP state, including any injected tool response note, with the state before case setup. It reports `cleanup_verified`; an unmet expected outcome or failed verification exits nonzero.

The fixed fixture processes have bounded stdio responses and run in a temporary directory. They use only synthetic accounts, resources, and canary data. The process boundary is not an operating-system network sandbox. The report includes case text and arguments, so use synthetic inputs only; do not supply credentials, private data, or live endpoints. The runner accepts no user-selected process command or network destination.

## Run the scenario simulator

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py list \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py evaluate \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios \
  --json --output /tmp/cops-foundry-scenario-report.json
```

The six legacy scenarios use a deterministic simulator and an in-memory mock sandbox. The `model_response_summary` field is simulator text, despite its historical schema name. An `executed_mock_effect` is a local mock effect, not evidence of a real agent action. The simulator's rollback ledger does not apply to the separate MCP laboratory; the laboratory verifies a fixture reset after each case.

See [the analyst playbook](docs/PLAYBOOK.md) for interpreting both workflows. The repository specification is `specs/agent-mcp-laboratories.spec.md`. Validate with `python3 plugins/offensive-security/foundry-agent-harness/scripts/validate_package.py` and `python3 -m cops check foundry-agent-harness`.
