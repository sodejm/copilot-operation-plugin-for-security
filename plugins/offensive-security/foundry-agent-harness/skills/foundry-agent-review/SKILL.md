---
name: foundry-agent-review
description: Inspect synthetic adversarial scenarios and deterministic mock authorization outcomes.
---

# Foundry Agent Harness scenario simulator

Use this skill to review the package's six offline scenarios and deterministic mock gate. This workflow does not call Microsoft Foundry, Semantic Kernel, a model, or a live agent. For process-backed local agent and MCP fixture cases, use the `ai-agent-mcp-laboratories` skill.

```bash
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py list \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios
python3 plugins/offensive-security/foundry-agent-harness/foundryharness/cli.py evaluate \
  --scenarios-dir plugins/offensive-security/foundry-agent-harness/scenarios \
  --json --output /tmp/cops-foundry-scenario-report.json
```

Interpret `model_response_summary` as simulator text, `attempted_tool_call` as a synthetic proposal, `denied_tool_call` as a local gate denial, and `executed_mock_effect` as an in-memory mock operation. These fields do not establish real-model behavior or live side effects. Use synthetic scenario content only. See `docs/PLAYBOOK.md` for the evidence rules.
