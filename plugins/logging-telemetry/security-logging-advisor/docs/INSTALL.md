# Install and run COPS Security Logging Advisor

The package ID remains `security-logging-advisor`. Use Python 3.11+ for the
repository's supported contributor environment. The scanner and validator do not
need third-party runtime packages.

From the COPS repository root:

```bash
python3 plugins/logging-telemetry/security-logging-advisor/scripts/validate-plugin.py
python3 security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py .
```

Replace `.` in the second command with the repository to inspect. The scanner
writes context JSON to standard output; it does not generate recommendations or
modify the target. Review that context before sharing it with an assistant.

## Agent integration

Use the [advisor instructions](../com.github.copilot/agents/security-logging-advisor.agent.md) with
the [repository-context](../skills/repository-context/SKILL.md) and
[logging-recommendations](../skills/logging-recommendations/SKILL.md) product skills
in a host that supports those instruction and tool surfaces. The report target is
`docs/security/logging-recommendations.md` in the analyzed repository.

The checked-in manifests and marketplace metadata describe the package; local
validation checks their repository contract, not acceptance by a vendor registry.
Consult the current documentation for your installed Copilot or Claude version
before registering it. Record host version, discovery path, tool permissions and
a successful end-to-end run before declaring that integration supported. There
is no automatic registration or publication step in this repository.

For working on COPS itself, root `AGENTS.md`, `CLAUDE.md`, and
`.github/copilot-instructions.md` provide contributor guidance. Generated
`.claude/skills/` entries are contributor workflows, separate from product skills.
See [compatibility](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/COMPATIBILITY.md).
