# COPS SOC Investigation Workbench

The **SOC Investigation Workbench** helps security analysts investigate complex, ambiguous security alerts methodically without succumbing to alert fatigue or confirmation bias.

During high-pressure incident triage, it is easy to latch onto an initial theory and miss alternative explanations—such as mistaking an approved internal developer integration for an attacker's rogue OAuth application. This workbench provides a structured investigative framework: it maintains **competing hypotheses**, tracks explicit evidence associations, builds a dependency graph of findings, and dynamically ranks the **highest-gain next questions** to query in your telemetry.

The workbench operates completely offline with Python 3.10+ and requires zero runtime dependencies, credentials, or cloud access.

---

## When to Use & SOC Analyst Playbook

For end-to-end investigation workflows, evidence collection tips, and case handoffs, see the complete [SOC Analyst Playbook](docs/PLAYBOOK.md).

Use this workbench when:
- **Investigating complex, multi-entity alerts**: Triaging ambiguous OAuth consent events, credential spills, or privilege escalation across users and service principals.
- **Countering confirmation bias**: Actively tracking competing hypotheses (e.g., malicious account takeover vs. authorized IT administration).
- **Ranking next investigative questions**: Determining the highest-value log queries to execute when faced with dozens of possible leads.
- **Structuring incident handoffs & post-mortems**: Exporting complete, immutable evidence chains and explicitly documenting unresolved uncertainties.

---

## Interactive Walkthrough (Offline Demo)

You can run through an entire simulated investigation using the included synthetic case and evidence snippets:

```bash
# Run from the soc-investigation-workbench directory:
# 1. Validate the initial case structure
python3 scripts/investigate.py validate examples/case.json

# 2. View the ranked next questions to investigate
python3 scripts/investigate.py next examples/case.json

# 3. Import sign-in telemetry results into a new case snapshot
python3 scripts/investigate.py import examples/case.json examples/signin-result.json --out /tmp/soc-case-01.json

# 4. Import OAuth application consent evidence
python3 scripts/investigate.py import /tmp/soc-case-01.json examples/consent-result.json --out /tmp/soc-case-02.json

# 5. Record an unmonitored mailbox gap and view the updated investigation report
python3 scripts/investigate.py import /tmp/soc-case-02.json examples/mailbox-gap.json --out /tmp/soc-case-03.json
python3 scripts/investigate.py report /tmp/soc-case-03.json
```

### What to look for
- **Immutable Snapshots**: Each `import` command produces a new, immutable snapshot file without modifying the original.
- **Privacy by Default**: Generated snapshot files are written with restricted POSIX permissions (`0600`) so other users on your machine cannot inspect sensitive investigation notes.
- **Explicit Uncertainty**: Notice how the final report preserves conflicting assessments and clearly flags the unavailable mailbox telemetry rather than glossing over missing evidence.

---

## Skills & Host Discovery

The workbench provides two canonical skills:
1. `soc-investigation-planning`: Formulates hypotheses, structures entities, and ranks next investigative questions.
2. `soc-investigation-review`: Audits case logic, checks for missing alternative hypotheses, and verifies evidence links.

The plugin can be loaded directly into GitHub Copilot, Claude Code, or OpenAI Codex using the portable `plugin.json` or `.claude-plugin/` manifests.

---

## Documentation & Methodology

- [SOC Analyst Playbook](docs/PLAYBOOK.md): Practical triage playbooks and investigative methodology.
- [Case Workflow & JSON Contracts](docs/workflow.md): Detailed schemas for cases, entities, observations, and hypotheses.
- [Validation Guide](docs/validation.md): Executable acceptance scenarios and test specifications.
- [Ownership & Updates](docs/ownership.md): How hunt workflows link with the Sentinel Hunt Workbench.

---

## Evidence & Practical Boundaries

The SOC Investigation Workbench is an analyst-led decision support system. It records and structures your observations, but **you remain the investigator**:
- You run the queries in your authorized SIEM, EDR, or identity portals.
- You import redacted observations and link them to entities.
- The tool does not autonomously quarantine hosts, disable accounts, or declare final verdicts.

### License
Offered under the [PolyForm Noncommercial License 1.0.0](LICENSE).
