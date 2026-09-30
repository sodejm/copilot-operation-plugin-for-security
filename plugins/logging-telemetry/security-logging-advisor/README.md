# COPS Security Logging Advisor

The **Security Logging Advisor** inspects your codebase's logging configuration and provides prioritized, actionable recommendations to improve security telemetry. Whether you're preparing for a compliance audit (SOC 2, PCI-DSS) or closing forensic blind spots after a security review, this advisor helps developers and security engineers implement structured, audit-ready logging on Day 1.

It is the primary logging and telemetry package in the Copilot Operations Plugin for Security (COPS) collection.

---

## Quick Test Drive (Offline Demo)

You can test drive the advisor right now from the repository root—no cloud credentials, API keys, or external dependencies required:

```bash
# Run the quick offline demonstration
python3 -m cops demo security-logging-advisor

# Run the complete package validation check
python3 -m cops check security-logging-advisor
```

### What to look for
Running the demo scans a realistic synthetic application fixture and generates an evidence-linked recommendations report. It flags missing audit events (such as authentication failures, password resets, and permission changes) and suggests structured JSON event schemas. Because this runs completely offline, you can safely explore how the advisor works before scanning your own codebase.

---

## When to Use & Engineering Playbook

For step-by-step guidance, common pitfalls, and real-world logging patterns, check out the [Analyst & Engineer Playbook](docs/PLAYBOOK.md).

Use this advisor when:
- **Onboarding new microservices**: Establishing auditable, structured JSON telemetry from the very first commit.
- **Remediating post-incident gaps**: Closing forensic blind spots after an alert or incident investigation.
- **Preparing for compliance audits**: Satisfying SOC 2 CC6.8, PCI-DSS v4.0 Req 10, or ISO 27001 audit trail requirements.
- **Migrating to structured logging**: Transitioning legacy text logs to modern frameworks like Pino, structlog, or Zap.
- **Assessing CVE reachability**: Verifying whether vulnerable dependency calls execute and generate audit trails.

---

## Using in an AI Assistant Host

The advisor is designed to run seamlessly across GitHub Copilot, Claude Code, and OpenAI Codex.
- To set it up in your favorite assistant, follow the [Installation Guide](docs/INSTALL.md).
- Before scanning production code, review our [Security and Privacy Guide](docs/SECURITY_PRIVACY.md).
- For enterprise security teams deploying the advisor across multiple engineering squads, see the [Enterprise Rollout Guide](docs/ENTERPRISE_ROLLOUT.md).

Package metadata is maintained in [plugin.json](plugin.json). Host-specific compatibility manifests are generated automatically to prevent configuration drift.

---

## Contributor & Maintainer Workflow

If you are contributing new rules or updating scanner logic, run these checks from the repository root:

```bash
python3 -m cops validate
python3 -m cops generate --check
python3 -m cops check security-logging-advisor
```

See [Maintainers](docs/MAINTAINERS.md) for package-specific release guidelines. For repository-wide contribution standards, see [`docs/ADDING_A_PLUGIN.md`](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/ADDING_A_PLUGIN.md).

---

## Evidence & Verification Boundaries

All generated recommendations are advisory and designed to empower engineers. An offline fixture scan proves that the advisor's rule engine and schemas are functioning correctly. However, an offline test cannot verify whether your production SIEM is successfully receiving events or whether custom framework wrappers drop fields at runtime. Always verify live telemetry in your staging or development environment.
