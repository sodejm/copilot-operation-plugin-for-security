# COPS Security Logging Advisor

The **Security Logging Advisor** inspects your codebase's logging configuration and provides prioritized, actionable recommendations to improve security telemetry. Whether you're preparing for a compliance audit (SOC 2, PCI-DSS) or closing forensic blind spots after a security review, this advisor helps developers and security engineers implement structured, audit-ready logging on Day 1.

It is the primary logging and telemetry package in the Copilot Operations Plugin for Security (COPS) collection.

---

Follow the [end-to-end verification playbook](docs/VERIFICATION.md) to qualify this
package's documented workflow and prepare evidence for a maturity review.

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

To exercise the collector directly and validate a manually authored recommendation
template, run the deterministic manifest playback from the repository root:

```bash
python3 plugins/logging-telemetry/security-logging-advisor/scripts/run_playback.py
```

The playback scans a disposable synthetic repository twice, checks the collector's
semantic repeatability, validates the recommendation document's
required structure, and exercises partial-scan and malformed-recommendation failure
paths. The validator checks required structure; it does not generate or
approve an LLM verdict. See the [playbook](docs/PLAYBOOK.md#deterministic-manifest-playback)
for the data contract and interpretation.

## Design and data flow

The collector turns a bounded source tree into an inventory of logging frameworks
and security-event coverage. A separate advisory step consumes that inventory and
authors recommendations; the playback supplies a synthetic recommendation so it
can verify the contract without presenting generated advice as an analyst verdict.

| Contract or artifact | Purpose | Key fields | Producer | Consumer | Validation | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Source tree | Bound the files inspected for logging evidence | Relative path, file type, size | Operator or playback fixture | Offline collector | Containment, file-size, and supported-type gates | Synthetic service with an authentication handler |
| Scan inventory | Record observed frameworks and missing security events | Files scanned, frameworks, event coverage, partial-scan status | Offline collector | Advisor workflow and reviewer | Schema checks plus repeatable semantic comparison | Authentication failures absent from the fixture |
| Recommendation document | Capture prioritized, evidence-linked advice | Priority, evidence reference, recommendation, event schema | Advisor workflow; a fixed fixture in playback | Engineer or security reviewer | Required structure and evidence-reference checks | P1 structured authentication-failure event |
| Playback summary | Record qualification assertions without retaining the temporary tree | Repeatability, failure-path results, artifact counts | `scripts/run_playback.py` | Maintainer | Explicit semantic assertions; any mismatch exits nonzero | `semantic_repeatability: true` |

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
