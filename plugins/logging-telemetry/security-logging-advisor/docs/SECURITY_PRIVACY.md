# COPS Security Logging Advisor security and privacy

The Python scanner and validator run locally and do not make model or network
calls. The assistant host may send prompts, repository context and tool results
to its configured provider. Review host permissions, provider policy and approved
data boundaries before an agent-assisted review; local scanning does not imply
that the complete agent workflow stays on the workstation.

Credential pattern findings report file paths, line numbers, issue types and
remediation guidance without matched secret values. This is a heuristic, not a
guarantee that every output is free of sensitive data. Paths, dependency names and
architecture metadata can themselves be confidential. Inspect context before
sharing and keep generated reports out of public commits unless reviewed.

Recommendations should use structured events, redact authorization headers,
cookies and credentials, and minimize personal identifiers. Prefer correlation
IDs and pseudonymous actor references; review retention and access controls for
the target environment. Sandbox, development and production recommendations
must balance security value, privacy and ingestion costs.

Scanner and model findings require human review. They do not certify compliance,
prove absence of vulnerabilities, or automatically implement changes. Report
product vulnerabilities through the [COPS security policy](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/SECURITY.md).
