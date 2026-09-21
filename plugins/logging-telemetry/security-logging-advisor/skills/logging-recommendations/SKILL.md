---
name: logging-recommendations
description: Analyze repository context and generate environment-specific, cost-conscious security logging recommendations.
---

# Logging Recommendations Advisor Skill

This skill analyzes the collected repository context and constructs a customized, tiered, and cost-aware security telemetry recommendation report.

## Trigger Instructions

Run this skill after the repository context has been collected and user clarifications have been addressed.

## Core Capabilities

1. **Gaps Analysis**: Match the detected tech stack against standard security logging matrices (e.g., OWASP, MITRE ATT&CK, cloud provider landing zones).
2. **Environment Calibration**:
   - **Sandbox**: Minimize ingestion cost, prioritize only critical error and security baseline telemetry.
   - **Development**: Support debugging and early threat signal identification with short-term retention.
   - **Integration**: Verify security-relevant flows and cross-service boundaries.
   - **Performance**: Suppress verbose log calls that distort performance tests; capture critical audit logs.
   - **Production**: Maximum telemetry, structured logs, strict retention, alert rules, and SIEM ingestion.
3. **Cost-Aware Optimization**:
   - Focus on high-signal logs (e.g., failed login attempts, configuration changes).
   - Sample or aggregate high-volume telemetry (e.g., database queries, network flow logs).
   - Discourage broad debug logging or raw payload logging.
4. **Structured Format**: Recommend JSON format with standard headers (e.g., Correlation IDs, Actor UUIDs, outcome codes, ISO 8601 UTC timestamps).

## Output Generation

Output the final report to `docs/security/logging-recommendations.md` matching the layout in `assets/logging-recommendations.md`.
