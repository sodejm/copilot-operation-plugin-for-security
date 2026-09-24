# Source and provenance register

The Workbench uses original hunt and query content informed by the sources
below. URLs record the design evidence and do not grant redistribution rights
for third-party text. No substantial third-party query is intentionally copied
into the package. Final release rights and license review is a separate,
content-addressed human evidence gate and is currently not implied by this
register.

## Microsoft execution surfaces

- [Microsoft Sentinel data lake sample queries](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-sample-queries) — examples of KQL hunting, anomaly, baseline, IOC, and cross-table patterns.
- [KQL queries in the Microsoft Sentinel data lake](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-queries) — surface-specific query behavior and constraints.
- [Defender XDR Advanced Hunting query language](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-language) — Advanced Hunting language and schema boundary.
- [Hunt for threats with Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/hunting) — Microsoft hunting workflow and product behavior.

## Hunting, incident response, and logging

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — incident-response integration with cybersecurity risk management.
- [Splunk PEAK Threat Hunting Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html) — vendor hunting workflow influence.
- [Elastic State of Detection Engineering](https://www.elastic.co/resources/security/report/state-of-detection-engineering-at-elastic) — detection-content lifecycle and organizational maturity guidance.
- [NSA and allied event-logging guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3880942/nsa-joins-allies-in-releasing-best-practices-for-event-logging/) — centralized logging and event-selection guidance.

## Threat modeling, analytics, and AI risk

- [MITRE ATT&CK Analytics](https://attack.mitre.org/analytics/) and [ATT&CK October 2025 update](https://attack.mitre.org/resources/updates/updates-october-2025/) — versioned Detection Strategy and Analytics mappings.
- [HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows](https://www.seclab.cs.sunysb.edu/seclab/pubs/holmes19.pdf) — peer-reviewed motivation for multi-stage correlation and provenance graphs; its measured results are not transferred to this package.
- [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) — generative-AI risk-management guidance.

## Platform packaging

- [OpenAI plugins](https://learn.chatgpt.com/docs/plugins), [building plugins](https://developers.openai.com/plugins/build/plugins), and [building skills](https://learn.chatgpt.com/docs/build-skills).
- [GitHub Copilot Agent Skills](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills) and [customization cheat sheet](https://docs.github.com/en/copilot/reference/customization-cheat-sheet).
- [Claude Code plugins](https://code.claude.com/docs/en/plugins) and [plugin reference](https://code.claude.com/docs/en/plugins-reference).

## Source-control provenance

Release reports bind every non-generated release-subject file to a SHA-256
digest. Generated adapter manifests record canonical skill hashes. Release
integrity evidence records the exact subject hash, SBOM, artifact manifest,
secret-scan result, and reproducible-build result. These records demonstrate
content identity; they do not establish third-party rights, tenant validation,
or operational effectiveness.
