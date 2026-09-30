# COPS MITRE ATT&CK Coverage Matrix

> [!IMPORTANT]
> ATT&CK mappings represent **planning evidence and investigative structure**, not proof of control
> effectiveness. Coverage claims distinguish between verified analytics and unverified proposals.
> Match criteria retain uncertainty, and reports never assume absence of alerts indicates absence of adversary activity.

## Summary Metrics

| Metric | Count | Description |
| :--- | :--- | :--- |
| **Total Mappings** | 22 | Total capability-to-technique associations |
| **Distinct Techniques** | 15 | Unique ATT&CK techniques and sub-techniques |
| **Validated Analytics** | 21 | Backed by automated deterministic offline test fixtures |
| **Unverified / Experimental** | 1 | Draft analytics without automated test verification |
| **Detective Coverage** | 14 | Threat hunting and detection engineering queries |
| **Investigative Coverage** | 6 | Deep-dive triage, entity tracing, and path analysis |
| **Preventive Coverage** | 1 | Telemetry posture and configuration recommendations |
| **Response Coverage** | 1 | Incident timeline and case handoff workflows |

## Capabilities and Techniques

| Technique ID | Technique Name | Tactic | Capability | Evidence Source | Role | Validation | Key Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [`T1114.003`](https://attack.mitre.org/techniques/T1114/003/) | Email Forwarding Rule | `collection` | `sentinel-hunt-workbench`<br>(H07) | Microsoft 365: `OfficeActivity` | `detection` | **Validated** | Authorized business forwarding rules require analyst confirmation |
| [`T1213.002`](https://attack.mitre.org/techniques/T1213/002/) | SharePoint | `collection` | `sentinel-hunt-workbench`<br>(H08) | Microsoft 365: `OfficeActivity` | `detection` | **Validated** | OneDrive sync engine performs bulk operations during initial machine con... |
| [`T1530`](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | `collection` | `sentinel-hunt-workbench`<br>(H-PREVIEW-STORAGE) | Azure: `StorageBlobLogs` | `detection` | *Unverified (Draft)* | Experimental draft query without deterministic test fixture verification |
| [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | `command-and-control` | `sentinel-hunt-workbench`<br>(H04) | Defender for Endpoint: `DeviceNetworkEvents` | `detection` | **Validated** | High-volume web browsing and SaaS integrations create noisy baseline tra... |
| [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | `command-and-control` | `sentinel-hunt-workbench`<br>(H06) | Defender for Endpoint: `DeviceNetworkEvents` | `detection` | **Validated** | Jitter algorithms or long sleep timers bypass interval heuristics |
| [`T1105`](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | `command-and-control` | `sentinel-hunt-workbench`<br>(H03) | Defender for Endpoint: `DeviceFileEvents` | `detection` | **Validated** | Legitimate software updates routinely download files to temporary direct... |
| [`T1110.003`](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | `credential-access` | `sentinel-hunt-workbench`<br>(H01) | Sentinel: `SigninLogs` | `detection` | **Validated** | NAT or proxy concentration can aggregate distinct failures |
| [`T1078`](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `defense-evasion` | `sentinel-hunt-workbench`<br>(H02) | Sentinel: `SigninLogs` | `detection` | **Validated** | VPN roaming and legitimate travel can trigger anomalous location alerts |
| [`T1078`](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `defense-evasion` | `soc-investigation-workbench`<br>(export-handoff) | Sentinel: `SigninLogs` | `response` | **Validated** | Produces structured reporting; does not perform active tenant remediation |
| [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | `defense-evasion` | `security-logging-advisor`<br>(logging-recommendations) | Azure: `DiagnosticSettings` | `prevention` | **Validated** | Checks static telemetry policies; does not monitor real-time sensor tamp... |
| [`T1059`](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | `execution` | `sentinel-hunt-workbench`<br>(H03) | Defender for Endpoint: `DeviceProcessEvents` | `detection` | **Validated** | Administrative automation and orchestration scripts can match heuristic ... |
| [`T1078`](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `initial-access` | `sentinel-hunt-workbench`<br>(H01) | Sentinel: `SigninLogs` | `investigation` | **Validated** | A successful authentication following spray failures is consistent with ... |
| [`T1078`](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `initial-access` | `soc-investigation-workbench`<br>(intake) | Sentinel: `SigninLogs` | `investigation` | **Validated** | Requires UTC timestamp normalization and consistent entity hashing acros... |
| [`T1566.002`](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | `initial-access` | `sentinel-hunt-workbench`<br>(H09) | Defender for Office 365: `UrlClickEvents` | `detection` | **Validated** | Automated mail gateway scanners and link evaluation bots can produce cli... |
| [`T1021`](https://attack.mitre.org/techniques/T1021/) | Remote Services | `lateral-movement` | `sentinel-hunt-workbench`<br>(H11) | Defender for Endpoint: `DeviceNetworkEvents` | `detection` | **Validated** | Systems administrators routinely use these ports for fleet maintenance |
| [`T1098`](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | `persistence` | `sentinel-hunt-workbench`<br>(H12) | Sentinel: `AuditLogs` | `detection` | **Validated** | DevOps automation regularly creates and updates service principal creden... |
| [`T1098`](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | `persistence` | `entra-identity-workbench`<br>(HYP-FED-WILDCARD) | Entra ID: `AuditLogs` | `investigation` | **Validated** | Evaluates offline export state; does not verify live token exchange events |
| [`T1547.001`](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | `persistence` | `sentinel-hunt-workbench`<br>(H05) | Defender for Endpoint: `DeviceRegistryEvents` | `detection` | **Validated** | Approved endpoint software and updater agents regularly update run keys |
| [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | `privilege-escalation` | `sentinel-hunt-workbench`<br>(H12) | Sentinel: `SigninLogs` | `investigation` | **Validated** | Sign-ins from automated jobs cannot be distinguished from attacker use w... |
| [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | `privilege-escalation` | `entra-identity-workbench`<br>(HYP-AGENT-MISMATCH) | Entra ID: `AuditLogs` | `investigation` | **Validated** | Identifies structural over-privilege; does not prove agent tool misuse |
| [`T1098.003`](https://attack.mitre.org/techniques/T1098/003/) | Additional Cloud Roles | `privilege-escalation` | `sentinel-hunt-workbench`<br>(H10) | Sentinel: `AuditLogs` | `detection` | **Validated** | Eligible PIM role assignments must be separated from standing administra... |
| [`T1098.003`](https://attack.mitre.org/techniques/T1098/003/) | Additional Cloud Roles | `privilege-escalation` | `attack-path-workbench`<br>(attackpath) | Azure: `RoleAssignments` | `investigation` | **Validated** | Establishes structural reachability, not active adversary execution or e... |

## Review Workflow & Maintenance

1. **Updating Mappings**: Modify `catalog/attack_coverage.json` and validate with `python3 -m cops coverage --check`.
2. **Evidence Boundaries**: Do not promote an analytic from `unverified` to `validated` without specifying a reproducible test fixture in `validation_fixture`.
3. **Version Synchronization**: Mappings target the pinned ATT&CK version (Enterprise v18.0). Deprecated or revoked objects are rejected by the validation gate.

