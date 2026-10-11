---
layout: documentation
title: "Getting Started with COPS"
description: "Go from a fresh repository clone to running verified, offline-first cybersecurity tools, demos, and specialist agent routing in under five minutes."
---

# Getting Started with COPS

Welcome to **COPS (Copilot Operations Plugins for Security)**! This guide takes you from a fresh clone to running real, verified cybersecurity tools in under five minutes.

Everything in this guide runs **100% offline** on your local machine using standard Python. You do not need an active cloud subscription, API tokens, or an AI assistant installed to explore, test, and validate these tools.

---

## Prerequisites

COPS requires only **Python 3.11 or newer**. That's it!

- No external pip dependencies are needed for running the CLI, doctor, demos, or offline plugin checks.
- Optional contributor dependencies (for running the full repository test suite) are specified in `requirements.txt`.
- Signed laboratory receipt verification requires the optional `laboratory` extra (`python -m pip install '.[laboratory]'`).

---

## Five-Minute Quickstart

Open your terminal and run these commands from the repository root:

```bash
# 1. Clone the repository and navigate into it
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security

# 2. Check local environment health and catalog synchronization
python3 -m cops doctor

# 3. List all 13 plugins and their validation status
python3 -m cops list

# 4. Inspect details and operational playbooks for a specific plugin
python3 -m cops info sentinel-hunt-workbench

# 5. Route a natural language security task to the best specialist agent
python3 -m cops route "Optimize Microsoft Sentinel KQL query for sign-in anomalies"

# 6. Run a safe, offline demonstration using synthetic test data
python3 -m cops demo sentinel-hunt-workbench

# 7. Run the plugin's deterministic verification suite
python3 -m cops check sentinel-hunt-workbench
```

---

## Step 1: Environment Diagnostics (`cops doctor`)

Before using the catalog, verify your environment:

```bash
python3 -m cops doctor
```

### What `cops doctor` checks:
1. **Python Interpreter**: Confirms that your active Python interpreter is version 3.11 or newer.
2. **Catalog Integrity**: Verifies that all 13 package manifests match their catalog declarations.
3. **Marketplace Synchronization**: Ensures that generated host indexes (`.github/plugin/marketplace.json`, `.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json`) are in sync with `catalog/plugins.json`.
4. **Offline Readiness**: Confirms that local tools execute without unverified external network requirements.

If any check reports an issue, the output provides clear, actionable instructions on how to resolve it. See the [Troubleshooting Guide](troubleshooting.md) for detailed help.

---

## Step 2: Exploring the Plugin Catalog (`cops list` & `cops info`)

COPS packages 13 dedicated security plugins across defensive and offensive domains. To view the full catalog:

```bash
python3 -m cops list
```

The output displays each plugin's name, category, maturity stage (`stable`, `beta`, `experimental`), and validation status:

```text
PLUGIN                          CATEGORY                  MATURITY      OFFLINE    HOST        LIVE          
------------------------------  ------------------------  ------------  ---------  ----------  --------------
security-logging-advisor        logging-telemetry         stable        validated  unverified  not_applicable
soc-investigation-workbench     detection-hunting         beta          validated  unverified  unverified    
sentinel-hunt-workbench         detection-hunting         beta          validated  unverified  unverified    
attack-path-workbench           detection-hunting         experimental  validated  unverified  unverified    
attack-surface-planner          offensive-security        experimental  validated  unverified  unverified    
entra-identity-workbench        identity-access           beta          validated  unverified  unverified    
exposure-triage-workbench       vulnerability-management  beta          validated  unverified  unverified    
foundry-agent-harness           offensive-security        beta          validated  unverified  unverified    
detection-quality-workbench     detection-hunting         beta          validated  unverified  unverified    
patch-security-review           vulnerability-management  beta          validated  unverified  unverified    
threat-intelligence-enrichment  detection-hunting         experimental  validated  unverified  unverified    
telemetry-proof-pack            logging-telemetry         beta          validated  unverified  unverified    
incident-response-sandbox       incident-response         experimental  validated  unverified  unverified    
```

To view in-depth details, operational playbooks, and limitations for any specific plugin:

```bash
python3 -m cops info security-logging-advisor
python3 -m cops info soc-investigation-workbench
python3 -m cops info sentinel-hunt-workbench
```

For recommendations on when to reach for each plugin, consult the [Plugin Selection Guide](plugin-guide.md).

---

## Step 3: Routing Tasks with Specialist Agents (`cops route`)

COPS includes 18 specialist cybersecurity agent profiles. The deterministic, zero-token router matches any natural language task or security question to the most qualified specialist profile:

```bash
# Example 1: Detection Engineering
python3 -m cops route "Review this Sentinel KQL query for high ingestion volume"

# Example 2: Identity & Access Management
python3 -m cops route "Audit Entra ID application registrations with high-privilege permissions"

# Example 3: Incident Response & Forensics
python3 -m cops route "Rehearse containment of a compromised service principal with blast radius proof"
```

To list all 18 specialist profiles and their domain specializations:

```bash
python3 -m cops specialists
```

For high-risk operations (e.g. penetration testing, red team emulation, active containment rehearsal), COPS automatically activates **Triad Orchestration** (Primary Specialist + Domain Skeptic + Evidence Auditor) with mandatory interactive operator approval. See [Specialist Agents](specialist-agents.md) for details.

---

## Step 4: Running Safe Offline Demos (`cops demo`)

Every plugin includes a self-contained, offline demonstration that exercises real operational logic against synthetic local test data:

```bash
# 1. Audit code for logging gaps and sensitive data leaks
python3 -m cops demo security-logging-advisor

# 2. Walk through a structured SOC investigation with competing hypotheses
python3 -m cops demo soc-investigation-workbench

# 3. Explain Sentinel KQL hunt workflows and evidence contracts
python3 -m cops demo sentinel-hunt-workbench

# 4. Trace cloud lateral movement paths to crown jewels
python3 -m cops demo attack-path-workbench

# 5. Build an authorized, passive attack surface review plan
python3 -m cops demo attack-surface-planner
```

### Why these demos are safe:
- **Zero Network Calls**: All processing operates exclusively on local synthetic test fixtures.
- **No Remote Writes**: Demos never transmit data, make cloud API calls, or mutate live services.
- **No Subshell Execution**: Commands execute strictly via explicit Python argument vectors, preventing shell injection vulnerabilities.

---

## Step 5: Validating Package Integrity (`cops check`)

To verify the code correctness, schemas, and regression tests of a plugin locally:

```bash
# Check a single package
python3 -m cops check sentinel-hunt-workbench

# Check all 13 packages
python3 -m cops check
```

Passing checks verify deterministic logic, contract schemas, and offline regression suites.

---

## Next Steps

- Consult the [Plugin Selection Guide](plugin-guide.md) to choose the right plugin for your operational needs.
- Explore the [18 Specialist Agent Profiles](specialist-agents.md) and Triad orchestration.
- Read the [ATT&CK Matrix (v18.0)](COVERAGE_MATRIX.md) for mapped defensive techniques.
- Set up a contributor environment with the [Contributor Guide](contributing.md).
- Resolve any environment questions with the [Troubleshooting Guide](troubleshooting.md).
