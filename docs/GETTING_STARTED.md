# Getting Started with COPS

Welcome! This guide is designed to take you from a fresh repository clone to running real, verified cybersecurity tools in under five minutes.

Everything in this guide runs **100% offline** on your local machine using standard Python. You do not need an active cloud subscription, API tokens, or an AI assistant installed to explore and test these tools.

---

## 1. Check Your Local Setup

Before diving in, make sure you have **Python 3.11 or newer** installed. Run the built-in diagnostic tool from the repository root:

```bash
python3 -m cops doctor
```

### What to look for
- **Python version**: You should see your Python interpreter confirmed as 3.11 or newer.
- **Catalog health**: Confirms that all thirteen security plugins and host marketplaces are synchronized.
- **Offline status**: Confirms that local tools run without external network dependencies.

If any check reports an issue, the output will give you clear, actionable instructions on how to resolve it.

---

## 2. Choose the Right Tool for the Job

COPS packages thirteen dedicated security plugins across defensive and offensive domains. To see the full catalog and current validation status, run:

```bash
python3 -m cops list
```

To view in-depth details, operational playbooks, and limitations for any specific plugin, run `cops info <plugin-id>`:

```bash
python3 -m cops info security-logging-advisor
python3 -m cops info soc-investigation-workbench
python3 -m cops info sentinel-hunt-workbench
python3 -m cops info attack-path-workbench
python3 -m cops info attack-surface-planner
python3 -m cops info entra-identity-workbench
python3 -m cops info exposure-triage-workbench
python3 -m cops info foundry-agent-harness
python3 -m cops info detection-quality-workbench
python3 -m cops info patch-security-review
python3 -m cops info threat-intelligence-enrichment
python3 -m cops info telemetry-proof-pack
python3 -m cops info incident-response-sandbox
```

### Quick Selection Matrix

| What are you trying to accomplish? | Reach for this plugin | Key capability |
| :--- | :--- | :--- |
| **Audit code for logging gaps and sensitive data leaks** | `security-logging-advisor` | Context collection, security event gap analysis, and CVE reachability. |
| **Investigate a complex alert or incident with rival hypotheses** | `soc-investigation-workbench` | Competing hypotheses, inquiry ranking, and evidence dependency graphs. |
| **Author, adapt, or stress-test Microsoft Sentinel & Defender KQL** | `sentinel-hunt-workbench` | 12 defensive threat hunts, multi-surface adaptation, and synthetic stress testing. |
| **Find lateral movement attack paths in cloud environments** | `attack-path-workbench` | Multi-hop IAM graph traversal, blast radius modeling, and choke-point remediation. |
| **Plan an authorized, passive attack surface review** | `attack-surface-planner` | Scope boundary partitioning (in-scope vs. excluded) and passive test plan authoring. |
| **Audit Entra ID role assignments, app registrations, and credentials** | `entra-identity-workbench` | Offline analysis of role grants, service principal keys, and account exposures. |
| **Prioritize vulnerability remediation with SBOM reachability** | `exposure-triage-workbench` | Multi-source CVE reachability correlation and exploit exposure prioritization. |
| **Simulate adversarial prompt injection and test agent safety** | `foundry-agent-harness` | Offline red-team evaluation harness for LLM agent boundary robustness. |
| **Validate detection query syntax and catch regressions** | `detection-quality-workbench` | Offline parser, syntax checker, and regression runner for Sentinel and Splunk. |
| **Review code diffs and pull requests for security weaknesses** | `patch-security-review` | Static diff inspection for authorization flaws, injection, and security defects. |
| **Enrich observable indicators with threat intelligence** | `threat-intelligence-enrichment` | Provenance-tracked indicator correlation against MISP/TAXII offline feeds. |
| **Verify telemetry pipelines and avoid SIEM blind spots** | `telemetry-proof-pack` | End-to-end health verification for Cribl Stream, Splunk, and Sentinel routes. |
| **Rehearse incident containment with cryptographic execution receipts** | `incident-response-sandbox` | Approval-gated containment planning, blast-radius calculation, and receipts. |

---

## 3. Take a Plugin for a Test Drive

Every plugin includes a safe, built-in demonstration that runs against local synthetic data:

```bash
# Review logging advice and context scanning
python3 -m cops demo security-logging-advisor

# Walk through a structured SOC investigation case
python3 -m cops demo soc-investigation-workbench

# Explain a Sentinel hunt workflow and evidence contract
python3 -m cops demo sentinel-hunt-workbench

# Trace an illustrative attack path to a crown jewel
python3 -m cops demo attack-path-workbench

# Build a passive attack surface review plan
python3 -m cops demo attack-surface-planner
```

### Why these demos are safe
- **Zero Network Calls**: Everything operates on synthetic fixtures stored locally.
- **No External Writes**: They never write to a cloud service, tenant, or external API.
- **No Shell Execution**: Commands execute strictly as argument lists directly through Python, preventing shell injection.

---

## 4. Validate Package Integrity

You can run the exact same verification checks that power our automated CI pipelines on your own machine.

To run checks for a single plugin:

```bash
# Verify metadata and schema conformance
python3 -m cops validate sentinel-hunt-workbench

# Run complete deterministic offline checks for a package
python3 -m cops check sentinel-hunt-workbench
```

To run offline checks across all thirteen plugins in sequence:

```bash
python3 -m cops check
```

### What these checks test
- **Syntax and Logic**: Validates query structures, parameter definitions, and scripts.
- **Adversarial Perturbations**: In `sentinel-hunt-workbench`, the test suite runs 144 semantic mutations to ensure hunts catch real attacks and resist noise.
- **Schema Contracts**: Ensures all JSON outputs and receipts conform strictly to published schemas.

---

## 5. Using Plugins in Your AI Assistant

Once you're comfortable with how a plugin works locally, you can load it into your preferred assistant:

- **GitHub Copilot**: Load via [`.github/plugin/marketplace.json`](../.github/plugin/marketplace.json) or point to the plugin's root `plugin.json`.
- **Claude Code**: Discover via [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json) or load the plugin's `.claude-plugin/plugin.json`.
- **Codex / ChatGPT**: Load via [`.agents/plugins/marketplace.json`](../.agents/plugins/marketplace.json) and leverage the packaged skills.

Each plugin's `README.md` and `docs/PLAYBOOK.md` provide detailed step-by-step instructions for getting the most out of your AI assistant during active security workflows.

---

## 6. Contributor Setup

Want to write a new hunt, add a detection rule, or contribute a new plugin? Setting up your full development environment is easy:

```bash
# 1. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\Activate.ps1

# 2. Install development test packages
python3 -m pip install -r requirements.txt

# 3. Verify developer prerequisites
python3 -m cops doctor --contributor
make check-prerequisites

# 4. Run the full test suite
make check
```

For guidelines on authoring new plugins, see **[Adding a Plugin](ADDING_A_PLUGIN.md)** and the **[Repository Contract (AGENTS.md)](../AGENTS.md)**.
