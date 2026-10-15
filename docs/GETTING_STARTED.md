# Getting Started with COPS

Welcome! This guide is designed to take you from a fresh repository clone to running real, verified cybersecurity tools in under five minutes.

After setup, the core commands and plugin checks in this guide run offline on your local machine. Cloning the repository and downloading contributor dependencies require network access unless you have local copies. You do not need a cloud subscription, API tokens, or an AI assistant to run the offline examples.

---

## 1. Check Your Local Setup

Install **Python 3.11 or newer** and obtain a repository copy using the [quickstart](../README.md#five-minute-quickstart). Run the diagnostic tool from the repository root:

```bash
python3 -m cops doctor
```

### What to look for
- **Python version**: You should see your Python interpreter confirmed as 3.11 or newer.
- **Catalog health**: Checks the catalog, package manifests, and generated marketplace indexes for consistency.

The default check does not run plugins or audit network behavior. Add `--contributor` to check for selected test modules and tool paths; see the [diagnostic limits](troubleshooting.md).

If any check reports an issue, the output will give you clear, actionable instructions on how to resolve it.

---

## 2. Choose the Right Tool for the Job

COPS packages twenty-five dedicated security plugins across defensive and offensive domains. To see the full catalog and current validation status, run:

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
python3 -m cops info offensive-engagement-workbench
python3 -m cops info host-assessment-workbench
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
| **Review scoped Active Directory relationships and candidate paths** | `ad-assessment-workbench` | Offline graph analysis with explicit forest and host collection coverage. |
| **Prioritize vulnerability remediation with SBOM reachability** | `exposure-triage-workbench` | Multi-source CVE reachability correlation and exploit exposure prioritization. |
| **Rehearse synthetic agent tool authorization** | `foundry-agent-harness` | Deterministic local agent and MCP fixtures with observed gate and mock state effects. |
| **Validate detection query syntax and catch regressions** | `detection-quality-workbench` | Offline parser, syntax checker, and regression runner for Sentinel and Splunk. |
| **Review code diffs and pull requests for security weaknesses** | `patch-security-review` | Static diff inspection for authorization flaws, injection, and security defects. |
| **Enrich observable indicators with threat intelligence** | `threat-intelligence-enrichment` | Provenance-tracked indicator correlation against MISP/TAXII offline feeds. |
| **Review supplied telemetry records for missing evidence** | `telemetry-proof-pack` | Uses a run manifest and JSON exports to correlate synthetic marker records across five stages; does not inspect live pipelines. |
| **Rehearse incident containment with cryptographic execution receipts** | `incident-response-sandbox` | Approval-gated containment planning, blast-radius calculation, and receipts. |
| **Plan and validate an authorized offensive engagement** | `offensive-engagement-workbench` | Offline engagement scope, scenario, and execution-authorization contracts. |
| **Classify a local Linux or Windows host assessment export** | `host-assessment-workbench` | Eight Linux or seven Windows surfaces and source-reported canary results from a versioned local export. |

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

Run each plugin's defined checks locally. The full repository suite also requires the contributor setup below.

To run checks for a single plugin:

```bash
# Verify metadata and schema conformance
python3 -m cops validate sentinel-hunt-workbench

# Run complete deterministic offline checks for a package
python3 -m cops check sentinel-hunt-workbench
```

To run offline checks across all twenty-five plugins in sequence:

```bash
python3 -m cops check
```

### What these checks test
- **Package Checks**: Each plugin defines checks for its artifacts, contracts, and test cases. Coverage differs by package.
- **Sentinel Fixtures and Mutations**: `sentinel-hunt-workbench` checks reference invariants against 576 curated and 3,000 generated perturbation cases, plus 144 query marker mutations. It does not parse or execute KQL or establish real attack coverage.
- **Schema Contracts**: Where a package defines schema checks, they validate the supplied fixtures and test outputs against those schemas.

Passing checks mean the assertions passed for the tested cases. They do not prove all code correct or validate a live environment.

To assemble a scoped, evidence-aware assessment from existing local contracts,
see the [offline engagement reporting guide](ENGAGEMENT_REPORTING.md). This
workflow reports supplied coverage and does not run a security test.

---

## 5. Using Plugins in Your AI Assistant

Once you're comfortable with how a plugin works locally, you can load it into your preferred assistant:

- **GitHub Copilot**: Load via [`.github/plugin/marketplace.json`](../.github/plugin/marketplace.json) or point to the plugin's root `plugin.json`.
- **Claude Code**: Discover via [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json) or load the plugin's `.claude-plugin/plugin.json`.
- **Codex / ChatGPT**: Load via [`.agents/plugins/marketplace.json`](../.agents/plugins/marketplace.json) and leverage the packaged skills.

Each plugin's `README.md` and `docs/PLAYBOOK.md` provide detailed step-by-step instructions for getting the most out of your AI assistant during active security workflows.

---

## 6. Contributor Setup

To contribute a hunt, detection rule, or plugin, set up the test environment below. Downloading dependencies requires network access; for prepared local packages, follow the [offline installation instructions](troubleshooting.md).

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
