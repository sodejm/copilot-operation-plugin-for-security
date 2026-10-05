# COPS Attack Surface Planner

The **Attack Surface Planner** helps offensive security engineers and red teams plan strictly authorized, scope-compliant assessments against Microsoft/Azure environments.

In complex enterprise environments, cloud boundaries blur quickly: an organization often manages dozens of Azure subscriptions, partner tenants, shared IP ranges, and historical DNS records. Accidentally probing an out-of-scope asset or unapproved third-party service can lead to severe compliance violations, legal liability, or cloud provider service suspensions.

The Attack Surface Planner acts as an **ethical guardrail for offensive operations**. It takes your human-signed Rules of Engagement (RoE) alongside local asset inventory exports, cross-references them, and partitions discoveries into three strict buckets: `in_scope`, `excluded`, and `unresolved`. It then drafts a structured, non-intrusive observation plan that keeps your testing 100% compliant with approved boundaries.

The planner operates completely offline, making zero network requests, tenant API calls, or active scans.

---

## When to Use & Offensive Engineer Playbook

For step-by-step scoping workflows, authorization templates, and compliance tracking, see the complete [Offensive Engineer & Red Teamer Playbook](docs/PLAYBOOK.md).

Use this planner when:
- **Scoping authorized offensive engagements**: Translating human-signed rules-of-engagement contracts into actionable asset inventories.
- **Reconciling multi-tenant cloud boundaries**: Partitioning Azure, Entra ID, and public endpoint exports into verified in-scope vs. excluded targets.
- **Planning passive reconnaissance**: Designing non-intrusive observation steps without executing unauthorized network calls.
- **Documenting engagement compliance**: Establishing verifiable audit trails, emergency stop conditions, and cleanup steps before testing begins.

---

## The Foundation: Rules of Engagement

Every engagement begins with explicit human authorization. Before generating a plan, ensure the assessment owner has signed off on:
- Approved Tenant IDs and Azure Subscription IDs
- Explicit DNS domain names and IP ranges
- Designated testing windows (UTC) and allowed observation methods
- Explicitly excluded assets (e.g., mission-critical production clusters or third-party partner services)

Record this sign-off in your local scope manifest. Discovered assets never automatically expand scope—if an asset's ownership is unverified, the planner flags it as `unresolved` and blocks testing until an authorized human signs off.

---

## Quick Test Drive (Offline Demo)

You can explore how the planner reconciles assets using the included synthetic test fixtures:

```bash
# From the repository root:
python3 -m cops demo attack-surface-planner

# Or run the script directly from the package directory:
python3 scripts/plan.py fixtures/synthetic/scope.json
```

### What to look for
The planner outputs a structured JSON report to standard output:
1. **`surface_map`**: Categorizes every discovered asset into:
   - `in_scope`: Matches your approved subscriptions, domains, and environments.
   - `excluded`: Explicitly prohibited assets, out-of-scope partner tenants, or non-production testbeds.
   - `unresolved`: Discovered assets with missing or ambiguous ownership that require manual verification.
2. **`test_plan`**: For in-scope assets only, generates a passive review plan specifying allowed observation methods, expected telemetry, emergency stop conditions, and cleanup protocols.

---

## Input Limits & Safety Guardrails

To protect your system from malformed inputs or runaway memory consumption, the planner enforces strict local constraints:
- Scope manifest maximum size: 128 KiB.
- Individual export maximum size: 4 MiB (total input capped at 12 MiB).
- Maximum total records: 1,000 across all sources.
- Maximum JSON nesting depth: 24 levels.
- File path containment: All export sources must reside within the manifest directory; symlinks and directory climbing (`../`) are strictly rejected.

---

## Extended Passive Discovery & Scope Quarantine Reconciliation

The package extends its passive planning capabilities with multi-source telemetry normalization and scope quarantine reconciliation (`cops discovery`):

1. **Multi-Source Normalization**: Ingests raw DNS, TLS/CT certificates, IP allocations, endpoints, and cloud exports into canonical `DiscoveredAsset` records with cryptographic SHA-256 evidence provenance.
2. **Provenance Deduplication**: Consolidates multi-source observations of identical entities while retaining all source proofs.
3. **Scope Quarantine Reconciliation**:
   - `verified_in_scope`: Matches approved targets, subnets, and domains with verified ownership.
   - `quarantined`: Flags assets with conflicting ownership, stale/dangling DNS records, or missing provenance so discovery cannot expand the engagement.
   - `excluded`: Explicitly prohibited domains, IP ranges, or partner tenants.

```bash
# Normalize raw telemetry
python3 -m cops discovery normalize fixtures/recon/dns.json --type dns --output inventory.json

# Reconcile against approved engagement scope
python3 -m cops discovery reconcile inventory.json --scope scope.json --output reconciled.json

# Merge and deduplicate multiple inventories
python3 -m cops discovery merge inv1.json inv2.json --output merged.json

# Inspect inventory summary
python3 -m cops discovery inspect reconciled.json
```

---

## Bounded Active Discovery & Service Identification

The package extends reconnaissance foundations with bounded, rate-limited active port and TLS service assessment (`cops discovery active` or `cops active-discovery`):

1. **Approved Assessment Configuration**:
   - Explicit scan vantage (`external`, `internal`, `egress_point`, `cloud_tenant`).
   - Rate limiting (`--rate-limit <pps>`) with probe pacing to prevent perimeter disruption.
   - Resource and execution budgets (`--timeout <sec>`, `--max-total-seconds <sec>`).
2. **Resumable Execution**:
   - Saves checkpoint after every probe or upon budget exhaustion.
   - Resuming skips completed probes without repeating network side effects or exceeding approved targets.
3. **Grounded Service Identification with Visible Uncertainty**:
   - Distinguishes verbatim observed configurations (raw banners, HTTP status/headers, TLS ciphers/certs) from inferred fingerprints (product, version, OS).
   - Calibrates confidence (`high`, `medium`, `low`, `uncertain`, `provisional`) and flags reverse proxies, CDNs, and certificate mismatches.
4. **Scope Quarantine & DNS Rebind Defense**:
   - Enforces scope CIDR and domain checks before each probe; halts probes and flags `dns_rebind_detected` if target resolution shifts.
5. **Remediated Exposure Verification**:
   - Compares baseline vs. re-test scans to compute remediated, new, and persistent exposures with exact remediation rate percentage.

```bash
# Plan active assessment
python3 -m cops discovery active plan --targets "198.51.100.10,app.corp.internal" --ports 80,443,22 --output session.json

# Execute bounded scan
python3 -m cops discovery active scan session.json --scope scope.json --checkpoint checkpoint.json

# Resume interrupted scan
python3 -m cops discovery active resume checkpoint.json --output completed.json

# Compare scans for remediation delta
python3 -m cops discovery active diff baseline.json current.json --output delta.json

# Import Masscan or Nmap output
python3 -m cops discovery active import masscan.json --tool masscan --output masscan_session.json
```

---

## Evidence & Ethical Boundaries

The Attack Surface Planner is a **planning and compliance tool**, not an active exploitation framework:
- It **never** authenticates to cloud tenants, crawls websites, queries live DNS/CT logs, or scans ports.
- It **never** runs active penetration tests, harvests credentials, or establishes persistence.
- Any finding, public endpoint, or permission name in an export is a hypothesis trigger for passive review, not proof of exploitability.

Always ensure you have written, executive authorization before undertaking any security assessment.
