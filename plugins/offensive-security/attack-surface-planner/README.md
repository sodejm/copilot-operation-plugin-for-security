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

## Evidence & Ethical Boundaries

The Attack Surface Planner is a **planning and compliance tool**, not an active exploitation framework:
- It **never** authenticates to cloud tenants, crawls websites, queries live DNS/CT logs, or scans ports.
- It **never** runs active penetration tests, harvests credentials, or establishes persistence.
- Any finding, public endpoint, or permission name in an export is a hypothesis trigger for passive review, not proof of exploitability.

Always ensure you have written, executive authorization before undertaking any security assessment.
