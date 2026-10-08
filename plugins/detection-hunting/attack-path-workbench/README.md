# Attack Path Workbench

The **Attack Path Workbench** models, analyzes, and disrupts multi-hop attack paths in cloud environments before adversaries can exploit them. Instead of getting overwhelmed by thousands of isolated vulnerability alerts, this workbench connects security findings, network reachability, and IAM entitlements into a coherent attack graph. This allows security engineers to identify and prioritize high-leverage **choke points**—the minimal policy or network adjustments that break dozens of critical attack paths simultaneously.

The workbench operates completely offline against local export files and Azure entitlement evidence, making zero network calls.

---

## When to Use & Engineering Playbook

For comprehensive methodologies and remediation workflows, see the [Analyst & Engineer Playbook](docs/PLAYBOOK.md).

Use this workbench when:
- **Reviewing cloud IAM & entitlements**: Analyzing multi-hop privilege escalation across Azure/AWS or Wiz export graphs.
- **Evaluating vulnerability reachability**: Determining whether an internet-exposed workload finding can laterally pivot to your crown-jewel databases.
- **Prioritizing choke-point remediations**: Finding the minimal policy or network changes that eliminate the most critical attack paths.
- **Validating architecture changes offline**: Modeling planned identity and network boundaries before rolling them out to production.

---

## Try the Offline Illustrative Fixture

You can explore the workbench immediately using the included synthetic test fixture:

```bash
# Run from the attack-path-workbench directory:
python3 scripts/attackpath.py analyze fixtures/illustrative/input.json --output-dir /tmp/attack-path-illustrative
python3 scripts/attackpath.py query-intent --start ILL-FINDING --target ILL-CROWN --scope ILL-SCOPE
python3 -m unittest discover -s tests -v
```

### What to look for
The analyzer generates four detailed output files in your chosen directory:
1. `report.md`: A human-readable Markdown summary breaking down candidate attack routes and candidate choke points.
2. `report.json`: Machine-readable results containing route provenance, confidence ratings, and a bounded search receipt. If a limit stops search, ranked paths are the best discovered paths only.
3. `graph.json`: An exported node-and-edge graph model ready for visualization or SIEM ingestion.
4. `remediation-ledger.json`: An auditable ledger mapping each identified risk to its concrete remediation step.

> [!NOTE]
> The illustrative fixture contains synthetic test data designed to demonstrate graph analysis algorithms safely. Structural routes are conditional on exploiting starting findings, and candidate routes highlight explicit evidence gaps.

The illustrative graph search considers routes of at most eight transitions. Its default hard ceilings are 50,000 expansions, 10,000 frontier entries, 1,000 complete paths, 1,000 partial paths, 100 emitted paths, and 64 MiB of serialized report JSON. The `analyze` command exposes corresponding `--max-*` options that can only tighten these ceilings. The `attackpath.report/v2` search receipt records effective limits, exact consumed counts, completeness within the eight-transition search, and the stop reason. These counters provide the reproducible work bound; elapsed time and peak memory still depend on the host runtime. The policy hash is part of the run identity. A legacy v1 report has no such receipt; audit accepts it only if replay finishes within current hard limits and does not infer historical search completeness.

Local evidence ingestion defaults to 4 MiB per file, 64 MiB in aggregate, 64 files, 1 MiB per physical JSONL line, 50,000 admitted records, and 32 nested JSON containers. Operators may tighten or raise these values only within hard maxima of 16 MiB per file, 256 MiB in aggregate, 256 files, 4 MiB per line, 200,000 records, and 64 containers. Each limit is inclusive: the exact boundary is accepted and the next byte, file, record, line byte, or container is rejected before report completion. Aggregate bytes and admitted records accumulate across reads and batches; JSON depth counts containers consistently whether they are empty or populated.

---

## Analyzing Azure Entitlement Evidence

For teams operating in Microsoft Azure, the workbench provides offline analysis of Graph, ARM, and Azure Resource Graph evidence:

```bash
# 1. Plan read-only queries for an authorized external collector
python3 scripts/attackpath.py plan-azure-collection --scope-file scopes.json --output collection-plan

# 2. Analyze collected entitlement evidence offline
python3 scripts/attackpath.py analyze-azure --input bundle/manifest.json --as-of 2026-09-28T12:00:00Z --output azure-report
```

Both commands run completely offline and write to fresh output directories. The planner outputs versioned queries for your operations team to run. The analyzer verifies checksummed evidence pages, modeling permissions and lateral movement assumptions without touching live cloud APIs.

For schemas and privacy limits, see the [Azure Entitlement Guide](docs/azure-entitlements.md).

---

## Contracts, Schemas, & Boundaries

To dive deeper into the workbench's internal design:
- [Architecture & Analysis Method](docs/architecture.md): Component responsibilities, graph rules, and impact algorithms.
- [Data Contract](docs/data-contract.md): Input schemas, data provenance, and output formats.
- [Decision Gates](docs/gates.md): Gates G1 through G8, graph semantics, and confidence scoring.
- [Integration Boundaries](docs/integration-boundaries.md): Prerequisites for Wiz exports, business impact scoring, and MITRE mapping.
- [Operations Guide](docs/operations.md): Report review processes and remediation tracking.
- [Implementation Status](docs/implementation-plan.md): Active capabilities and gated integrations.
- [Specialist Agent Roles](agents/README.md): Defined advisory subagents (Path Skeptic, Claim Auditor, Impact Reviewer).

---

## Evidence & Verification Boundaries

The Attack Path Workbench is an analytical modeling tool. It models potential lateral movement and privilege escalation paths based on supplied configuration data. It does not actively exploit vulnerabilities, execute cloud commands, or test network reachability in live environments. Always validate identified choke points in staging or during authorized change windows before applying production policy changes.
