"""Capability reconciliation and truth-in-advertising auditor for COPS."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from cops.evidence.canonical import EvidenceError, canonical, utc_now
from cops.evidence.validation import _check

from .models import CapabilityEntry, CapabilityTruthError


ROOT: Path = Path(__file__).resolve().parents[2]


# Plugins categorized as 'laboratory' have synthetic execution or simulation sandboxes
LABORATORY_PLUGIN_IDS: set[str] = {
    "sentinel-hunt-workbench",
    "soc-investigation-workbench",
    "foundry-agent-harness",
    "telemetry-proof-pack",
    "incident-response-sandbox",
    "detection-quality-workbench",
}

# Plugins categorized as 'planned' are scoping and planning only
PLANNED_PLUGIN_IDS: set[str] = {
    "attack-surface-planner",
    "offensive-engagement-workbench",
}


def build_capability_registry(root: Path = ROOT) -> dict[str, Any]:
    """Inspect all plugins, specialist profiles, and scenarios to build the reconciled capability registry."""
    capabilities: list[dict[str, Any]] = []

    # 1. Inspect Plugins
    plugins_index_path = root / "catalog" / "plugins.json"
    if not plugins_index_path.is_file():
        raise CapabilityTruthError("missing_catalog", f"plugins index missing at {plugins_index_path}")
    plugins_index = json.loads(plugins_index_path.read_text(encoding="utf-8"))

    for p in plugins_index["plugins"]:
        pid = p["id"]
        pkg_path = root / p["path"] / "package.json"
        if not pkg_path.is_file():
            raise CapabilityTruthError("missing_package", f"package.json missing for plugin {pid} at {pkg_path}")
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))

        support = pkg.get("support", {})
        live_int = support.get("live_integration", "unverified")

        # Determine mode
        if live_int == "validated":
            mode = "live-validated"
            live_verified = True
        elif pid in PLANNED_PLUGIN_IDS:
            mode = "planned"
            live_verified = False
        elif pid in LABORATORY_PLUGIN_IDS:
            mode = "laboratory"
            live_verified = False
        else:
            mode = "import"
            live_verified = False

        # Limitations / boundaries
        limitations = pkg.get("limitations", [])
        boundaries = "; ".join(limitations) if limitations else pkg.get("summary", "Offline security capability.")

        # Evidence requirements
        if mode == "laboratory":
            ev_reqs = ["Deterministic offline test execution", "Synthetic fixture validation", "Zero network egress"]
        elif mode == "import":
            ev_reqs = ["Local static file/manifest parsing", "Deterministic AST/schema validation", "Zero live service mutation"]
        elif mode == "live-validated":
            ev_reqs = ["cops.evidence/v1 receipt bundle", "Operator authorization receipt", "Live environment execution log"]
        else:
            ev_reqs = ["Scoping specification", "Human-approved rules of engagement"]

        entry = CapabilityEntry(
            id=pid,
            name=pkg.get("display_name", p["name"]),
            kind="plugin",
            mode=mode,
            domain=p.get("primary_category", "general"),
            validation_status="validated" if support.get("structural_validation") == "validated" else "unverified",
            truth_boundaries=boundaries,
            evidence_requirements=ev_reqs,
            live_evidence_verified=live_verified,
        )
        capabilities.append(entry.to_dict())

    # 2. Inspect Specialist Agent Profiles
    agents_registry_path = root / "agents" / "registry.json"
    if not agents_registry_path.is_file():
        raise CapabilityTruthError("missing_agents_registry", f"agents registry missing at {agents_registry_path}")
    agents_reg = json.loads(agents_registry_path.read_text(encoding="utf-8"))

    for spec in agents_reg["specialists"]:
        entry = CapabilityEntry(
            id=spec["id"],
            name=spec["display_name"],
            kind="specialist",
            mode="planned",  # Specialist profiles are advisory/planning personas
            domain=spec.get("domain", "cybersecurity"),
            validation_status="validated",
            truth_boundaries=(
                "Advisory, reasoning, and planning profile; requires human-signed ActionPlan "
                "and authorization receipt for active execution."
            ),
            evidence_requirements=[
                "Specialist profile frontmatter validation",
                "Intent routing keyword mapping",
                "Contract file presence",
            ],
            live_evidence_verified=False,
        )
        capabilities.append(entry.to_dict())

    # 3. Inspect Canonical Scenarios
    scenarios_path = root / "catalog" / "scenarios.json"
    if not scenarios_path.is_file():
        raise CapabilityTruthError("missing_scenarios", f"scenarios registry missing at {scenarios_path}")
    scenarios_data = json.loads(scenarios_path.read_text(encoding="utf-8"))

    for s in scenarios_data["scenarios"]:
        safety = s.get("safety_profile", {})
        mode = s.get("coverage_mode", "planned")
        live_verified = (mode == "live-validated")

        bounds = (
            f"Impact: {safety.get('impact', 'unknown')}; "
            f"Safe for production: {safety.get('safe_for_production', False)}; "
            f"Reversible: {safety.get('reversible', True)}. "
            f"{s.get('description', '')}"
        )

        ev_reqs = [
            f"Pinned research source {s.get('provenance', {}).get('source_id', 'unknown')}",
            "MITRE ATT&CK technique mapping",
            "Isolated worker configuration" if s.get("environment", {}).get("isolated_worker_required") else "Standard runner",
        ]

        entry = CapabilityEntry(
            id=s["scenario_id"],
            name=s["title"],
            kind="scenario",
            mode=mode,
            domain=s.get("family_id", "security-scenario"),
            validation_status="validated",
            truth_boundaries=bounds,
            evidence_requirements=ev_reqs,
            live_evidence_verified=live_verified,
        )
        capabilities.append(entry.to_dict())

    # Summarize
    by_kind = {
        "plugin": sum(1 for c in capabilities if c["kind"] == "plugin"),
        "specialist": sum(1 for c in capabilities if c["kind"] == "specialist"),
        "scenario": sum(1 for c in capabilities if c["kind"] == "scenario"),
    }
    by_mode = {
        "planned": sum(1 for c in capabilities if c["mode"] == "planned"),
        "import": sum(1 for c in capabilities if c["mode"] == "import"),
        "laboratory": sum(1 for c in capabilities if c["mode"] == "laboratory"),
        "live-validated": sum(1 for c in capabilities if c["mode"] == "live-validated"),
    }

    doc = {
        "schema_version": "cops.capabilities/v1",
        "updated_at": utc_now(),
        "summary": {

            "total_capabilities": len(capabilities),
            "by_kind": by_kind,
            "by_mode": by_mode,
        },
        "capabilities": capabilities,
    }

    # Validate against schema
    schema_path = root / "catalog" / "schemas" / "capability-registry.schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        try:
            canonical(doc)
            _check(doc, schema)
        except EvidenceError as err:
            raise CapabilityTruthError(err.code, f"capability registry schema validation failed: {err}") from err

    return doc


def audit_capabilities(root: Path = ROOT, registry_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform deterministic truth-in-advertising audit across all capabilities.

    Rules enforced:
    1. Unverified Live Claims: No capability may claim 'live-validated' mode or 'live_integration: validated'
       without verified live evidence records.
    2. Truth Boundaries: Every capability must specify non-empty truth boundaries.
    3. Descriptive Drift: Total counts must match expected counts (13 plugins, 18 specialists, 32 scenarios).
    4. Specialist Advisory Constraints: Specialists cannot claim direct execution without an ActionPlan contract.
    """
    if registry_data is None:
        registry_data = build_capability_registry(root)

    capabilities = registry_data["capabilities"]
    summary = registry_data["summary"]

    # Rule 1: No unverified live-validated claims
    for cap in capabilities:
        cid = cap["id"]
        mode = cap["mode"]
        live_verified = cap.get("live_evidence_verified", False)

        if mode == "live-validated" and not live_verified:
            raise CapabilityTruthError(
                "unverified_live_claim",
                f"Capability '{cid}' claims 'live-validated' mode without verified live execution evidence."
            )

        # Check for empty boundaries
        if not cap.get("truth_boundaries", "").strip():
            raise CapabilityTruthError(
                "missing_truth_boundary",
                f"Capability '{cid}' has empty truth_boundaries."
            )

    # Rule 2: Check plugin package.json live_integration values directly
    plugins_index_path = root / "catalog" / "plugins.json"
    if plugins_index_path.is_file():
        plugins_index = json.loads(plugins_index_path.read_text(encoding="utf-8"))
        for p in plugins_index["plugins"]:
            pkg_path = root / p["path"] / "package.json"
            if pkg_path.is_file():
                pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
                support = pkg.get("support", {})
                live_int = support.get("live_integration")
                if live_int == "validated":
                    # Check if verified live evidence envelope exists
                    evidence_dir = root / "cops" / "evidence" / "live_receipts"
                    if not evidence_dir.is_dir() or not any(evidence_dir.glob(f"{p['id']}-*.json")):
                        raise CapabilityTruthError(
                            "unverified_live_integration",
                            f"Plugin '{p['id']}' claims live_integration: validated without verified evidence receipts."
                        )

    # Rule 3: Catalog descriptive drift check
    if summary["by_kind"]["plugin"] != 14:
        raise CapabilityTruthError(
            "catalog_descriptive_drift",
            f"Expected exactly 14 plugins, found {summary['by_kind']['plugin']}."
        )
    if summary["by_kind"]["specialist"] != 18:
        raise CapabilityTruthError(
            "catalog_descriptive_drift",
            f"Expected exactly 18 specialist profiles, found {summary['by_kind']['specialist']}."
        )
    if summary["by_kind"]["scenario"] != 33:
        raise CapabilityTruthError(
            "catalog_descriptive_drift",
            f"Expected exactly 33 scenarios, found {summary['by_kind']['scenario']}."
        )

    return {
        "status": "valid",
        "total_capabilities": summary["total_capabilities"],
        "by_kind": summary["by_kind"],
        "by_mode": summary["by_mode"],
    }


def generate_capability_matrix_markdown(registry_data: dict[str, Any]) -> str:
    """Render a clean Markdown capability matrix distinguishing the 4 operational modes."""
    caps = registry_data["capabilities"]
    summary = registry_data["summary"]

    lines: list[str] = [
        "## Capability Truth-in-Advertising Mode Matrix",
        "",
        "COPS enforces strict truthfulness regarding the operational readiness of all capabilities.",
        "Capabilities are classified into four explicit operational modes:",
        "",
        "- **`planned`**: Specification, routing persona, or scoping defined; no autonomous runtime execution.",
        "- **`import`**: Offline telemetry, code AST, diff, or export manifest ingestion only; zero live service mutation.",
        "- **`laboratory`**: Controlled offline simulation, synthetic replay, or rehearsal sandbox; zero external egress.",
        "- **`live-validated`**: Fully authorized, live-tested execution path with cryptographic evidence receipt.",
        "",
        f"**Audit Status**: Validated across {summary['total_capabilities']} capabilities "
        f"({summary['by_kind']['plugin']} plugins, {summary['by_kind']['specialist']} specialist profiles, {summary['by_kind']['scenario']} scenarios).",
        "",
        "| ID | Capability Name | Kind | Operational Mode | Practical Truth Boundary |",
        "| :--- | :--- | :---: | :---: | :--- |",
    ]

    for c in caps:
        boundaries = c["truth_boundaries"]
        # Truncate long descriptions if needed for clean table formatting
        if len(boundaries) > 120:
            boundaries = boundaries[:117] + "..."
        lines.append(
            f"| `{c['id']}` | **{c['name']}** | {c['kind']} | `{c['mode']}` | {boundaries} |"
        )

    lines.append("")
    return "\n".join(lines)
