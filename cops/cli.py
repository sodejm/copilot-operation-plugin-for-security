"""Operator-first command line for discovering and exercising COPS plugins."""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from .catalog import ROOT, CatalogError, PluginRecord, find_plugin, plugin_records, validate_declared_command
from .coverage import (
    CoverageError,
    evaluate_coverage_gaps,
    generate_attack_flow,
    generate_coverage_matrix,
    load_attack_coverage,
    load_attack_reference,
    render_gap_report_markdown,
    review_coverage_freshness,
)
from .validation import ValidationError, generate_marketplaces, validate_repository


def _print_command(command: Sequence[str]) -> None:
    print("+ " + shlex.join(command), flush=True)


def _run_definition(
    definition: dict[str, Any],
    record: PluginRecord,
    *,
    root: Path,
) -> int:
    command, timeout = validate_declared_command(definition, record, root)
    _print_command(command)
    try:
        result = subprocess.run(command, cwd=root, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"error: {record.id} command timed out after {timeout} seconds", file=sys.stderr)
        return 124
    return result.returncode


def _select(plugin_ids: list[str], root: Path) -> list[PluginRecord]:
    if not plugin_ids:
        return plugin_records(root)
    return [find_plugin(plugin_id, root) for plugin_id in plugin_ids]


def command_list(root: Path = ROOT) -> int:
    records = validate_repository(root)
    header = ("PLUGIN", "CATEGORY", "MATURITY", "OFFLINE", "HOST", "LIVE")
    rows = [
        (
            record.id,
            record.primary_category,
            record.maturity,
            record.support["offline_workflow"],
            record.support["host_installation"],
            record.support["live_integration"],
        )
        for record in records
    ]
    widths = [max(len(row[index]) for row in [header, *rows]) for index in range(len(header))]
    print("  ".join(value.ljust(widths[index]) for index, value in enumerate(header)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
    return 0


def command_info(plugin_id: str, root: Path = ROOT) -> int:
    validate_repository(root)
    record = find_plugin(plugin_id, root)
    document = {
        "id": record.id,
        "display_name": record.name,
        "version": record.version,
        "category": record.primary_category,
        "maturity": record.maturity,
        "summary": record.package["summary"],
        "support": record.support,
        "limitations": record.package["limitations"],
        "demo": record.package["demo"]["description"],
        "path": record.path,
    }
    print(json.dumps(document, indent=2, ensure_ascii=False))
    return 0


def command_doctor(*, contributor: bool, root: Path = ROOT) -> int:
    missing: list[str] = []
    print(f"COPS root: {root}")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    if sys.version_info < (3, 11):
        missing.append("Python 3.11 or newer")
    try:
        records = validate_repository(root)
        print(f"Catalog: {len(records)} package(s), generated indexes current")
    except CatalogError as error:
        missing.append(f"repository contract ({error})")

    if contributor:
        for module in ("pytest", "pytest_bdd"):
            available = importlib.util.find_spec(module) is not None
            print(f"{module}: {'installed' if available else 'MISSING (test dependency)'}")
            if not available:
                missing.append(module)
        for command, required in (("git", True), ("make", False), ("gh", False)):
            location = shutil.which(command)
            print(f"{command}: {location or ('MISSING (required)' if required else 'not installed (optional)')}")
            if required and not location:
                missing.append(command)

    if missing:
        print("Not ready: " + "; ".join(missing), file=sys.stderr)
        if contributor:
            print("Install contributor dependencies with: python3 -m pip install -r requirements.txt")
        return 1
    mode = "contributor checks" if contributor else "offline plugin use"
    print(f"Environment is ready for {mode}.")
    print("Host installation and live-service behavior remain separate evidence gates.")
    return 0


def command_validate(plugin_ids: list[str], root: Path = ROOT) -> int:
    validate_repository(root)
    records = _select(plugin_ids, root)
    print("Validated package contracts: " + ", ".join(record.id for record in records))
    print("This is structural validation; it does not prove host installation or live integrations.")
    return 0


def command_demo(plugin_id: str, root: Path = ROOT) -> int:
    validate_repository(root)
    record = find_plugin(plugin_id, root)
    print(record.package["demo"]["description"])
    return _run_definition(record.package["demo"], record, root=root)


def command_check(plugin_ids: list[str], root: Path = ROOT) -> int:
    validate_repository(root)
    records = _select(plugin_ids, root)
    failures: list[str] = []
    for record in records:
        print(f"\n[{record.id}]", flush=True)
        for definition in record.package["validation"]:
            name = str(definition["name"])
            print(f"-- {name}", flush=True)
            if _run_definition(definition, record, root=root) != 0:
                failures.append(f"{record.id}:{name}")
    if failures:
        print("Failed package checks: " + ", ".join(failures), file=sys.stderr)
        return 1
    print(f"\nAll declared checks passed for {len(records)} package(s).")
    return 0


def command_generate(*, check: bool, root: Path = ROOT) -> int:
    validate_repository(root, check_indexes=False)
    changed = generate_marketplaces(root, check=check)
    if check:
        print("Generated host indexes are current.")
    elif changed:
        print("Updated host indexes: " + ", ".join(path.as_posix() for path in changed))
    else:
        print("Generated host indexes already current.")
    return 0


def command_coverage(
    *,
    matrix: bool = False,
    output: Path | None = None,
    check: bool = False,
    gaps: bool = False,
    profile_path: Path | None = None,
    export_flow: str | None = None,
    output_flow: Path | None = None,
    as_json: bool = False,
    root: Path = ROOT,
) -> int:
    ref = load_attack_reference(root=root)
    mappings = load_attack_coverage(reference=ref, root=root, strict=True)

    if check:
        freshness = review_coverage_freshness(mappings, ref)
        if freshness["status"] != "fresh":
            print(
                f"error: ATT&CK review findings detected: "
                f"revoked={freshness['revoked_count']}, "
                f"deprecated={freshness['deprecated_count']}, "
                f"version_drift={freshness['version_drift_count']}",
                file=sys.stderr,
            )
            return 1
        matrix_file = root / "docs" / "COVERAGE_MATRIX.md"
        if not matrix_file.is_file():
            print(f"error: Coverage matrix file missing: {matrix_file}", file=sys.stderr)
            return 1
        expected_matrix = generate_coverage_matrix(mappings, ref)
        actual_matrix = matrix_file.read_text(encoding="utf-8")
        if actual_matrix.strip() != expected_matrix.strip():
            print(
                f"error: {matrix_file} is out of date with catalog/attack_coverage.json; "
                f"run 'python3 -m cops coverage --matrix --output docs/COVERAGE_MATRIX.md'",
                file=sys.stderr,
            )
            return 1
        print("MITRE ATT&CK coverage mappings, reference data, and matrix are valid and synchronized.")
        return 0

    if gaps:
        env_profile = None
        if profile_path is not None:
            profile_file = (root / profile_path) if not profile_path.is_absolute() else profile_path
            if not profile_file.is_file():
                print(f"error: profile file not found: {profile_file}", file=sys.stderr)
                return 1
            env_profile = json.loads(profile_file.read_text(encoding="utf-8"))
        gap_data = evaluate_coverage_gaps(mappings, ref, environment_profile=env_profile)
        if as_json:
            print(json.dumps(gap_data, indent=2))
        else:
            print(render_gap_report_markdown(gap_data))
        return 0

    if export_flow:
        flow_data = generate_attack_flow(export_flow, mappings=mappings, reference=ref)
        if output_flow is not None:
            out_path = (root / output_flow) if not output_flow.is_absolute() else output_flow
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(flow_data, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote Attack Flow bundle to {output_flow}")
        else:
            print(json.dumps(flow_data, indent=2))
        return 0

    # Default action: render matrix
    text = generate_coverage_matrix(mappings, ref)
    if output is not None:
        out_path = (root / output) if not output.is_absolute() else output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"Wrote coverage matrix to {output}")
    else:
        print(text)
    return 0


def command_contract_validate(file_path: Path, contract_type: str | None = None) -> int:
    from .contracts import ContractError, validate_contract
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        validate_contract(data, contract_type)
        print(f"Contract valid ({data.get('schema_version')}): {file_path}")
        return 0
    except (json.JSONDecodeError, ContractError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def command_contract_transition(current: str, target: str, contract_type: str) -> int:
    from .contracts import ContractError, validate_transition
    try:
        validate_transition(current, target, contract_type)
        print(f"Valid transition for {contract_type}: {current} -> {target}")
        return 0
    except ContractError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def command_scenario_list(family_id: str | None = None, tactic: str | None = None, coverage_mode: str | None = None, as_json: bool = False, root: Path = ROOT) -> int:
    from .scenarios import list_scenarios
    scenarios = list_scenarios(root, family_id=family_id, tactic=tactic, coverage_mode=coverage_mode)
    if as_json:
        print(json.dumps(scenarios, indent=2))
        return 0
    print(f"Registered Scenarios ({len(scenarios)}):")
    for s in scenarios:
        techs = ", ".join(s.get("mitre_attack", {}).get("techniques", []))
        print(f"  {s['scenario_id']:<20} | {s.get('family_id', ''):<15} | [{s.get('coverage_mode', '')}] {s['title']} ({techs})")
    return 0


def command_scenario_info(scenario_id: str, as_json: bool = False, root: Path = ROOT) -> int:
    from .scenarios import RegistryError, get_scenario
    try:
        scen = get_scenario(scenario_id, root)
    except RegistryError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(scen, indent=2))
        return 0
    print(f"Scenario: {scen['scenario_id']} - {scen['title']}")
    print(f"Family: {scen.get('family_id', '')}")
    print(f"Coverage Mode: {scen.get('coverage_mode', '')}")
    print(f"Description: {scen.get('description', '')}")
    print(f"MITRE Tactics: {', '.join(scen.get('mitre_attack', {}).get('tactics', []))}")
    print(f"MITRE Techniques: {', '.join(scen.get('mitre_attack', {}).get('techniques', []))}")
    prov = scen.get("provenance", {})
    print(f"Provenance: {prov.get('source_id', '')} ({prov.get('source_reference', '')})")
    print(f"License: {prov.get('license', '')} (version bound: {prov.get('version_bound', '')})")
    safety = scen.get("safety_profile", {})
    print(f"Safety: impact={safety.get('impact')}, safe_for_production={safety.get('safe_for_production')}, reversible={safety.get('reversible')}")
    env = scen.get("environment", {})
    print(f"Environment: os={env.get('os', [])}, tools={env.get('required_tools', [])}, isolated_worker={env.get('isolated_worker_required')}")
    prereqs = scen.get("prerequisites", [])
    if prereqs:
        print("Prerequisites:")
        for p in prereqs:
            print(f"  - {p}")
    return 0


def command_scenario_validate(root: Path = ROOT) -> int:
    from .scenarios import RegistryError, validate_scenario_and_provenance_integrity
    try:
        res = validate_scenario_and_provenance_integrity(root)
        print("Scenario and Provenance Registry valid:")
        print(f"  Sources: {res['sources_count']}")
        print(f"  Inventory Items: {res['inventory_items_count']}")
        print(f"  Scenarios: {res['scenarios_count']}")
        return 0
    except RegistryError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def command_scenario_provenance(source_id: str | None = None, as_json: bool = False, root: Path = ROOT) -> int:
    from .scenarios import RegistryError, get_provenance_source, list_provenance_sources
    if source_id:
        try:
            src = get_provenance_source(source_id, root)
        except RegistryError as err:
            print(f"error: {err}", file=sys.stderr)
            return 1
        if as_json:
            print(json.dumps(src, indent=2))
            return 0
        print(f"Provenance Source: {src['source_id']} - {src['name']}")
        print(f"Category: {src.get('category')}")
        print(f"URL: {src['url']}")
        print(f"Pinned Revision: {src.get('pinned_revision')}")
        print(f"License: {src.get('license')}")
        print(f"Item Count: {src.get('item_count')}")
        print(f"Inventory Items ({len(src.get('inventory', []))}):")
        for item in src.get("inventory", []):
            print(f"  {item['item_id']:<10} | [{item['resolution']}] {item['target_id']} ({item.get('notes', '')})")
        return 0
    sources = list_provenance_sources(root)
    if as_json:
        print(json.dumps(sources, indent=2))
        return 0
    print(f"Registered Provenance Sources ({len(sources)}):")
    for s in sources:
        print(f"  {s['source_id']:<6} | {s.get('category', ''):<22} | {len(s.get('inventory', [])):>3} items | {s['name']}")
    return 0


def command_capabilities_list(mode: str | None = None, kind: str | None = None, as_json: bool = False, root: Path = ROOT) -> int:
    from .capabilities import build_capability_registry
    reg = build_capability_registry(root)
    caps = reg["capabilities"]
    if mode:
        caps = [c for c in caps if c["mode"] == mode]
    if kind:
        caps = [c for c in caps if c["kind"] == kind]
    if as_json:
        print(json.dumps(caps, indent=2))
        return 0
    print(f"Reconciled Capabilities ({len(caps)}):")
    for c in caps:
        print(f"  {c['id']:<32} | {c['kind']:<10} | [{c['mode']:<14}] {c['name']}")
    return 0


def command_capabilities_audit(check: bool = False, root: Path = ROOT) -> int:
    from .capabilities import CapabilityTruthError, audit_capabilities, build_capability_registry
    try:
        reg = build_capability_registry(root)
        summary = audit_capabilities(root, registry_data=reg)
        print("Capability Truth-in-Advertising Audit Passed:")
        print(f"  Total Audited: {summary['total_capabilities']}")
        print(f"  Plugins: {summary['by_kind']['plugin']}")
        print(f"  Specialist Profiles: {summary['by_kind']['specialist']}")
        print(f"  Scenarios: {summary['by_kind']['scenario']}")
        print("  By Operational Mode:")
        for mode, count in summary["by_mode"].items():
            print(f"    - {mode}: {count}")
        return 0
    except CapabilityTruthError as err:
        print(f"audit failure: [{err.code}] {err.message}", file=sys.stderr)
        return 1


def command_capabilities_matrix(output: Path | None = None, root: Path = ROOT) -> int:
    from .capabilities import build_capability_registry, generate_capability_matrix_markdown
    reg = build_capability_registry(root)
    text = generate_capability_matrix_markdown(reg)
    if output:
        out_path = (root / output) if not output.is_absolute() else output
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"Wrote capability matrix to {output}")
    else:
        print(text)
    return 0


def command_worker_status(args: argparse.Namespace) -> int:
    from .execution import IsolatedWorker, WorkerConfig
    try:
        worker = IsolatedWorker(WorkerConfig(worker_id=getattr(args, "worker_id", None) or "worker-local-01"))
        info = {
            "worker_id": worker.config.worker_id,
            "status": "ready",
            "enforce_unprivileged": worker.config.enforce_unprivileged,
            "allowed_tools": list(worker.config.allowed_tools),
            "max_wall_time_seconds": worker.config.max_wall_time_seconds,
            "max_output_bytes": worker.config.max_output_bytes,
        }
        if getattr(args, "json", False):
            print(json.dumps(info, indent=2))
        else:
            print(f"Worker Identity: {info['worker_id']}")
            print(f"Status         : {info['status']}")
            print(f"Allowed Tools  : {', '.join(info['allowed_tools'])}")
            print(f"Max Wall Time  : {info['max_wall_time_seconds']}s")
            print(f"Max Output     : {info['max_output_bytes']} bytes")
        return 0
    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def command_worker_store_list(args: argparse.Namespace) -> int:
    from .execution import ApprovalStore
    db_path = getattr(args, "db", None) or (Path.home() / ".cops" / "approvals.sqlite3")
    try:
        store = ApprovalStore(db_path)
        approvals = store.list_approvals(status=getattr(args, "status", None))
        if getattr(args, "json", False):
            print(json.dumps([a.to_dict() for a in approvals], indent=2))
        else:
            print(f"Approvals Store ({len(approvals)} records at {db_path}):")
            for a in approvals:
                print(f"  {a.authorization_id:<28} | plan: {a.action_plan_id:<20} | [{a.status:<8}] operator: {a.operator}")
        return 0
    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def command_worker_execute(args: argparse.Namespace) -> int:
    from .contracts.models import ActionPlan, ExecutionAuthorization
    from .execution import ApprovalStore, IsolatedWorker, WorkerConfig, ScopeGuard
    plan_path = Path(args.plan)
    if not plan_path.is_file():
        print(f"error: plan file not found: {plan_path}", file=sys.stderr)
        return 1

    db_path = getattr(args, "db", None) or (Path.home() / ".cops" / "approvals.sqlite3")
    try:
        store = ApprovalStore(db_path)
        worker_id = getattr(args, "worker_id", None) or "worker-local-01"

        # Load engagement and scope guard if provided
        scope_guard = None
        eng_path = getattr(args, "engagement", None)
        if eng_path and Path(eng_path).is_file():
            eng_doc = json.loads(Path(eng_path).read_text(encoding="utf-8"))
            scope_guard = ScopeGuard.from_engagement(eng_doc)

        worker = IsolatedWorker(WorkerConfig(worker_id=worker_id), store=store, scope_guard=scope_guard)
        plan_doc = json.loads(plan_path.read_text(encoding="utf-8"))

        auth_val: str
        auth_path = Path(args.authorization)
        if auth_path.is_file():
            auth_doc = json.loads(auth_path.read_text(encoding="utf-8"))
            auth_model = ExecutionAuthorization.from_dict(auth_doc)
            store.store_authorization(auth_model)
            auth_val = auth_model.authorization_id
        else:
            auth_val = args.authorization

        result = worker.execute_plan(plan_doc, authorization=auth_val)
        if getattr(args, "json", False):
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"Execution complete: {result.result_id} ({result.status})")
            if result.status != "success":
                print(f"Reason: {result.status_details.get('reason')}")
        return 0 if result.is_successful() else 1
    except Exception as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m cops",
        description="Discover, validate, and safely exercise COPS cybersecurity plugins.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list cataloged plugins and support evidence")
    info = subparsers.add_parser("info", help="show one plugin's purpose and evidence boundaries")
    info.add_argument("plugin_id")
    doctor = subparsers.add_parser("doctor", help="check the local runtime and repository contract")
    doctor.add_argument("--contributor", action="store_true", help="also require test dependencies and Git")
    validate = subparsers.add_parser("validate", help="validate package and marketplace contracts")
    validate.add_argument("plugin_ids", nargs="*")
    demo = subparsers.add_parser("demo", help="run one package's safe, offline demonstration")
    demo.add_argument("plugin_id")
    check = subparsers.add_parser("check", help="run package-declared deterministic checks")
    check.add_argument("plugin_ids", nargs="*")
    generate = subparsers.add_parser("generate", help="generate host indexes from the catalog")
    generate.add_argument("--check", action="store_true", help="fail instead of writing when indexes are stale")

    cov_parser = subparsers.add_parser("coverage", help="inspect ATT&CK coverage, gap analysis, and Attack Flow")
    cov_parser.add_argument("--matrix", action="store_true", help="render the Markdown coverage matrix")
    cov_parser.add_argument("--output", type=Path, help="write coverage matrix to file")
    cov_parser.add_argument("--check", action="store_true", help="validate mappings and check matrix freshness")
    cov_parser.add_argument("--gaps", action="store_true", help="run telemetry and analytics gap analysis")
    cov_parser.add_argument("--profile", type=Path, help="environment profile for gap analysis")
    cov_parser.add_argument("--export-flow", choices=["azure-identity", "m365-compromise"], help="export STIX 2.1 Attack Flow bundle")
    cov_parser.add_argument("--output-flow", type=Path, help="write Attack Flow bundle to file")
    cov_parser.add_argument("--json", action="store_true", help="output structured JSON")

    route_p = subparsers.add_parser("route", help="route a security task to the optimal specialist profile")
    route_p.add_argument("query", help="natural language task description or request")
    route_p.add_argument("--critical", action="store_true", help="force critical classification (triad)")
    route_p.add_argument("--authorize", action="store_true", help="trigger authorization gate if required")
    route_p.add_argument("--scope", nargs="+", help="target scope identifiers for authorization")
    route_p.add_argument("--action", help="action name for authorization")
    route_p.add_argument("--json", action="store_true", help="output structured JSON")

    spec_p = subparsers.add_parser("specialists", help="list all specialist cybersecurity agent profiles")
    spec_p.add_argument("--json", action="store_true", help="output structured JSON")

    contract_p = subparsers.add_parser("contract", help="validate and transition operational contracts")
    contract_sub = contract_p.add_subparsers(dest="contract_command", required=True)
    c_val = contract_sub.add_parser("validate", help="validate an operational contract file")
    c_val.add_argument("file", type=Path, help="path to contract JSON file")
    c_val.add_argument("--type", choices=["engagement", "scenario", "action_plan", "run_result", "finding", "execution_authorization", "specialist_handoff", "laboratory_environment"], help="explicit contract type")

    c_trans = contract_sub.add_parser("transition", help="validate a lifecycle transition")
    c_trans.add_argument("current", help="current lifecycle state")
    c_trans.add_argument("target", help="target lifecycle state")
    c_trans.add_argument("--type", choices=["engagement", "action_plan", "execution_authorization", "specialist_handoff", "laboratory_environment"], default="engagement", help="contract type")

    scen_p = subparsers.add_parser("scenario", help="inspect and validate scenario and provenance registries")
    scen_sub = scen_p.add_subparsers(dest="scenario_command", required=True)
    scen_list = scen_sub.add_parser("list", help="list registered scenarios")
    scen_list.add_argument("--family", dest="family_id", help="filter by scenario family ID")
    scen_list.add_argument("--tactic", help="filter by MITRE ATT&CK tactic")
    scen_list.add_argument("--mode", dest="coverage_mode", choices=["planned", "implemented", "unsupported"], help="filter by coverage mode")
    scen_list.add_argument("--json", action="store_true", help="output structured JSON")

    scen_info = scen_sub.add_parser("info", help="display details for a specific scenario")
    scen_info.add_argument("scenario_id", help="canonical scenario identifier")
    scen_info.add_argument("--json", action="store_true", help="output structured JSON")

    scen_sub.add_parser("validate", help="validate scenario and provenance registry integrity")

    scen_prov = scen_sub.add_parser("provenance", help="inspect pinned provenance sources")
    scen_prov.add_argument("--source", dest="source_id", help="specific source ID to inspect")
    scen_prov.add_argument("--json", action="store_true", help="output structured JSON")

    cap_p = subparsers.add_parser("capabilities", help="inspect, audit, and render capability truth-in-advertising matrices")
    cap_sub = cap_p.add_subparsers(dest="capabilities_command", required=True)
    cap_l = cap_sub.add_parser("list", help="list reconciled capabilities")
    cap_l.add_argument("--mode", choices=["planned", "import", "laboratory", "live-validated"], help="filter by operational mode")
    cap_l.add_argument("--kind", choices=["plugin", "specialist", "scenario"], help="filter by capability kind")
    cap_l.add_argument("--json", action="store_true", help="output structured JSON")

    cap_a = cap_sub.add_parser("audit", help="audit capability claims against truth-in-advertising rules")
    cap_a.add_argument("--check", action="store_true", help="exit with non-zero if audit fails")

    cap_m = cap_sub.add_parser("matrix", help="render the Markdown capability matrix")
    cap_m.add_argument("--output", type=Path, help="write capability matrix to file")

    worker_p = subparsers.add_parser("worker", help="isolated execution worker and approval store operations")
    worker_sub = worker_p.add_subparsers(dest="worker_command", required=True)
    w_status = worker_sub.add_parser("status", help="display worker readiness and configuration")
    w_status.add_argument("--worker-id", help="override worker identity")
    w_status.add_argument("--json", action="store_true", help="output structured JSON")

    w_store = worker_sub.add_parser("store", help="inspect approvals in the approval store")
    w_store.add_argument("--db", type=Path, help="path to sqlite approval store")
    w_store.add_argument("--status", choices=["approved", "consumed", "revoked", "expired"], help="filter by status")
    w_store.add_argument("--json", action="store_true", help="output structured JSON")

    w_exec = worker_sub.add_parser("execute", help="execute an authorized action plan")
    w_exec.add_argument("plan", help="path to ActionPlan JSON file")
    w_exec.add_argument("--authorization", required=True, help="authorization ID or path to authorization JSON file")
    w_exec.add_argument("--worker-id", default="worker-local-01", help="override worker identity")
    w_exec.add_argument("--engagement", type=Path, help="path to engagement JSON file for scope enforcement")
    w_exec.add_argument("--db", type=Path, help="path to sqlite approval store")
    w_exec.add_argument("--json", action="store_true", help="output structured JSON")

    eng_p = subparsers.add_parser("engagement", help="authorized engagement intake, scope validation, and action planning")
    eng_sub = eng_p.add_subparsers(dest="engagement_command", required=True)

    e_create = eng_sub.add_parser("create", help="create and validate a new engagement intake contract")
    e_create.add_argument("--name", required=True, help="engagement name")
    e_create.add_argument("--owner", "--operator", dest="owner", required=True, help="engagement operator or owner")
    e_create.add_argument("--targets", required=True, help="comma-separated included targets")
    e_create.add_argument("--exclusions", default="", help="comma-separated excluded targets")
    e_create.add_argument("--start", required=True, help="window started_at (ISO-8601)")
    e_create.add_argument("--until", required=True, help="window authorized_until_utc (ISO-8601)")
    e_create.add_argument("--allowed-effects", "--allowed-actions", dest="allowed_effects", help="comma-separated allowed effects/actions")
    e_create.add_argument("--max-intensity", choices=["low", "medium", "high"], default="low", help="maximum execution intensity")
    e_create.add_argument("--emergency-contact", default="security-ops@internal.net", help="emergency contact")
    e_create.add_argument("--no-safe-mode", action="store_true", help="disable safe mode (default is enabled)")
    e_create.add_argument("--mode", choices=["planning", "import", "laboratory", "live"], default="planning", help="execution mode")
    e_create.add_argument("--budget-duration", type=int, help="max duration in seconds")
    e_create.add_argument("--budget-output-bytes", type=int, help="max output in bytes")
    e_create.add_argument("--credentials", help="comma-separated credential references")
    e_create.add_argument("--id", help="optional explicit engagement ID")
    e_create.add_argument("--output", help="path to save engagement JSON file")

    e_val = eng_sub.add_parser("validate", help="validate an engagement intake file")
    e_val.add_argument("file", help="path to engagement JSON file")
    e_val.add_argument("--json", action="store_true", help="output structured JSON")

    e_plan = eng_sub.add_parser("plan", help="produce an immutable reviewable action plan from engagement and scenario")
    e_plan.add_argument("--engagement", required=True, help="path to engagement contract JSON file")
    e_plan.add_argument("--scenario", required=True, help="scenario ID (e.g. COPS-E03.01-S01) or path to scenario JSON")
    e_plan.add_argument("--target", required=True, help="target from engagement included_targets")
    e_plan.add_argument("--specialist", default="cops-pentest-specialist", help="specialist profile ID")
    e_plan.add_argument("--mode", choices=["planning", "import", "laboratory", "live"], help="override execution mode")
    e_plan.add_argument("--output", help="path to save ActionPlan JSON file")
    e_plan.add_argument("--json", action="store_true", help="output JSON to stdout")

    e_info = eng_sub.add_parser("info", help="display details of an engagement contract")
    e_info.add_argument("file", help="path to engagement JSON file")
    e_info.add_argument("--json", action="store_true", help="output structured JSON")

    e_handoff = eng_sub.add_parser("handoff", help="specialist routing and bounded workflow handoffs")
    e_h_sub = e_handoff.add_subparsers(dest="handoff_command", required=True)

    h_propose = e_h_sub.add_parser("propose", help="propose specialist handoff from planner")
    h_propose.add_argument("--engagement", required=True, type=Path, help="path to engagement contract")
    h_propose.add_argument("--plan", required=True, type=Path, help="path to action plan contract")
    h_propose.add_argument("--task", required=True, help="task description")
    h_propose.add_argument("--planner", default="secops-lead", help="planner identifier")
    h_propose.add_argument("--specialist", help="target specialist profile ID (default: auto-route)")
    h_propose.add_argument("--output", help="output path for handoff JSON")
    h_propose.add_argument("--json", action="store_true", help="output JSON")

    h_accept = e_h_sub.add_parser("accept", help="specialist accepts handoff with capability validation")
    h_accept.add_argument("--handoff", required=True, type=Path, help="path to proposed handoff JSON")
    h_accept.add_argument("--specialist", required=True, help="specialist profile ID")
    h_accept.add_argument("--output", help="output path for updated handoff JSON")
    h_accept.add_argument("--json", action="store_true", help="output JSON")

    h_review = e_h_sub.add_parser("review", help="skeptic reviews evidence envelopes")
    h_review.add_argument("--handoff", required=True, type=Path, help="path to accepted handoff JSON")
    h_review.add_argument("--skeptic", default="cops-threat-hunter", help="skeptic specialist ID")
    h_review.add_argument("--evidence", nargs="*", help="evidence envelope references")
    h_review.add_argument("--findings", nargs="*", help="finding IDs")
    h_review.add_argument("--output", help="output path for updated handoff JSON")
    h_review.add_argument("--json", action="store_true", help="output JSON")

    h_audit = e_h_sub.add_parser("audit", help="auditor verifies plan bounds and approves handoff")
    h_audit.add_argument("--handoff", required=True, type=Path, help="path to reviewed handoff JSON")
    h_audit.add_argument("--plan", required=True, type=Path, help="path to approved action plan contract")
    h_audit.add_argument("--auditor", default="cops-compliance-auditor", help="auditor specialist ID")
    h_audit.add_argument("--output", help="output path for approved handoff JSON")
    h_audit.add_argument("--json", action="store_true", help="output JSON")

    h_workflow = e_h_sub.add_parser("workflow", help="orchestrate complete Triad handoff workflow")
    h_workflow.add_argument("--engagement", required=True, type=Path, help="path to engagement contract")
    h_workflow.add_argument("--plan", required=True, type=Path, help="path to action plan contract")
    h_workflow.add_argument("--task", required=True, help="task description")
    h_workflow.add_argument("--planner", default="secops-lead", help="planner identifier")
    h_workflow.add_argument("--specialist", help="target specialist profile ID (default: auto-route)")
    h_workflow.add_argument("--output", help="output path for completed handoff JSON")
    h_workflow.add_argument("--json", action="store_true", help="output JSON")

    lab_p = subparsers.add_parser("lab", help="manage scenario laboratory environments and harness execution")
    lab_sub = lab_p.add_subparsers(dest="lab_command", required=True)

    l_reg = lab_sub.add_parser("register", help="register a laboratory environment contract")
    l_reg.add_argument("environment", help="path to laboratory environment JSON or inline JSON")
    l_reg.add_argument("--output", help="output path for registered environment JSON")

    l_ver = lab_sub.add_parser("verify", help="verify laboratory environment isolation, prerequisites, and canary")
    l_ver.add_argument("environment", help="path to laboratory environment JSON")
    l_ver.add_argument("--tools", help="comma-separated list of required tools")
    l_ver.add_argument("--mock", action="store_true", default=True, help="use mock checks for offline testing")
    l_ver.add_argument("--output", help="output path for verified environment JSON")

    l_res = lab_sub.add_parser("reset", help="reproducible reset of laboratory environment")
    l_res.add_argument("environment", help="path to laboratory environment JSON")
    l_res.add_argument("--mock", action="store_true", default=True, help="use mock reset")
    l_res.add_argument("--output", help="output path for reset environment JSON")

    l_mat = lab_sub.add_parser("matrix", help="display tested platform and tool matrix")
    l_mat.add_argument("--output", help="output path for matrix JSON")

    l_run = lab_sub.add_parser("run", help="execute a laboratory test case")
    l_run.add_argument("--environment", required=True, help="path to laboratory environment JSON")
    l_run.add_argument("--plan", required=True, help="path to action plan JSON")
    l_run.add_argument("--authorization", required=True, help="path to execution authorization JSON")
    l_run.add_argument("--case-type", choices=["positive", "negative", "remediated"], default="positive", help="case type")
    l_run.add_argument("--store", help="path to sqlite3 approval store")
    l_run.add_argument("--allowed-cidr", help="allowed network CIDR for scope guard")
    l_run.add_argument("--output", help="output path for case result JSON")

    return parser


def main(argv: list[str] | None = None, *, root: Path = ROOT) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            return command_list(root)
        if args.command == "info":
            return command_info(args.plugin_id, root)
        if args.command == "doctor":
            return command_doctor(contributor=args.contributor, root=root)
        if args.command == "validate":
            return command_validate(args.plugin_ids, root)
        if args.command == "demo":
            return command_demo(args.plugin_id, root)
        if args.command == "check":
            return command_check(args.plugin_ids, root)
        if args.command == "generate":
            return command_generate(check=args.check, root=root)
        if args.command == "coverage":
            return command_coverage(
                matrix=args.matrix,
                output=args.output,
                check=args.check,
                gaps=args.gaps,
                profile_path=args.profile,
                export_flow=args.export_flow,
                output_flow=args.output_flow,
                as_json=args.json,
                root=root,
            )
        if args.command == "route":
            from .routing.cli import command_route
            return command_route(args)
        if args.command == "specialists":
            from .routing.cli import command_list as spec_list
            return spec_list(args)
        if args.command == "contract":
            if args.contract_command == "validate":
                return command_contract_validate(args.file, args.type)
            if args.contract_command == "transition":
                return command_contract_transition(args.current, args.target, args.type)
        if args.command == "scenario":
            if args.scenario_command == "list":
                return command_scenario_list(family_id=args.family_id, tactic=args.tactic, coverage_mode=args.coverage_mode, as_json=args.json, root=root)
            if args.scenario_command == "info":
                return command_scenario_info(args.scenario_id, as_json=args.json, root=root)
            if args.scenario_command == "validate":
                return command_scenario_validate(root=root)
            if args.scenario_command == "provenance":
                return command_scenario_provenance(source_id=args.source_id, as_json=args.json, root=root)
        if args.command == "capabilities":
            if args.capabilities_command == "list":
                return command_capabilities_list(mode=args.mode, kind=args.kind, as_json=args.json, root=root)
            if args.capabilities_command == "audit":
                return command_capabilities_audit(check=args.check, root=root)
            if args.capabilities_command == "matrix":
                return command_capabilities_matrix(output=args.output, root=root)
        if args.command == "worker":
            if args.worker_command == "status":
                return command_worker_status(args)
            if args.worker_command == "store":
                return command_worker_store_list(args)
            if args.worker_command == "execute":
                return command_worker_execute(args)
        if args.command == "engagement":
            from .engagement.cli import (
                command_engagement_create,
                command_engagement_handoff,
                command_engagement_info,
                command_engagement_plan,
                command_engagement_validate,
            )
            if args.engagement_command == "create":
                return command_engagement_create(args)
            if args.engagement_command == "validate":
                return command_engagement_validate(args)
            if args.engagement_command == "plan":
                return command_engagement_plan(args)
            if args.engagement_command == "info":
                return command_engagement_info(args)
            if args.engagement_command == "handoff":
                return command_engagement_handoff(args)
        if args.command == "lab":
            from .laboratory.cli import command_laboratory
            return command_laboratory(args, root=root)
    except (CatalogError, ValidationError, CoverageError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    parser.error(f"unsupported command: {args.command}")
    return 2
