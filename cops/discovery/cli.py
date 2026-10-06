"""CLI interface for passive, active, and infrastructure asset discovery and assessment."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .active_models import (
    ActiveScanSession,
    ScanBudget,
)
from .active_scanner import (
    ActiveScanner,
    OfflineSyntheticDispatcher,
    StandardSocketDispatcher,
    compare_active_scans,
)
from .data_collector import (
    OfflineSyntheticDataCollector,
    StandardSocketDataCollector,
    assess_data_services,
)
from .data_models import (
    DataServicesReport,
)
from .developer_collector import (
    OfflineSyntheticDeveloperCollector,
    StandardSocketDeveloperCollector,
    assess_developer_services,
)
from .developer_models import (
    DeveloperServicesReport,
)
from .importer import import_masscan_json, import_nmap_xml
from .infra_collector import (
    OfflineSyntheticInfraCollector,
    StandardSocketInfraCollector,
    assess_infrastructure_services,
)
from .infra_models import (
    InfraAssessmentReport,
)
from .legacy_collector import (
    OfflineSyntheticLegacyCollector,
    StandardSocketLegacyCollector,
    assess_legacy_services,
)
from .legacy_models import (
    LegacyServicesReport,
)
from .merger import merge_inventories
from .messaging_collector import (
    OfflineSyntheticMessagingCollector,
    StandardSocketMessagingCollector,
    assess_messaging_services,
)
from .messaging_models import (
    MessagingServicesReport,
)
from .models import DiscoveredAsset, DiscoveryInventory, EvidenceProvenance
from .normalizers import (
    normalize_certificate_record,
    normalize_cloud_export,
    normalize_dns_record,
    normalize_endpoint_record,
    normalize_ip_record,
)
from .reconciler import reconcile_inventory
from .remote_collector import (
    OfflineSyntheticRemoteCollector,
    StandardSocketRemoteCollector,
    assess_remote_services,
)
from .remote_models import (
    RemoteServicesReport,
)

ROOT: Path = Path(__file__).resolve().parents[2]


def build_active_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for active network discovery and assessment."""
    active_subs = parser.add_subparsers(dest="active_command", required=True)

    # 1. plan
    plan_p = active_subs.add_parser("plan", help="Create an active scanning session plan with budgets and targets.")
    plan_p.add_argument("--targets", "-t", required=True, help="Comma-separated target hosts/IPs or path to JSON.")
    plan_p.add_argument("--ports", "-p", default="80,443,22", help="Comma-separated ports (default: 80,443,22).")
    plan_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Scan vantage point.")
    plan_p.add_argument("--rate-limit", type=float, default=10.0, help="Max probes per second (default: 10.0).")
    plan_p.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds (default: 2.0).")
    plan_p.add_argument("--max-total-seconds", type=float, default=None, help="Maximum total execution budget in seconds.")
    plan_p.add_argument("--scope-ref", default="authorized-scope", help="Reference identifier of authorized scope.")
    plan_p.add_argument("--output", "-o", default=None, help="Output path for session JSON.")

    # 2. scan
    scan_p = active_subs.add_parser("scan", help="Run bounded active assessment against planned session.")
    scan_p.add_argument("session", help="Path to ActiveScanSession plan JSON.")
    scan_p.add_argument("--scope", "-s", default=None, help="Path to scope boundaries JSON (for DNS rebind/exclusion enforcement).")
    scan_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Execution mode (default: synthetic offline).")
    scan_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON for synthetic dispatcher.")
    scan_p.add_argument("--checkpoint", "-c", default=None, help="Path to save execution checkpoint.")
    scan_p.add_argument("--output", "-o", default=None, help="Output path for completed session JSON.")

    # 3. resume
    res_p = active_subs.add_parser("resume", help="Resume interrupted active scan session from checkpoint.")
    res_p.add_argument("checkpoint", help="Path to session checkpoint JSON.")
    res_p.add_argument("--scope", "-s", default=None, help="Path to scope boundaries JSON.")
    res_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Execution mode.")
    res_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    res_p.add_argument("--checkpoint-out", default=None, help="Path to save updated checkpoint.")
    res_p.add_argument("--output", "-o", default=None, help="Output path for completed session JSON.")

    # 4. diff
    diff_p = active_subs.add_parser("diff", help="Compare baseline and current active scan sessions for remediated exposures.")
    diff_p.add_argument("baseline", help="Path to baseline session JSON.")
    diff_p.add_argument("current", help="Path to current/re-test session JSON.")
    diff_p.add_argument("--output", "-o", default=None, help="Output path for scan delta JSON.")

    # 5. import
    imp_p = active_subs.add_parser("import", help="Import Masscan or Nmap output into active discovery session.")
    imp_p.add_argument("file", help="Path to Masscan JSON or Nmap XML output file.")
    imp_p.add_argument("--tool", choices=["masscan", "nmap"], required=True, help="Tool that generated the output.")
    imp_p.add_argument("--vantage", default="external", help="Scan vantage point (default: external).")
    imp_p.add_argument("--scope-ref", default="imported-scan", help="Scope reference.")
    imp_p.add_argument("--output", "-o", default=None, help="Output path for imported session JSON.")


def build_infra_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for infrastructure and identity service assessment."""
    infra_subs = parser.add_subparsers(dest="infra_command", required=True)

    # 1. assess
    ass_p = infra_subs.add_parser("assess", help="Assess infrastructure and identity-facing services.")
    ass_p.add_argument("--targets", "-t", required=True, help="Comma-separated targets or path to JSON.")
    ass_p.add_argument("--services", "-s", default=None, help="Comma-separated service types (dns,mdns,snmp,ntp,rpc,ldap,kerberos,discovery).")
    ass_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Probe vantage.")
    ass_p.add_argument("--scope-ref", default="authorized-scope", help="Scope reference.")
    ass_p.add_argument("--canary-id", default=None, help="Canary record / controlled identity identifier.")
    ass_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Collector mode.")
    ass_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    ass_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 2. candidates
    cand_p = infra_subs.add_parser("candidates", help="Export identity attack-path candidates for AD inventory handoff.")
    cand_p.add_argument("report", help="Path to InfraAssessmentReport JSON.")
    cand_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 3. inspect
    insp_p = infra_subs.add_parser("inspect", help="Inspect and summarize infrastructure service assessment report.")
    insp_p.add_argument("report", help="Path to InfraAssessmentReport JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_remote_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for remote admin, file sharing, and printing service assessment."""
    remote_subs = parser.add_subparsers(dest="remote_command", required=True)

    # 1. assess
    ass_p = remote_subs.add_parser("assess", help="Assess remote administration, file sharing, and printing services.")
    ass_p.add_argument("--targets", "-t", required=True, help="Comma-separated targets or path to JSON.")
    ass_p.add_argument("--services", "-s", default=None, help="Comma-separated service types (ssh,telnet,rdp,vnc,winrm,x11,smb,nfs,ftp,tftp,rsync,afp,lpd,ipp,raw_print).")
    ass_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Probe vantage.")
    ass_p.add_argument("--scope-ref", default="authorized-scope", help="Scope reference.")
    ass_p.add_argument("--canary-id", default=None, help="Canary record / controlled identity / canary file / canary print job identifier.")
    ass_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Collector mode.")
    ass_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    ass_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 2. candidates
    cand_p = remote_subs.add_parser("candidates", help="Export host privilege candidates for lateral movement specialists.")
    cand_p.add_argument("report", help="Path to RemoteServicesReport JSON.")
    cand_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 3. cleanup
    clean_p = remote_subs.add_parser("cleanup", help="Export verified cleanup receipts for canary artifacts.")
    clean_p.add_argument("report", help="Path to RemoteServicesReport JSON.")
    clean_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 4. inspect
    insp_p = remote_subs.add_parser("inspect", help="Inspect and summarize remote services assessment report.")
    insp_p.add_argument("report", help="Path to RemoteServicesReport JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_data_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for database, cache, and search/analytics service assessment."""
    data_subs = parser.add_subparsers(dest="data_command", required=True)

    # 1. assess
    ass_p = data_subs.add_parser("assess", help="Assess databases, caches, and search/analytics services.")
    ass_p.add_argument("--targets", "-t", required=True, help="Comma-separated targets or path to JSON.")
    ass_p.add_argument("--services", "-s", default=None, help="Comma-separated service types (mysql,postgres,mssql,oracle,mongodb,couchdb,cassandra,redis,memcached,elasticsearch,influxdb,kibana,splunk).")
    ass_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Probe vantage.")
    ass_p.add_argument("--scope-ref", default="authorized-scope", help="Scope reference.")
    ass_p.add_argument("--canary-id", default=None, help="Canary record / query / key / index identifier.")
    ass_p.add_argument("--query-budget", type=int, default=5, help="Maximum sample rows/documents to inspect without bulk extraction (default: 5).")
    ass_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Collector mode.")
    ass_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    ass_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 2. candidates
    cand_p = data_subs.add_parser("candidates", help="Export data privilege candidates for database takeover or lateral movement workflows.")
    cand_p.add_argument("report", help="Path to DataServicesReport JSON.")
    cand_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 3. cleanup
    clean_p = data_subs.add_parser("cleanup", help="Export verified cleanup receipts for canary records.")
    clean_p.add_argument("report", help="Path to DataServicesReport JSON.")
    clean_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 4. inspect
    insp_p = data_subs.add_parser("inspect", help="Inspect and summarize database, cache, and search assessment report.")
    insp_p.add_argument("report", help="Path to DataServicesReport JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_messaging_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for mail, chat, and message broker service assessment."""
    msg_subs = parser.add_subparsers(dest="messaging_command", required=True)

    # 1. assess
    ass_p = msg_subs.add_parser("assess", help="Assess mail, chat, and message broker services.")
    ass_p.add_argument("--targets", "-t", required=True, help="Comma-separated targets or path to JSON.")
    ass_p.add_argument("--services", "-s", default=None, help="Comma-separated service types (smtp,pop3,imap,irc,rabbitmq,nats,ibmmq,kafka,mqtt).")
    ass_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Probe vantage.")
    ass_p.add_argument("--scope-ref", default="authorized-scope", help="Scope reference.")
    ass_p.add_argument("--canary-id", default=None, help="Canary message / queue / mailbox / topic identifier.")
    ass_p.add_argument("--message-budget", type=int, default=5, help="Maximum sample messages to transmit or inspect (default: 5).")
    ass_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Collector mode.")
    ass_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    ass_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 2. candidates
    cand_p = msg_subs.add_parser("candidates", help="Export messaging privilege candidates for unauthorized relay or broker takeover.")
    cand_p.add_argument("report", help="Path to MessagingServicesReport JSON.")
    cand_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 3. cleanup
    clean_p = msg_subs.add_parser("cleanup", help="Export verified cleanup receipts for canary messages and queues.")
    clean_p.add_argument("report", help="Path to MessagingServicesReport JSON.")
    clean_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 4. inspect
    insp_p = msg_subs.add_parser("inspect", help="Inspect and summarize mail, chat, and message broker assessment report.")
    insp_p.add_argument("report", help="Path to MessagingServicesReport JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_developer_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for developer and runtime interface service assessment."""
    dev_subs = parser.add_subparsers(dest="developer_command", required=True)

    # 1. assess
    ass_p = dev_subs.add_parser("assess", help="Assess developer and runtime interface services.")
    ass_p.add_argument("--targets", "-t", required=True, help="Comma-separated targets or path to JSON.")
    ass_p.add_argument("--services", "-s", default=None, help="Comma-separated service types (docker,docker_registry,rmi,jdwp,erlang_epmd,adb,distcc,svn,ajp,fastcgi).")
    ass_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Probe vantage.")
    ass_p.add_argument("--scope-ref", default="authorized-scope", help="Scope reference.")
    ass_p.add_argument("--canary-id", default=None, help="Canary record / container / debug session / code artifact identifier.")
    ass_p.add_argument("--allow-code-execution", action="store_true", default=False, help="Explicitly authorize code execution probes bound to the approved plan.")
    ass_p.add_argument("--allow-state-change", action="store_true", default=False, help="Explicitly authorize state change probes bound to the approved plan.")
    ass_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Collector mode.")
    ass_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    ass_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 2. candidates
    cand_p = dev_subs.add_parser("candidates", help="Export developer privilege candidates for code execution or breakout workflows.")
    cand_p.add_argument("report", help="Path to DeveloperServicesReport JSON.")
    cand_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 3. cleanup
    clean_p = dev_subs.add_parser("cleanup", help="Export verified cleanup receipts for canary artifacts.")
    clean_p.add_argument("report", help="Path to DeveloperServicesReport JSON.")
    clean_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 4. inspect
    insp_p = dev_subs.add_parser("inspect", help="Inspect and summarize developer and runtime interfaces assessment report.")
    insp_p.add_argument("report", help="Path to DeveloperServicesReport JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_legacy_parser(parser: argparse.ArgumentParser) -> None:
    """Build sub-commands for legacy enterprise, management, and proxy service assessment."""
    leg_subs = parser.add_subparsers(dest="legacy_command", required=True)

    # 1. assess
    ass_p = leg_subs.add_parser("assess", help="Assess legacy enterprise, management, and proxy services.")
    ass_p.add_argument("--targets", "-t", required=True, help="Comma-separated targets or path to JSON.")
    ass_p.add_argument("--services", "-s", default=None, help="Comma-separated service types (ndmp,iscsi,ipmi,cisco_smart_install,tacacs,ike,pptp,socks,squid).")
    ass_p.add_argument("--vantage", default="external", choices=["external", "internal", "egress_point", "cloud_tenant"], help="Probe vantage.")
    ass_p.add_argument("--scope-ref", default="authorized-scope", help="Scope reference.")
    ass_p.add_argument("--canary-id", default=None, help="Canary record / container / debug session / code artifact identifier.")
    ass_p.add_argument("--allow-code-execution", action="store_true", default=False, help="Explicitly authorize code execution probes bound to the approved plan.")
    ass_p.add_argument("--allow-state-change", action="store_true", default=False, help="Explicitly authorize state change probes bound to the approved plan.")
    ass_p.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Collector mode.")
    ass_p.add_argument("--offline-targets", default=None, help="Path to mock targets JSON.")
    ass_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 2. candidates
    cand_p = leg_subs.add_parser("candidates", help="Export legacy privilege candidates for takeover or proxy egress pivoting.")
    cand_p.add_argument("report", help="Path to LegacyServicesReport JSON.")
    cand_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 3. cleanup
    clean_p = leg_subs.add_parser("cleanup", help="Export verified cleanup receipts for canary artifacts.")
    clean_p.add_argument("report", help="Path to LegacyServicesReport JSON.")
    clean_p.add_argument("--output", "-o", default=None, help="Output JSON path.")

    # 4. inspect
    insp_p = leg_subs.add_parser("inspect", help="Inspect and summarize legacy enterprise and proxy services assessment report.")
    insp_p.add_argument("report", help="Path to LegacyServicesReport JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_discovery_parser(subparsers: argparse._SubParsersAction[Any]) -> argparse.ArgumentParser:
    """Build the discovery sub-parser for cops CLI."""
    parser = subparsers.add_parser(
        "discovery",
        help="Passive, active, and infrastructure asset discovery, service identification, and scope reconciliation.",
        description="Normalize asset telemetry, run bounded active assessment, and evaluate infrastructure service posture.",
    )
    disc_subs = parser.add_subparsers(dest="discovery_command", required=True)

    # Passive Subcommand: normalize
    norm_p = disc_subs.add_parser("normalize", help="Normalize raw asset records into DiscoveredAsset schema.")
    norm_p.add_argument("file", help="Path to JSON file containing raw records or single record.")
    norm_p.add_argument(
        "--type",
        "-t",
        required=True,
        choices=["dns", "cert", "certificate", "ip", "endpoint", "cloud"],
        help="Type of asset record to normalize.",
    )
    norm_p.add_argument("--source-id", default="S01", help="Provenance source ID (default: S01).")
    norm_p.add_argument("--output", "-o", default=None, help="Output JSON path (prints to stdout if omitted).")

    # Passive Subcommand: reconcile
    rec_p = disc_subs.add_parser("reconcile", help="Reconcile inventory against approved scope and quarantine uncertain assets.")
    rec_p.add_argument("inventory", help="Path to discovery inventory JSON.")
    rec_p.add_argument("--scope", "-s", required=True, help="Path to engagement scope or action plan JSON.")
    rec_p.add_argument("--output", "-o", default=None, help="Output JSON path (prints to stdout if omitted).")

    # Passive Subcommand: merge
    merge_p = disc_subs.add_parser("merge", help="Merge and deduplicate multiple discovery inventory files.")
    merge_p.add_argument("files", nargs="+", help="Paths to discovery inventory JSON files to merge.")
    merge_p.add_argument("--output", "-o", default=None, help="Output JSON path (prints to stdout if omitted).")

    # Passive Subcommand: inspect
    insp_p = disc_subs.add_parser("inspect", help="Inspect and summarize discovery inventory.")
    insp_p.add_argument("inventory", help="Path to discovery inventory JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # Active Subcommands under discovery
    active_p = disc_subs.add_parser("active", help="Bounded active discovery and service identification.")
    build_active_parser(active_p)

    # Infrastructure Subcommands under discovery
    infra_p = disc_subs.add_parser("infrastructure", help="Assess infrastructure and identity-facing services.")
    build_infra_parser(infra_p)

    # Remote Administration, File Sharing, and Printing Subcommands under discovery
    remote_p = disc_subs.add_parser("remote", help="Assess remote administration, file sharing, and printing services.")
    build_remote_parser(remote_p)

    # Database, Cache, and Search Subcommands under discovery
    data_p = disc_subs.add_parser("data", help="Assess databases, caches, and search/analytics services.")
    build_data_parser(data_p)

    # Mail, Chat, and Message Broker Subcommands under discovery
    msg_p = disc_subs.add_parser("messaging", help="Assess mail, chat, and message broker services.")
    build_messaging_parser(msg_p)

    # Developer and Runtime Interfaces Subcommands under discovery
    dev_p = disc_subs.add_parser("developer", help="Assess developer and runtime interface services.")
    build_developer_parser(dev_p)

    # Legacy Enterprise, Management, and Proxy Services Subcommands under discovery
    leg_p = disc_subs.add_parser("legacy", help="Assess legacy enterprise, management, and proxy services.")
    build_legacy_parser(leg_p)

    return parser


def command_active_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle active discovery CLI subcommands."""
    active_cmd = getattr(args, "active_command", None)

    if active_cmd == "plan":
        # Resolve targets
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else t_data.get("targets", [])
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        budget = ScanBudget(
            timeout_seconds=args.timeout,
            max_total_seconds=args.max_total_seconds,
            rate_limit_pps=args.rate_limit,
        )
        h = hashlib.sha256(f"{args.scope_ref}:{sorted(targets)}:{sorted(ports)}".encode()).hexdigest()[:16]
        session = ActiveScanSession(
            session_id=f"active-{h}",
            scope_reference=args.scope_ref,
            approved_targets=targets,
            approved_ports=ports,
            vantage=args.vantage,
            budget=budget,
        )
        out_json = json.dumps(session.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Created active scan session plan at {args.output}")
        else:
            print(out_json)
        return 0

    if active_cmd == "scan":
        session_path = Path(args.session)
        session = ActiveScanSession.load_checkpoint(session_path)

        scope_dict = None
        if args.scope and Path(args.scope).is_file():
            sc_raw = json.loads(Path(args.scope).read_text(encoding="utf-8"))
            scope_dict = sc_raw.get("scope", sc_raw)

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            dispatcher = OfflineSyntheticDispatcher(targets=mock_targets)
        else:
            dispatcher = StandardSocketDispatcher()

        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=scope_dict)
        completed_session = scanner.run()

        if args.checkpoint:
            completed_session.save_checkpoint(args.checkpoint)

        out_json = json.dumps(completed_session.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Active scan complete (status: {completed_session.status}, probes: {completed_session.total_probes_dispatched}) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if active_cmd == "resume":
        checkpoint_path = Path(args.checkpoint)
        session = ActiveScanSession.load_checkpoint(checkpoint_path)

        scope_dict = None
        if args.scope and Path(args.scope).is_file():
            sc_raw = json.loads(Path(args.scope).read_text(encoding="utf-8"))
            scope_dict = sc_raw.get("scope", sc_raw)

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            dispatcher = OfflineSyntheticDispatcher(targets=mock_targets)
        else:
            dispatcher = StandardSocketDispatcher()

        scanner = ActiveScanner(session=session, dispatcher=dispatcher, scope=scope_dict)
        resumed_session = scanner.run()

        save_chk = args.checkpoint_out or args.checkpoint
        resumed_session.save_checkpoint(save_chk)

        out_json = json.dumps(resumed_session.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Resumed active scan complete (status: {resumed_session.status}) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if active_cmd == "diff":
        base_session = ActiveScanSession.load_checkpoint(args.baseline)
        curr_session = ActiveScanSession.load_checkpoint(args.current)
        delta = compare_active_scans(base_session, curr_session)
        out_json = json.dumps(delta.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Scan delta ({len(delta.remediated_exposures)} remediated, {delta.remediation_rate}% rate) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if active_cmd == "import":
        file_path = Path(args.file)
        if args.tool == "masscan":
            imported = import_masscan_json(file_path, vantage=args.vantage, scope_ref=args.scope_ref)
        elif args.tool == "nmap":
            imported = import_nmap_xml(file_path, vantage=args.vantage, scope_ref=args.scope_ref)
        else:
            print(f"Unsupported tool: {args.tool}", file=sys.stderr)
            return 1

        out_json = json.dumps(imported.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Imported {len(imported.assessments)} assessments from {args.tool} saved to {args.output}")
        else:
            print(out_json)
        return 0

    return 0


def command_infra_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle infrastructure service discovery CLI subcommands."""
    infra_cmd = getattr(args, "infra_command", None)

    if infra_cmd == "assess":
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else t_data.get("targets", [])
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        services = [s.strip().lower() for s in args.services.split(",") if s.strip()] if args.services else None

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            collector = OfflineSyntheticInfraCollector(targets=mock_targets)
        else:
            collector = StandardSocketInfraCollector()

        report = assess_infrastructure_services(
            targets=targets,
            service_types=services,
            collector=collector,
            vantage=args.vantage,
            scope_ref=args.scope_ref,
            canary_id=args.canary_id,
        )

        out_json = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Assessed {len(report.services_assessed)} infrastructure services ({len(report.attack_path_candidates)} candidates) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if infra_cmd == "candidates":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates = report_data.get("attack_path_candidates", [])

        out_json = json.dumps(candidates, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(candidates)} identity attack path candidates to {args.output}")
        else:
            print(out_json)
        return 0

    if infra_cmd == "inspect":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        report = InfraAssessmentReport.from_dict(report_data)

        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return 0

        print(f"=== Infrastructure & Identity Services Report ({report.report_id}) ===")
        print(f"Scope Reference:   {report.scope_reference}")
        print(f"Probe Vantage:     {report.vantage}")
        print(f"Total Assessed:    {report.summary.get('total_services', len(report.services_assessed))}")
        print(f"Exposed:           {report.summary.get('exposed', 0)}")
        print(f"Protected:         {report.summary.get('protected', 0)}")
        print(f"Inaccessible:      {report.summary.get('inaccessible', 0)}")
        print(f"Attack Path Cand:  {report.summary.get('attack_path_candidates', len(report.attack_path_candidates))}")
        print()
        for s in report.services_assessed:
            status_icon = "!" if s.exposure_status in ("exposed", "misconfigured") else ("✓" if s.exposure_status == "protected" else "?")
            cand_marker = f" -> CANDIDATE: {s.attack_path_candidate.attack_path_type}" if s.attack_path_candidate else ""
            print(f"  [{status_icon}] {s.service_type.upper():<10} {s.target_host}:{s.port:<5} {s.exposure_status:<14} (auth: {s.auth_prerequisite}){cand_marker}")
        if report.summary.get("inaccessible", 0) > 0:
            print()
            print("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened.")
        return 0

    return 0


def command_remote_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle remote admin, file sharing, and printing discovery CLI subcommands."""
    remote_cmd = getattr(args, "remote_command", None)

    if remote_cmd == "assess":
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else (t_data.get("targets") or list(t_data.keys()))
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        services = [s.strip().lower() for s in args.services.split(",") if s.strip()] if args.services else None

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            collector = OfflineSyntheticRemoteCollector(targets=mock_targets)
        else:
            collector = StandardSocketRemoteCollector()

        report = assess_remote_services(
            targets=targets,
            service_types=services,
            collector=collector,
            vantage=args.vantage,
            scope_ref=args.scope_ref,
            canary_id=args.canary_id,
        )

        out_json = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Assessed {len(report.services_assessed)} remote/file/print services ({len(report.host_privilege_candidates)} candidates, {len(report.cleanup_receipts)} cleanup receipts) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if remote_cmd == "candidates":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates = report_data.get("host_privilege_candidates", [])

        out_json = json.dumps(candidates, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(candidates)} host privilege candidates to {args.output}")
        else:
            print(out_json)
        return 0

    if remote_cmd == "cleanup":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        receipts = report_data.get("cleanup_receipts", [])

        out_json = json.dumps(receipts, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(receipts)} cleanup receipts to {args.output}")
        else:
            print(out_json)
        return 0

    if remote_cmd == "inspect":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        report = RemoteServicesReport.from_dict(report_data)

        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return 0

        print(f"=== Remote Administration, File Sharing & Printing Report ({report.report_id}) ===")
        print(f"Scope Reference:     {report.scope_reference}")
        print(f"Probe Vantage:       {report.vantage}")
        print(f"Total Assessed:      {report.summary.get('total_services', len(report.services_assessed))}")
        print(f"Exposed:             {report.summary.get('exposed', 0)}")
        print(f"Protected:           {report.summary.get('protected', 0)}")
        print(f"Inaccessible:        {report.summary.get('inaccessible', 0)}")
        print(f"Host Privilege Cand: {report.summary.get('host_privilege_candidates', len(report.host_privilege_candidates))}")
        print(f"Cleanup Receipts:    {report.summary.get('cleanup_receipts', len(report.cleanup_receipts))}")
        print()
        for s in report.services_assessed:
            status_icon = "!" if s.exposure_status in ("exposed", "misconfigured") else ("✓" if s.exposure_status in ("protected", "remediated") else "?")
            cand_types = [c.finding_type for c in s.host_privilege_candidates]
            cand_marker = f" -> CANDIDATES: {', '.join(cand_types)}" if cand_types else ""
            cat_label = s.category.upper() if isinstance(s.category, str) else s.category.value.upper()
            stype = s.service_type if isinstance(s.service_type, str) else s.service_type.value
            auth_val = s.auth_prerequisite if isinstance(s.auth_prerequisite, str) else s.auth_prerequisite.value
            exp_val = s.exposure_status if isinstance(s.exposure_status, str) else s.exposure_status.value
            print(f"  [{status_icon}] [{cat_label:<12}] {stype.upper():<10} {s.target_host}:{s.port:<5} {exp_val:<14} (auth: {auth_val}){cand_marker}")
        if report.summary.get("inaccessible", 0) > 0:
            print()
            print("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened.")
        return 0

    return 0


def command_data_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle database, cache, and search discovery CLI subcommands."""
    data_cmd = getattr(args, "data_command", None)

    if data_cmd == "assess":
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else (t_data.get("targets") or list(t_data.keys()))
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        services = [s.strip().lower() for s in args.services.split(",") if s.strip()] if args.services else None

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            collector = OfflineSyntheticDataCollector(targets=mock_targets)
        else:
            collector = StandardSocketDataCollector()

        report = assess_data_services(
            targets=targets,
            service_types=services,
            collector=collector,
            vantage=args.vantage,
            scope_ref=args.scope_ref,
            canary_id=args.canary_id,
            query_budget_rows=getattr(args, "query_budget", 5),
        )

        out_json = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Assessed {len(report.services_assessed)} data services ({len(report.privilege_candidates)} candidates, {len(report.cleanup_receipts)} cleanup receipts) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if data_cmd == "candidates":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates = report_data.get("privilege_candidates", [])

        out_json = json.dumps(candidates, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(candidates)} data privilege candidates to {args.output}")
        else:
            print(out_json)
        return 0

    if data_cmd == "cleanup":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        receipts = report_data.get("cleanup_receipts", [])

        out_json = json.dumps(receipts, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(receipts)} cleanup receipts to {args.output}")
        else:
            print(out_json)
        return 0

    if data_cmd == "inspect":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        report = DataServicesReport.from_dict(report_data)

        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return 0

        print(f"=== Databases, Caches & Search Services Report ({report.report_id}) ===")
        print(f"Scope Reference:      {report.scope_reference}")
        print(f"Probe Vantage:        {report.vantage}")
        print(f"Total Assessed:       {report.summary.get('total_services', len(report.services_assessed))}")
        print(f"Exposed:              {report.summary.get('exposed', 0)}")
        print(f"Protected:            {report.summary.get('protected', 0)}")
        print(f"Inaccessible:         {report.summary.get('inaccessible', 0)}")
        print(f"Privilege Candidates: {report.summary.get('privilege_candidates', len(report.privilege_candidates))}")
        print(f"Cleanup Receipts:     {report.summary.get('cleanup_receipts', len(report.cleanup_receipts))}")
        print()
        for s in report.services_assessed:
            status_icon = "!" if s.exposure_status in ("exposed", "misconfigured") else ("✓" if s.exposure_status in ("protected", "remediated") else "?")
            cand_types = [c.finding_type for c in s.privilege_candidates]
            cand_marker = f" -> CANDIDATES: {', '.join(cand_types)}" if cand_types else ""
            cat_label = s.category.upper() if isinstance(s.category, str) else s.category.value.upper()
            stype = s.service_type if isinstance(s.service_type, str) else s.service_type.value
            auth_val = s.auth_prerequisite if isinstance(s.auth_prerequisite, str) else s.auth_prerequisite.value
            exp_val = s.exposure_status if isinstance(s.exposure_status, str) else s.exposure_status.value
            print(f"  [{status_icon}] [{cat_label:<15}] {stype.upper():<14} {s.target_host}:{s.port:<5} {exp_val:<14} (auth: {auth_val}, role: {s.assigned_role}){cand_marker}")
        if report.summary.get("inaccessible", 0) > 0:
            print()
            print("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened.")
        return 0

    return 0


def command_messaging_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle mail, chat, and message broker service discovery CLI subcommands."""
    msg_cmd = getattr(args, "messaging_command", None)

    if msg_cmd == "assess":
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else t_data.get("targets", [])
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        services = None
        if args.services:
            services = [s.strip().lower() for s in args.services.split(",") if s.strip()]

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            collector = OfflineSyntheticMessagingCollector(targets=mock_targets)
        else:
            collector = StandardSocketMessagingCollector()

        report = assess_messaging_services(
            targets=targets,
            service_types=services,
            collector=collector,
            vantage=args.vantage,
            scope_ref=args.scope_ref,
            canary_id=args.canary_id,
            message_budget=getattr(args, "message_budget", 5),
        )

        out_json = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Assessed {len(report.assessments)} messaging services ({report.candidates_count} candidates, {report.cleanup_receipts_count} cleanup receipts) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if msg_cmd == "candidates":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates = []
        for ass in report_data.get("assessments", []):
            candidates.extend(ass.get("privilege_candidates", []))

        out_json = json.dumps(candidates, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(candidates)} messaging privilege candidates to {args.output}")
        else:
            print(out_json)
        return 0

    if msg_cmd == "cleanup":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        receipts = []
        for ass in report_data.get("assessments", []):
            receipts.extend(ass.get("cleanup_receipts", []))

        out_json = json.dumps(receipts, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(receipts)} cleanup receipts to {args.output}")
        else:
            print(out_json)
        return 0

    if msg_cmd == "inspect":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        report = MessagingServicesReport.from_dict(report_data)

        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return 0

        target_scope_str = ", ".join(report.target_scope)
        print(f"=== Mail, Messaging & Message Brokers Report ({report.report_id}) ===")
        print(f"Target Scope:         {target_scope_str}")
        print(f"Probe Vantage:        {report.vantage}")
        print(f"Total Assessed:       {report.total_probed}")
        print(f"Exposed:              {report.total_exposed}")
        print(f"Protected:            {report.total_protected}")
        print(f"Inaccessible:         {report.total_inaccessible}")
        print(f"Privilege Candidates: {report.candidates_count}")
        print(f"Cleanup Receipts:     {report.cleanup_receipts_count}")
        print()
        for s in report.assessments:
            status_icon = "!" if s.exposure_status in ("exposed", "misconfigured") else ("✓" if s.exposure_status in ("protected", "remediated") else "?")
            cand_types = [c.finding_type for c in s.privilege_candidates]
            cand_types_str = ", ".join(cand_types)
            cand_marker = f" -> CANDIDATES: {cand_types_str}" if cand_types else ""
            cat_label = s.category.upper() if isinstance(s.category, str) else s.category.value.upper()
            stype = s.service_type if isinstance(s.service_type, str) else s.service_type.value
            auth_val = s.auth_prerequisite if isinstance(s.auth_prerequisite, str) else s.auth_prerequisite.value
            exp_val = s.exposure_status if isinstance(s.exposure_status, str) else s.exposure_status.value
            print(f"  [{status_icon}] [{cat_label:<25}] {stype.upper():<10} {s.target_host}:{s.port:<5} {exp_val:<14} (auth: {auth_val}, role: {s.assigned_role}){cand_marker}")
        if report.total_inaccessible > 0:
            print()
            print("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened.")
        return 0

    return 0


def command_developer_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle developer and runtime interface discovery CLI subcommands."""
    dev_cmd = getattr(args, "developer_command", None)

    if dev_cmd == "assess":
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else (t_data.get("targets") or list(t_data.keys()))
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        services = [s.strip().lower() for s in args.services.split(",") if s.strip()] if args.services else None

        allow_exec = getattr(args, "allow_code_execution", False)
        allow_state = getattr(args, "allow_state_change", False)

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            collector = OfflineSyntheticDeveloperCollector(
                targets=mock_targets,
                allow_code_execution=allow_exec,
                allow_state_change=allow_state,
            )
        else:
            collector = StandardSocketDeveloperCollector(
                allow_code_execution=allow_exec,
                allow_state_change=allow_state,
            )

        report = assess_developer_services(
            targets=targets,
            service_types=services,
            collector=collector,
            vantage=args.vantage,
            scope_ref=args.scope_ref,
            canary_id=args.canary_id,
            allow_code_execution=allow_exec,
            allow_state_change=allow_state,
        )

        out_json = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Assessed {len(report.assessments)} developer interface services ({report.candidates_count} candidates, {report.cleanup_receipts_count} receipts) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if dev_cmd == "candidates":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates: list[dict[str, Any]] = []
        for assessment in report_data.get("assessments", []):
            candidates.extend(assessment.get("privilege_candidates", []))

        out_json = json.dumps(candidates, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(candidates)} developer privilege candidates to {args.output}")
        else:
            print(out_json)
        return 0

    if dev_cmd == "cleanup":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        receipts: list[dict[str, Any]] = []
        for assessment in report_data.get("assessments", []):
            receipts.extend(assessment.get("cleanup_receipts", []))

        out_json = json.dumps(receipts, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(receipts)} cleanup receipts to {args.output}")
        else:
            print(out_json)
        return 0

    if dev_cmd == "inspect":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        report = DeveloperServicesReport.from_dict(report_data)

        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return 0

        target_scope_str = ", ".join(report.target_scope)
        print(f"=== Developer & Runtime Interfaces Report ({report.report_id}) ===")
        print(f"Target Scope:         {target_scope_str}")
        print(f"Probe Vantage:        {report.vantage}")
        print(f"Total Assessed:       {report.total_probed}")
        print(f"Exposed:              {report.total_exposed}")
        print(f"Protected:            {report.total_protected}")
        print(f"Inaccessible:         {report.total_inaccessible}")
        print(f"Privilege Candidates: {report.candidates_count}")
        print(f"Cleanup Receipts:     {report.cleanup_receipts_count}")
        print()
        for s in report.assessments:
            status_icon = "!" if s.exposure_status in ("exposed", "misconfigured") else ("✓" if s.exposure_status in ("protected", "remediated") else "?")
            cand_types = [c.finding_type for c in s.privilege_candidates]
            cand_types_str = ", ".join(cand_types)
            cand_marker = f" -> CANDIDATES: {cand_types_str}" if cand_types else ""
            cat_label = s.category.upper() if isinstance(s.category, str) else s.category.value.upper()
            stype = s.service_type if isinstance(s.service_type, str) else s.service_type.value
            auth_val = s.auth_prerequisite if isinstance(s.auth_prerequisite, str) else s.auth_prerequisite.value
            exp_val = s.exposure_status if isinstance(s.exposure_status, str) else s.exposure_status.value
            exec_note = " [CODE-EXEC]" if s.can_execute_code else (" [STATE-CHANGE]" if s.can_change_state else "")
            print(f"  [{status_icon}] [{cat_label:<32}] {stype.upper():<15} {s.target_host}:{s.port:<5} {exp_val:<14} (auth: {auth_val}, role: {s.assigned_role}){exec_note}{cand_marker}")
        if report.total_inaccessible > 0:
            print()
            print("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened.")
        return 0

    return 0


def command_legacy_discovery(args: argparse.Namespace, root: Path | None = None) -> int:
    """Handle legacy enterprise, management, and proxy discovery CLI subcommands."""
    leg_cmd = getattr(args, "legacy_command", None)

    if leg_cmd == "assess":
        raw_targets = args.targets
        if Path(raw_targets).is_file():
            t_data = json.loads(Path(raw_targets).read_text(encoding="utf-8"))
            targets = t_data if isinstance(t_data, list) else (t_data.get("targets") or list(t_data.keys()))
        else:
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        services = [s.strip().lower() for s in args.services.split(",") if s.strip()] if args.services else None

        allow_exec = getattr(args, "allow_code_execution", False)
        allow_state = getattr(args, "allow_state_change", False)

        if args.mode == "synthetic":
            mock_targets = {}
            if args.offline_targets and Path(args.offline_targets).is_file():
                mock_targets = json.loads(Path(args.offline_targets).read_text(encoding="utf-8"))
            collector = OfflineSyntheticLegacyCollector(
                targets=mock_targets,
                allow_code_execution=allow_exec,
                allow_state_change=allow_state,
            )
        else:
            collector = StandardSocketLegacyCollector(
                allow_code_execution=allow_exec,
                allow_state_change=allow_state,
            )

        report = assess_legacy_services(
            targets=targets,
            service_types=services,
            collector=collector,
            vantage=args.vantage,
            scope_ref=args.scope_ref,
            canary_id=args.canary_id,
            allow_code_execution=allow_exec,
            allow_state_change=allow_state,
        )

        out_json = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Assessed {len(report.assessments)} legacy services ({report.candidates_count} candidates, {report.cleanup_receipts_count} receipts) saved to {args.output}")
        else:
            print(out_json)
        return 0

    if leg_cmd == "candidates":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates: list[dict[str, Any]] = []
        for assessment in report_data.get("assessments", []):
            candidates.extend(assessment.get("privilege_candidates", []))

        out_json = json.dumps(candidates, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(candidates)} legacy privilege candidates to {args.output}")
        else:
            print(out_json)
        return 0

    if leg_cmd == "cleanup":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        receipts: list[dict[str, Any]] = []
        for assessment in report_data.get("assessments", []):
            receipts.extend(assessment.get("cleanup_receipts", []))

        out_json = json.dumps(receipts, indent=2)
        if args.output:
            Path(args.output).write_text(out_json, encoding="utf-8")
            print(f"Exported {len(receipts)} cleanup receipts to {args.output}")
        else:
            print(out_json)
        return 0

    if leg_cmd == "inspect":
        report_path = Path(args.report)
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        report = LegacyServicesReport.from_dict(report_data)

        if getattr(args, "json", False):
            print(json.dumps(report.to_dict(), indent=2))
            return 0

        target_scope_str = ", ".join(report.target_scope)
        print(f"=== Legacy Enterprise, Management & Proxy Services Report ({report.report_id}) ===")
        print(f"Target Scope:         {target_scope_str}")
        print(f"Probe Vantage:        {report.vantage}")
        print(f"Total Assessed:       {report.total_probed}")
        print(f"Exposed:              {report.total_exposed}")
        print(f"Protected:            {report.total_protected}")
        print(f"Inaccessible:         {report.total_inaccessible}")
        print(f"Privilege Candidates: {report.candidates_count}")
        print(f"Cleanup Receipts:     {report.cleanup_receipts_count}")
        print()
        for s in report.assessments:
            status_icon = "!" if s.exposure_status in ("exposed", "misconfigured") else ("✓" if s.exposure_status in ("protected", "remediated") else "?")
            cand_types = [c.finding_type for c in s.privilege_candidates]
            cand_types_str = ", ".join(cand_types)
            cand_marker = f" -> CANDIDATES: {cand_types_str}" if cand_types else ""
            cat_label = s.category.upper() if isinstance(s.category, str) else s.category.value.upper()
            stype = s.service_type if isinstance(s.service_type, str) else s.service_type.value
            auth_val = s.auth_prerequisite if isinstance(s.auth_prerequisite, str) else s.auth_prerequisite.value
            exp_val = s.exposure_status if isinstance(s.exposure_status, str) else s.exposure_status.value
            exec_note = " [CODE-EXEC]" if s.can_execute_code else (" [STATE-CHANGE]" if s.can_change_state else "")
            proxy_note = ""
            if s.proxy_egress_tested:
                proxy_note = " [EGRESS-RESTRICTED]" if s.proxy_egress_restricted else " [EGRESS-OPEN]"
            print(f"  [{status_icon}] [{cat_label:<35}] {stype.upper():<20} {s.target_host}:{s.port:<5} {exp_val:<14} (auth: {auth_val}, role: {s.assigned_role}){exec_note}{proxy_note}{cand_marker}")
        if report.total_inaccessible > 0:
            print()
            print("Truth-in-Advertising Notice: Inaccessible services are NOT reported as secure or hardened.")
        return 0

    return 0


def command_discovery(
    args: argparse.Namespace | None = None,
    root: Path | None = None,
    *,
    subcommand: str | None = None,
    file_path: str | None = None,
    asset_type: str | None = None,
    scope_path: str | None = None,
    output_path: str | None = None,
    as_json: bool = False,
) -> int:
    """Execute discovery CLI command."""
    cmd = subcommand or (getattr(args, "discovery_command", None) if args else None)

    try:
        if cmd == "active":
            return command_active_discovery(args, root=root)

        if cmd == "infrastructure":
            return command_infra_discovery(args, root=root)

        if cmd == "remote":
            return command_remote_discovery(args, root=root)

        if cmd == "data":
            return command_data_discovery(args, root=root)

        if cmd == "messaging":
            return command_messaging_discovery(args, root=root)

        if cmd == "developer":
            return command_developer_discovery(args, root=root)

        if cmd == "legacy":
            return command_legacy_discovery(args, root=root)

        if cmd == "normalize":
            src_file = Path(file_path or args.file)
            typ = (asset_type or args.type).lower()
            source_id = getattr(args, "source_id", "S01") if args else "S01"
            out_file = output_path or (getattr(args, "output", None) if args else None)

            raw_bytes = src_file.read_bytes()
            sha = hashlib.sha256(raw_bytes).hexdigest()
            raw_data = json.loads(raw_bytes.decode("utf-8"))

            records = raw_data if isinstance(raw_data, list) else [raw_data]
            normalized_assets: list[DiscoveredAsset] = []

            for idx, r in enumerate(records):
                prov = EvidenceProvenance(
                    source_id=source_id,
                    source_type=typ,
                    sha256=sha,
                    timestamp="2026-10-05T00:00:00Z",
                    path_or_uri=str(src_file),
                    raw_record_ref=f"rec-{idx:04d}",
                )
                if typ in ("dns",):
                    normalized_assets.append(normalize_dns_record(r, prov))
                elif typ in ("cert", "certificate"):
                    normalized_assets.append(normalize_certificate_record(r, prov))
                elif typ in ("ip", "ip_address"):
                    normalized_assets.append(normalize_ip_record(r, prov))
                elif typ in ("endpoint",):
                    normalized_assets.append(normalize_endpoint_record(r, prov))
                elif typ in ("cloud", "cloud_resource"):
                    normalized_assets.append(normalize_cloud_export(r, prov))

            inventory = DiscoveryInventory(
                timestamp="2026-10-05T00:00:00Z",
                assets=normalized_assets,
                summary={
                    "total_assets": len(normalized_assets),
                    "quarantined": len(normalized_assets),
                },
            )
            out_json = json.dumps(inventory.to_dict(), indent=2)
            if out_file:
                Path(out_file).write_text(out_json, encoding="utf-8")
                print(f"Normalized {len(normalized_assets)} assets saved to {out_file}")
            else:
                print(out_json)
            return 0

        elif cmd == "reconcile":
            inv_file = Path(file_path or args.inventory)
            sc_file = Path(scope_path or args.scope)
            out_file = output_path or (getattr(args, "output", None) if args else None)

            inv_data = json.loads(inv_file.read_text(encoding="utf-8"))
            scope_data = json.loads(sc_file.read_text(encoding="utf-8"))

            scope_dict = scope_data.get("scope", scope_data)

            inventory = DiscoveryInventory.from_dict(inv_data)
            reconciled = reconcile_inventory(inventory.assets, scope_dict)

            out_json = json.dumps(reconciled.to_dict(), indent=2)
            if out_file:
                Path(out_file).write_text(out_json, encoding="utf-8")
                print(f"Reconciled inventory saved to {out_file}")
            else:
                print(out_json)
            return 0

        elif cmd == "merge":
            files = getattr(args, "files", [])
            out_file = output_path or (getattr(args, "output", None) if args else None)

            loaded_inventories = []
            for f in files:
                p = Path(f)
                data = json.loads(p.read_text(encoding="utf-8"))
                loaded_inventories.append(DiscoveryInventory.from_dict(data))

            merged = merge_inventories(*loaded_inventories)
            out_json = json.dumps(merged.to_dict(), indent=2)
            if out_file:
                Path(out_file).write_text(out_json, encoding="utf-8")
                print(f"Merged {len(files)} inventories ({len(merged.assets)} assets) saved to {out_file}")
            else:
                print(out_json)
            return 0

        elif cmd == "inspect":
            inv_file = Path(file_path or args.inventory)
            use_json = as_json or (getattr(args, "json", False) if args else False)

            inv_data = json.loads(inv_file.read_text(encoding="utf-8"))
            inventory = DiscoveryInventory.from_dict(inv_data)

            if use_json:
                print(json.dumps(inventory.to_dict(), indent=2))
                return 0

            print("=== Discovery Inventory Summary ===")
            print(f"Timestamp:          {inventory.timestamp}")
            print(f"Total Assets:       {inventory.summary.get('total_assets', len(inventory.assets))}")
            print(f"Verified In Scope:  {inventory.summary.get('verified_in_scope', 0)}")
            print(f"Quarantined:        {inventory.summary.get('quarantined', 0)}")
            print(f"Excluded:           {inventory.summary.get('excluded', 0)}")
            print()
            print("Assets:")
            for a in inventory.assets:
                status_icon = "✓" if a.status == "verified_in_scope" else ("✗" if a.status == "excluded" else "!")
                reasons = f" ({', '.join(a.quarantine_reasons)})" if a.quarantine_reasons else ""
                print(f"  [{status_icon}] {a.asset_type:<15} {a.identifier:<35} {a.status:<18}{reasons}")
            return 0

    except Exception as err:
        print(f"discovery error: {err}", file=sys.stderr)
        return 1

    return 0
