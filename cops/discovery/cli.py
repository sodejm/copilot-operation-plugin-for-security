"""CLI interface for passive asset discovery, evidence provenance, and scope reconciliation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from .merger import merge_inventories
from .models import DiscoveredAsset, DiscoveryInventory, EvidenceProvenance
from .normalizers import (
    normalize_certificate_record,
    normalize_cloud_export,
    normalize_dns_record,
    normalize_endpoint_record,
    normalize_ip_record,
)
from .reconciler import reconcile_inventory

ROOT: Path = Path(__file__).resolve().parents[2]


def build_discovery_parser(subparsers: argparse._SubParsersAction[Any]) -> argparse.ArgumentParser:
    """Build the discovery sub-parser for cops CLI."""
    parser = subparsers.add_parser(
        "discovery",
        help="Passive asset discovery, evidence provenance, and scope reconciliation.",
        description="Normalize asset telemetry, deduplicate multi-source evidence, and reconcile scope quarantine.",
    )
    disc_subs = parser.add_subparsers(dest="discovery_command", required=True)

    # Subcommand: normalize
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

    # Subcommand: reconcile
    rec_p = disc_subs.add_parser("reconcile", help="Reconcile inventory against approved scope and quarantine uncertain assets.")
    rec_p.add_argument("inventory", help="Path to discovery inventory JSON.")
    rec_p.add_argument("--scope", "-s", required=True, help="Path to engagement scope or action plan JSON.")
    rec_p.add_argument("--output", "-o", default=None, help="Output JSON path (prints to stdout if omitted).")

    # Subcommand: merge
    merge_p = disc_subs.add_parser("merge", help="Merge and deduplicate multiple discovery inventory files.")
    merge_p.add_argument("files", nargs="+", help="Paths to discovery inventory JSON files to merge.")
    merge_p.add_argument("--output", "-o", default=None, help="Output JSON path (prints to stdout if omitted).")

    # Subcommand: inspect
    insp_p = disc_subs.add_parser("inspect", help="Inspect and summarize discovery inventory.")
    insp_p.add_argument("inventory", help="Path to discovery inventory JSON.")
    insp_p.add_argument("--json", action="store_true", help="Emit JSON output.")

    return parser


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

            # If scope_data is ActionPlan or Engagement, extract target scope
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
