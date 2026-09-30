"""Unit and integration tests for SOC evidence intake and case handoff workflow (Issue #15)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

import sys

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "plugins/detection-hunting/soc-investigation-workbench"
sys.path.insert(0, str(PLUGIN_DIR))

from investigationwb.engine import (  # type: ignore
    ContractError,
    validate,
)
from investigationwb.handoff import (  # type: ignore
    generate_handoff,
    write_handoff,
)
from investigationwb.intake import (  # type: ignore
    ingest_sources,
    parse_timestamp,
)

EXAMPLES_DIR = PLUGIN_DIR / "examples/intake"


class SOCIntakeHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_timestamp_parsing_and_normalization(self) -> None:
        # Standard UTC Z
        self.assertEqual(parse_timestamp("2026-01-01T04:15:00Z"), "2026-01-01T04:15:00Z")
        # Offset +02:00
        self.assertEqual(parse_timestamp("2026-01-01T06:15:00+02:00"), "2026-01-01T04:15:00Z")
        # Offset -05:00
        self.assertEqual(parse_timestamp("2026-01-01T01:15:00-05:00"), "2026-01-01T06:15:00Z")
        # Space separator
        self.assertEqual(parse_timestamp("2026-01-01 04:15:00Z"), "2026-01-01T04:15:00Z")

        # Invalid formats fail closed
        with self.assertRaises(ContractError):
            parse_timestamp("not-a-timestamp")
        with self.assertRaises(ContractError):
            parse_timestamp("")

    def test_multi_source_intake_creates_valid_case(self) -> None:
        sources = [
            f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}",
            f"splunk:{EXAMPLES_DIR / 'splunk-events.json'}",
            f"entra:{EXAMPLES_DIR / 'entra-signins.json'}",
        ]
        case = ingest_sources(
            source_specs=sources,
            case_id="case-secops-01",
            tenant="tenant-a",
            workspace="workspace-a",
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
        )

        # Validate with the strict case engine
        validated = validate(case)
        self.assertEqual(validated["id"], "case-secops-01")
        self.assertEqual(validated["scope"]["tenant"], "tenant-a")
        self.assertEqual(validated["scope"]["workspace"], "workspace-a")

        # Must have both malicious and benign hypotheses
        kinds = {h["kind"] for h in validated["hypotheses"]}
        self.assertEqual(kinds, {"malicious", "benign"})

        # Evidence records should be present and sorted
        self.assertGreater(len(validated["evidence"]), 0)
        times = [e["event_time"] for e in validated["evidence"]]
        self.assertEqual(times, sorted(times))

        # Entities should have hashed keys and lowercase aliases
        for ent in validated["entities"]:
            self.assertRegex(ent["id"], r"^[a-z]+-\d{2}$")
            self.assertEqual(len(ent["key"]), 64)

    def test_cross_tenant_source_fails_closed(self) -> None:
        sources = [str(EXAMPLES_DIR / "cross-tenant.json")]
        with self.assertRaises(ContractError) as ctx:
            ingest_sources(
                source_specs=sources,
                case_id="case-cross-test",
                tenant="tenant-a",
                workspace="workspace-a",
                start="2026-01-01T00:00:00Z",
                end="2026-01-02T00:00:00Z",
            )
        self.assertIn("Cross-tenant record detected", str(ctx.exception))

    def test_out_of_interval_sources_fail_if_no_valid_records(self) -> None:
        sources = [f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}"]
        # Case window is in 2025, but events are in 2026
        with self.assertRaises(ContractError) as ctx:
            ingest_sources(
                source_specs=sources,
                case_id="case-stale-test",
                tenant="tenant-a",
                workspace="workspace-a",
                start="2025-01-01T00:00:00Z",
                end="2025-01-02T00:00:00Z",
            )
        self.assertIn("No records found within the specified case time window", str(ctx.exception))

    def test_export_handoff_produces_valid_json_and_markdown(self) -> None:
        sources = [
            f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}",
            f"entra:{EXAMPLES_DIR / 'entra-signins.json'}",
        ]
        case = ingest_sources(
            source_specs=sources,
            case_id="case-handoff-test",
            tenant="tenant-a",
            workspace="workspace-a",
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
        )

        handoff_dict, handoff_md = generate_handoff(case)
        self.assertEqual(handoff_dict["case_id"], "case-handoff-test")
        self.assertIn("timeline", handoff_dict)
        self.assertIn("hypotheses", handoff_dict)
        self.assertIn("next_inquiries", handoff_dict)

        # Markdown checks
        self.assertIn("# Incident Case Handoff: `case-handoff-test`", handoff_md)
        self.assertIn("Chronological Evidence Timeline", handoff_md)
        self.assertIn("Competing Hypotheses Evaluation", handoff_md)
        self.assertIn("Recommended Next Inquiries", handoff_md)

        # Write to disk and check permissions
        dest_dir = self.out_dir / "handoff-output"
        receipt = write_handoff(dest_dir, case)
        self.assertEqual(receipt["status"], "written")

        json_file = Path(receipt["json_path"])
        md_file = Path(receipt["md_path"])
        self.assertTrue(json_file.is_file())
        self.assertTrue(md_file.is_file())

        if os.name == "posix":
            # Check 0600 mode (rw-------)
            json_mode = json_file.stat().st_mode & 0o777
            md_mode = md_file.stat().st_mode & 0o777
            self.assertEqual(json_mode, 0o600)
            self.assertEqual(md_mode, 0o600)

    def test_export_handoff_fails_if_output_exists(self) -> None:
        sources = [f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}"]
        case = ingest_sources(
            source_specs=sources,
            case_id="case-exclusive-test",
            tenant="tenant-a",
            workspace="workspace-a",
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
        )
        dest_dir = self.out_dir / "exclusive-test"
        write_handoff(dest_dir, case)

        # Second write should fail because files exist
        with self.assertRaises(FileExistsError):
            write_handoff(dest_dir, case)


    def test_deduplication_of_repeated_records(self) -> None:
        # Same source provided twice
        sources = [
            f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}",
            f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}",
        ]
        case = ingest_sources(
            source_specs=sources,
            case_id="case-dedup-test",
            tenant="tenant-a",
            workspace="workspace-a",
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
        )
        # Should have exactly 2 unique evidence items, not 4
        self.assertEqual(len(case["evidence"]), 2)

    def test_csv_source_ingestion(self) -> None:
        csv_file = self.out_dir / "test-sentinel.csv"
        csv_file.write_text(
            "TenantId,TimeGenerated,Title,Severity,Account,IPAddress\n"
            "tenant-a,2026-01-01T08:00:00Z,Brute Force Detected,High,alice@example.com,192.0.2.1\n"
        )
        case = ingest_sources(
            source_specs=[f"sentinel:{csv_file}"],
            case_id="case-csv-test",
            tenant="tenant-a",
            workspace="workspace-a",
            start="2026-01-01T00:00:00Z",
            end="2026-01-02T00:00:00Z",
        )
        self.assertEqual(len(case["evidence"]), 1)
        self.assertEqual(case["evidence"][0]["event_time"], "2026-01-01T08:00:00Z")

    def test_cli_subprocesses_intake_and_export_handoff(self) -> None:
        import subprocess
        import sys

        cli_script = PLUGIN_DIR / "scripts/investigate.py"
        case_out = self.out_dir / "cli-intake-case.json"
        handoff_dir = self.out_dir / "cli-handoff-dir"

        # 1. Run intake CLI
        intake_res = subprocess.run(
            [
                sys.executable,
                str(cli_script),
                "intake",
                "--case-id",
                "cli-case-01",
                "--tenant",
                "tenant-a",
                "--workspace",
                "workspace-a",
                "--start",
                "2026-01-01T00:00:00Z",
                "--end",
                "2026-01-02T00:00:00Z",
                "--sources",
                f"sentinel:{EXAMPLES_DIR / 'sentinel-incidents.json'}",
                "--out",
                str(case_out),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(intake_res.returncode, 0, f"CLI stderr: {intake_res.stderr}")
        self.assertTrue(case_out.is_file())

        # 2. Run export-handoff CLI
        handoff_res = subprocess.run(
            [
                sys.executable,
                str(cli_script),
                "export-handoff",
                str(case_out),
                "--out-dir",
                str(handoff_dir),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(handoff_res.returncode, 0, f"CLI stderr: {handoff_res.stderr}")
        self.assertTrue((handoff_dir / "handoff.json").is_file())
        self.assertTrue((handoff_dir / "handoff.md").is_file())


if __name__ == "__main__":
    unittest.main()

