"""Focused regressions for package, rendering, archive, and CLI boundaries."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from huntwb import reports
from huntwb.cli import main
from huntwb.errors import ContentError
from huntwb.package_validation import validate_package
from huntwb.paths import PACKAGE_ROOT, load_json, sha256_bytes
from huntwb.release_build import archive_bytes, secret_findings
from huntwb.rendering import render_hunt
from huntwb.reports import release_subject


class WorkbenchTests(unittest.TestCase):
    def test_package_inventory_and_adapters(self) -> None:
        report = validate_package()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["contract"]["hunts"], 12)
        self.assertEqual(report["skill_count"], 6)

    def test_rendered_hunt_uses_typed_parameters(self) -> None:
        parameters = load_json(PACKAGE_ROOT / "examples" / "h01-parameters.json")
        rendered = render_hunt("H01", "sentinel_analytics", parameters)
        self.assertEqual(rendered["hunt_brief"]["id"], "H01")
        self.assertNotIn("11111111-1111-4111-8111-111111111111", json.dumps(rendered.get("parameter_manifest", {})))

    def test_parameter_injection_is_rejected(self) -> None:
        parameters = load_json(PACKAGE_ROOT / "examples" / "h01-parameters.json")
        parameters["tenant_id"] = "22222222-2222-4222-8222-222222222222 | union *"
        with self.assertRaises(ContentError):
            render_hunt("H01", "sentinel_analytics", parameters)

    def test_unknown_surface_is_rejected(self) -> None:
        parameters = load_json(PACKAGE_ROOT / "examples" / "h01-parameters.json")
        with self.assertRaises(ContentError):
            render_hunt("H01", "unknown_surface", parameters)

    def test_archive_is_reproducible_and_contains_subject(self) -> None:
        subject = release_subject()
        first = archive_bytes(subject)
        self.assertEqual(first, archive_bytes(subject))
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            expected = [f"sentinel-hunt-workbench/{name}" for name in sorted(subject["artifacts"])]
            self.assertEqual(archive.namelist(), expected)
            self.assertTrue(all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in archive.infolist()))

    def test_release_integrity_rejects_changed_archive_bytes(self) -> None:
        subject = release_subject()
        archive = archive_bytes(subject)
        digest = sha256_bytes(archive)
        payloads = {
            "provenance_manifest": {
                "archive_name": "sentinel-hunt-workbench.zip",
                "archive_sha256": digest,
            },
            "reproducible_build": {
                "archive_name": "sentinel-hunt-workbench.zip",
                "build_a_sha256": digest,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel-hunt-workbench.zip"
            with mock.patch.object(reports, "RELEASE_DIR", Path(directory)):
                path.write_bytes(archive)
                valid = reports._Findings()
                reports._validate_release_archive(payloads, subject, valid)
                self.assertFalse(valid)

                path.write_bytes(archive + b"changed")
                invalid = reports._Findings()
                reports._validate_release_archive(payloads, subject, invalid)
                self.assertTrue(invalid)

    def test_secret_scan_reports_only_pattern_and_path(self) -> None:
        candidate = b"AKIA" + b"A" * 16
        findings = secret_findings("example.txt", candidate)
        self.assertEqual(findings, [{"path": "example.txt", "pattern": "aws_access_key"}])
        self.assertNotIn(candidate.decode(), json.dumps(findings))

    def test_cli_validation_and_bad_parameter_exit(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["validate", "H01"]), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "passed")

        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(main(["render", "H01", "--surface", "sentinel_analytics"]), 2)
        self.assertEqual(json.loads(errors.getvalue())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
