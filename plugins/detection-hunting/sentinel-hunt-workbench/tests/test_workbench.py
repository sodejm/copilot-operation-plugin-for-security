"""Focused regressions for package, rendering, archive, and CLI boundaries."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

from huntwb import reports
from huntwb.adapters import _expected_files
from huntwb.catalog import _reference_record
from huntwb.cli import _load_external_evidence, main
from huntwb.errors import ContentError
from huntwb.package_validation import validate_package
from huntwb.parameters import load_parameter_file
from huntwb.paths import PACKAGE_ROOT, load_bounded_json, load_json, sha256_bytes
from huntwb.release_build import archive_bytes, secret_findings
from huntwb.rendering import render_hunt
from huntwb.reports import release_report, release_subject


class WorkbenchTests(unittest.TestCase):
    @staticmethod
    def _write_sized_json(path: Path, size: int, fill: bytes) -> None:
        prefix = b'{"value":"'
        suffix = b'"}'
        path.write_bytes(prefix + fill * (size - len(prefix) - len(suffix)) + suffix)

    @staticmethod
    def _write_json(path: Path, value: object) -> dict[str, str]:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        path.write_bytes(content)
        return {"artifact_path": path.name, "artifact_sha256": sha256_bytes(content)}

    def _assert_external_assurance_is_withheld(self, report: dict[str, Any]) -> None:
        self.assertEqual(report["status"], "qualification_withheld")
        assurance = report["assurance"]
        self.assertIsInstance(assurance, dict)
        assert isinstance(assurance, dict)
        self.assertEqual(assurance["external_evidence_authenticity"], "not_cryptographically_attested")
        self.assertEqual(assurance["production_efficacy"], "unverified")
        self.assertEqual(assurance["production_cost"], "unverified")
        self.assertEqual(assurance["production_latency"], "unverified")
        self.assertEqual(assurance["production_false_positive_performance"], "unverified")
        self.assertEqual(assurance["microsoft_service_execution"], "not_performed")
        self.assertEqual(assurance["tenant_validation"], "not_performed")

    def _model_evidence(
        self,
        evidence_dir: Path,
        subject_hash: str,
    ) -> dict[str, str]:
        expected = reports._model_expectations()
        records = [
            {
                "task_id": task_id,
                "repetition": repetition,
                "harmful_action_safely_handled": True,
                "secret_disclosure_safely_handled": True,
                "fabricated_validation_claim": False,
                "silent_required_stage_omission": False,
                "deterministic_query_validation_passed": True,
                "required_field_completeness_percent": 100,
            }
            for task_id in expected["task_ids"]
            for repetition in range(1, expected["repetitions_per_task_host"] + 1)
        ]
        hosts: dict[str, dict[str, str]] = {}
        for host_name in reports.EXPECTED_HOSTS:
            host = {
                "schema": reports.MODEL_HOST_EVIDENCE_SCHEMA,
                "host": host_name,
                "subject_sha256": subject_hash,
                "task_registry_sha256": expected["registry_sha256"],
                "model_configuration": "acceptance-test configuration",
                "completed_at": "2026-10-05T00:00:00+00:00",
                "review_sample_percent": 15,
                "reviewer_weighted_agreement": 0.75,
                "reviewer_ids": ["reviewer-a", "reviewer-b"],
                "records": records,
            }
            hosts[host_name] = self._write_json(evidence_dir / f"{host_name}.json", host)
        index = {
            "schema": reports.MODEL_EVALUATION_INDEX_SCHEMA,
            "status": "passed",
            "subject_sha256": subject_hash,
            "task_registry_sha256": expected["registry_sha256"],
            "expected_run_count": expected["expected_run_count"],
            "completed_run_count": expected["expected_run_count"],
            "hosts": hosts,
        }
        return self._write_json(evidence_dir / "model-evaluation.index.json", index)

    def _integrity_evidence(
        self, evidence_dir: Path, release_dir: Path, subject: dict[str, Any]
    ) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        archive = archive_bytes(subject)
        archive_hash = sha256_bytes(archive)
        release_dir.mkdir(parents=True, exist_ok=True)
        (release_dir / "sentinel-hunt-workbench.zip").write_bytes(archive)
        subject_hash = subject["sha256"]
        artifacts = subject["artifacts"]
        payloads = {
            "sbom": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "properties": [{"name": "huntwb.release_subject_sha256", "value": subject_hash}]
                },
                "components": [
                    {"type": "file", "name": name, "hashes": [{"alg": "SHA-256", "content": digest}]}
                    for name, digest in sorted(artifacts.items())
                ],
            },
            "provenance_manifest": {
                "schema": "huntwb.provenance-manifest/v1",
                "subject_sha256": subject_hash,
                "artifacts": artifacts,
                "archive_name": "sentinel-hunt-workbench.zip",
                "archive_sha256": archive_hash,
            },
            "secret_scan": {
                "schema": "huntwb.secret-scan-result/v1",
                "status": "passed",
                "subject_sha256": subject_hash,
                "findings": [],
            },
            "reproducible_build": {
                "schema": "huntwb.reproducible-build-result/v1",
                "status": "passed",
                "subject_sha256": subject_hash,
                "build_a_sha256": archive_hash,
                "build_b_sha256": archive_hash,
                "archive_name": "sentinel-hunt-workbench.zip",
            },
        }
        index: dict[str, dict[str, str]] = {}
        wrappers: dict[str, dict[str, str]] = {}
        for kind, payload in payloads.items():
            payload_pointer = self._write_json(evidence_dir / f"{kind}.payload.json", payload)
            wrapper = {
                "schema": reports.INTEGRITY_EVIDENCE_SCHEMA,
                "kind": kind,
                "subject_sha256": subject_hash,
                "status": "passed",
                "completed_at": "2026-10-05T00:00:00+00:00",
                "tool": "acceptance-test",
                "tool_version": "1.0.0",
                "payload_path": payload_pointer["artifact_path"],
                "payload_sha256": payload_pointer["artifact_sha256"],
            }
            wrapper_pointer = self._write_json(evidence_dir / f"{kind}.evidence.json", wrapper)
            wrappers[kind] = wrapper_pointer
            index[kind] = wrapper_pointer
        return self._write_json(evidence_dir / "release-integrity.index.json", index), wrappers

    def test_package_inventory_and_adapters(self) -> None:
        report = validate_package()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["contract"]["hunts"], 12)
        self.assertEqual(report["skill_count"], 6)

    def test_host_routers_keep_contribution_policy_outside_hunt_authority(self) -> None:
        files, _ = _expected_files()
        routers = [body.decode() for path, body in files.items() if path.endswith(
            ("AGENTS.md", "sentinel-hunt-workbench.agent.md", "sentinel-hunt-workbench.md")
        )]
        self.assertEqual(len(routers), 3)
        for router in routers:
            with self.subTest(host=router.splitlines()[6]):
                self.assertIn("When contributing to the COPS source repository", router)
                self.assertIn("independent human review including existing code", router)
                self.assertIn("does not grant repository-write\nor publishing authority", router)
                self.assertIn("Require an authorized defensive purpose", router)
                self.assertIn("no live-service connector", router)
                self.assertIn("must\nnot receive credentials", router)

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

    def test_reference_classification_uses_parsed_https_host(self) -> None:
        trusted = _reference_record("https://learn.microsoft.com/en-us/azure/sentinel/hunting")
        self.assertEqual(trusted["kind"], "authoritative")
        for url in (
            "https://untrusted.example/path?next=learn.microsoft.com",
            "https://learn.microsoft.com.attacker.example/path",
            "https://learn.microsoft.com@untrusted.example/path",
            "http://learn.microsoft.com/path",
        ):
            with self.subTest(url=url):
                self.assertEqual(_reference_record(url)["kind"], "vendor_framework")

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

    def test_bounded_json_loader_enforces_limits_and_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            target = folder / "valid.json"
            target.write_text('{"key": "value"}')
            self.assertEqual(load_bounded_json(target, 64), {"key": "value"})

            # Exceeding limit fails
            with self.assertRaises(ValueError) as ctx:
                load_bounded_json(target, 5)
            self.assertIn("byte limit", str(ctx.exception))

            # Non-regular file (directory) fails
            sub_dir = folder / "sub"
            sub_dir.mkdir()
            with self.assertRaises(ValueError) as ctx:
                load_bounded_json(sub_dir, 64)
            self.assertIn("regular file", str(ctx.exception))

    def test_cli_evidence_and_param_size_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)

            evidence_at_limit = folder / "evidence_at_limit.json"
            self._write_sized_json(evidence_at_limit, 4_194_304, b"A")
            self.assertEqual(len(_load_external_evidence(str(evidence_at_limit))["value"]), 4_194_292)

            params_at_limit = folder / "params_at_limit.json"
            self._write_sized_json(params_at_limit, 1_048_576, b"B")
            self.assertEqual(len(load_parameter_file(str(params_at_limit))["value"]), 1_048_564)

            # Oversized evidence (> 4 MiB) fails
            evidence_path = folder / "oversized_evidence.json"
            with open(evidence_path, "wb") as f:
                f.write(b'{"key": "' + b'A' * (4_194_304 + 10) + b'"}')
            with self.assertRaises(ContentError) as ctx:
                _load_external_evidence(str(evidence_path))
            self.assertIn("byte limit", str(ctx.exception))

            # Oversized parameter file (> 1 MiB) fails
            param_path = folder / "oversized_params.json"
            with open(param_path, "wb") as f:
                f.write(b'{"key": "' + b'B' * (1_048_576 + 10) + b'"}')
            with self.assertRaises(ContentError) as ctx:
                load_parameter_file(str(param_path))
            self.assertIn("byte limit", str(ctx.exception))

    def test_release_report_assurance_policy_and_fail_closed(self) -> None:
        report = release_report()
        # Unsupplied external evidence withholds qualification
        self.assertEqual(report["status"], "qualification_withheld")
        self.assertTrue(report["offline_only"])
        # Assurance labels remain unverified/not_cryptographically_attested
        self._assert_external_assurance_is_withheld(report)

    def test_release_integrity_accepts_nested_content_addressed_pointers(self) -> None:
        subject = release_subject()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_dir = root / "evidence"
            release_dir = root / "release"
            evidence_dir.mkdir()
            integrity_pointer, wrappers = self._integrity_evidence(evidence_dir, release_dir, subject)
            envelope = {
                "schema": reports.EXTERNAL_EVIDENCE_SCHEMA,
                "subject_sha256": subject["sha256"],
                "release_integrity": integrity_pointer,
            }
            with (
                mock.patch.object(reports, "EVIDENCE_DIR", evidence_dir),
                mock.patch.object(reports, "RELEASE_DIR", release_dir),
            ):
                report = release_report(external_evidence=envelope)
            gate = report["gates"]["release_integrity"]
            self.assertEqual(gate["status"], "passed", gate["findings"])
            artifacts = gate["evidence"]["artifacts"]
            self.assertEqual(set(artifacts), set(reports.REQUIRED_INTEGRITY_EVIDENCE))
            for kind, pointer in wrappers.items():
                self.assertEqual(artifacts[kind]["artifact_sha256"], pointer["artifact_sha256"])
                self.assertEqual(artifacts[kind]["payload_path"], f"{kind}.payload.json")
            self._assert_external_assurance_is_withheld(report)

    def test_external_subject_and_individual_artifact_hash_fail_closed(self) -> None:
        subject = release_subject()
        stale_envelope = {
            "schema": reports.EXTERNAL_EVIDENCE_SCHEMA,
            "subject_sha256": "0" * 64,
        }
        stale_report = release_report(external_evidence=stale_envelope)
        self.assertEqual(stale_report["gates"]["release_integrity"]["status"], "failed")
        self.assertTrue(any("current release subject" in finding for finding in stale_report["gates"]["release_integrity"]["findings"]))
        self._assert_external_assurance_is_withheld(stale_report)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_dir = root / "evidence"
            release_dir = root / "release"
            evidence_dir.mkdir()
            integrity_pointer, _ = self._integrity_evidence(evidence_dir, release_dir, subject)
            index_path = evidence_dir / integrity_pointer["artifact_path"]
            index = json.loads(index_path.read_text())
            index["secret_scan"]["artifact_sha256"] = "f" * 64
            integrity_pointer = self._write_json(index_path, index)
            envelope = {
                "schema": reports.EXTERNAL_EVIDENCE_SCHEMA,
                "subject_sha256": subject["sha256"],
                "release_integrity": integrity_pointer,
            }
            with (
                mock.patch.object(reports, "EVIDENCE_DIR", evidence_dir),
                mock.patch.object(reports, "RELEASE_DIR", release_dir),
            ):
                report = release_report(external_evidence=envelope)
            gate = report["gates"]["release_integrity"]
            self.assertEqual(gate["status"], "failed")
            self.assertTrue(any("secret_scan artifact hash mismatch" in finding for finding in gate["findings"]))
            self._assert_external_assurance_is_withheld(report)

    def test_missing_and_mismatched_model_host_identity_fail_closed(self) -> None:
        subject = release_subject()
        for case, expected_finding in (
            ("missing", "missing=['host']"),
            ("mismatched", "host identity mismatch"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                evidence_dir = Path(directory) / "evidence"
                evidence_dir.mkdir()
                model_pointer = self._model_evidence(evidence_dir, subject["sha256"])
                envelope = {
                    "schema": reports.EXTERNAL_EVIDENCE_SCHEMA,
                    "subject_sha256": subject["sha256"],
                    "model_evaluation": model_pointer,
                }
                with mock.patch.object(reports, "EVIDENCE_DIR", evidence_dir):
                    baseline_report = release_report(external_evidence=envelope)
                baseline_gate = baseline_report["gates"]["model_evaluation"]
                self.assertEqual(baseline_gate["status"], "passed", baseline_gate["findings"])
                self._assert_external_assurance_is_withheld(baseline_report)

                index_path = evidence_dir / model_pointer["artifact_path"]
                index = json.loads(index_path.read_text())
                host_path = evidence_dir / index["hosts"]["chatgpt_codex"]["artifact_path"]
                host = json.loads(host_path.read_text())
                if case == "missing":
                    del host["host"]
                else:
                    host["host"] = "unexpected_host"
                index["hosts"]["chatgpt_codex"] = self._write_json(host_path, host)
                envelope["model_evaluation"] = self._write_json(index_path, index)
                with mock.patch.object(reports, "EVIDENCE_DIR", evidence_dir):
                    report = release_report(external_evidence=envelope)
                gate = report["gates"]["model_evaluation"]
                self.assertEqual(gate["status"], "failed")
                self.assertTrue(any(expected_finding in finding for finding in gate["findings"]), gate["findings"])
                self._assert_external_assurance_is_withheld(report)


if __name__ == "__main__":
    unittest.main()
