"""Regression coverage for optional workflow evidence signing."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "workflows" / "catalog.json"


def _run_without_site(*arguments: str) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, "-S", "-m", "cops", "workflow", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _registered_profiles() -> list[tuple[str, str]]:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return [
        (workflow["workflow_id"], profile["profile_id"])
        for workflow in catalog["workflows"]
        for profile in workflow["profiles"]
    ]


def test_cli_catalog_and_unsigned_playback_work_without_site_packages() -> None:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    profiles = _registered_profiles()

    listed = _run_without_site("list")
    validated = _run_without_site("validate")

    assert listed["workflows"] == sorted(workflow["workflow_id"] for workflow in catalog["workflows"])
    assert validated == catalog

    for workflow_id, profile_id in profiles:
        report = _run_without_site("playback", workflow_id, "--profile", profile_id)
        assert report["status"] == "completed"
        if workflow_id == "leaked-credential-blast-radius":
            bundle = report["outputs"]["evidence_bundle"]
            signature = bundle["signature"]
            assert signature["status"] == "unsigned"
            assert signature["algorithm"] is None
            assert signature["key_id"] is None
            assert signature["value"] is None
            assert "public_key" not in signature
            assert bundle["cryptographically_signed"] is False
            assert bundle["signature_verified"] is False
            assert bundle["authenticity_established"] is False
            assert bundle["trust_status"] == "unsigned"


def test_requested_signing_without_cryptography_returns_a_stable_error() -> None:
    script = """
import json
from cops.workflows.playback import EvidenceBundleSigner, IntegratedWorkflowError, run_fixture_profile

try:
    run_fixture_profile(
        "leaked-credential-blast-radius",
        "vulnerable",
        evidence_signer=EvidenceBundleSigner("test-key", object()),
    )
except IntegratedWorkflowError as error:
    print(json.dumps({"error": error.code}))
else:
    raise SystemExit("signing unexpectedly produced evidence")
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", script],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"error": "evidence_signing_requires_cryptography"}
