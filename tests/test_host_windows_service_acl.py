"""Service-specific DACL semantics and real SCM correction acceptance."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins/offensive-security/host-assessment-workbench/scripts"


def test_service_dacl_collection_is_local_read_only_and_bounded() -> None:
    helper = (SCRIPTS / "windows-service-acl.ps1").read_text()
    collector = (SCRIPTS / "collect-windows.ps1").read_text()
    assert "QueryServiceObjectSecurity" in helper
    assert "OpenSCManager(null, null, 1)" in helper
    assert "OpenService(manager, name, 0x00020000)" in helper
    assert "new byte[65536]" in helper
    assert "CloseServiceHandle" in helper
    for forbidden in ("SetServiceObjectSecurity", "CreateService", "StartService", "ChangeServiceConfig"):
        assert forbidden not in helper
    assert "# E01.1 section: service_dacl" in collector
    assert "[Cops.ServiceDacl]::Read" in collector


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows PowerShell required")
def test_native_service_dacl_correction_and_cleanup(tmp_path: Path) -> None:
    assert shutil.which("pwsh"), "PowerShell 7 is required on the Windows acceptance runner"
    receipt_path = tmp_path / "service-acl.json"
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCRIPTS / "exercise-windows-service-acl.ps1"),
         "-ReceiptPath", str(receipt_path)],
        capture_output=True, text=True, timeout=90, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
    assert receipt["schema_version"] == "windows-service-acl-acceptance-1.0"
    assert receipt["vulnerable"] == "interesting"
    assert receipt["corrected"] == "ordinary"
    assert receipt["missing"] == "not_assessed"
    assert receipt["denied"] == "access_denied"
    assert receipt["semantic_cases"] >= 12
    assert receipt["success_cleanup_verified"] is True
    assert receipt["failure_cleanup_verified"] is True
    assert receipt["service_started"] is False
