#!/usr/bin/env python3
"""Validate deterministic synthetic cases and the safe local command path."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import ContractError, load_report_bytes  # noqa: E402
from host_assessment_workbench.windows import SURFACES  # noqa: E402
from host_assessment_workbench.windows_bridge import (  # noqa: E402
    load_bridge_receipt_bytes,
    validate_bridge_receipt,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    expected = {
        "positive": "reported_canary_crossing",
        "negative": "reported_canary_blocked",
        "fixed": "reported_canary_blocked",
    }
    for case, classification in expected.items():
        fixture = PACKAGE / "fixtures" / "synthetic" / f"host_linux_{case}_v1.json"
        result = load_report_bytes(fixture.read_bytes())
        _require(result["source"]["kind"] == "synthetic_lab", f"Linux {case} source mismatch")
        _require(
            result["observations"][0]["classification"] == classification,
            f"Linux {case} classification mismatch",
        )
        if case == "positive":
            _require(len(result["coverage"]) == 8, "Linux positive coverage mismatch")
    windows_expected = {
        "vulnerable": ("reported_canary_crossing", "selected"),
        "protected": ("reported_canary_blocked", "selected"),
        "remediated": ("reported_canary_blocked", "selected"),
    }
    for case, (classification, decision) in windows_expected.items():
        fixture = PACKAGE / "fixtures" / "synthetic" / f"host_windows_{case}_v1.json"
        result = load_report_bytes(fixture.read_bytes())
        _require(result["source"]["kind"] == "synthetic_lab", f"Windows {case} source mismatch")
        _require(result["mode"] == "offline_import", f"Windows {case} mode mismatch")
        _require(len(result["coverage"]) == 7, f"Windows {case} coverage mismatch")
        _require(
            result["observations"][0]["classification"] == classification,
            f"Windows {case} classification mismatch",
        )
        _require(
            result["observations"][0]["decision"] == decision,
            f"Windows {case} decision mismatch",
        )
    unsupported = load_report_bytes(
        (PACKAGE / "fixtures" / "synthetic" / "host_windows_unsupported_v1.json").read_bytes()
    )
    _require(
        unsupported["coverage"]["versioned_escalation_families"] == "unsupported",
        "Windows unsupported coverage mismatch",
    )
    _require(unsupported["observations"] == [], "Windows unsupported observations mismatch")

    native_payload = json.loads(
        (PACKAGE / "fixtures" / "synthetic" / "host_windows_unsupported_v1.json").read_text()
    )
    native_payload["source_kind"] = "operator_export"
    native_payload["source_id"] = "native_windows_bridge"
    native_payload["bridge"] = {
        "mode": "native_windows_bridge",
        "platform": "windows",
        "capabilities": list(SURFACES),
        "canary_assertions": False,
    }
    native_payload["coverage"] = {surface: "not_assessed" for surface in SURFACES}
    native_bytes = json.dumps(native_payload, separators=(",", ":"), sort_keys=True).encode()
    native = load_report_bytes(native_bytes)
    _require(native["mode"] == "native_bridge_import", "Windows native bridge mode mismatch")
    receipt = {
        "schema_version": "windows-bridge-receipt-1.0",
        "platform": "windows",
        "bridge_mode": "native_windows_bridge",
        "export_sha256": hashlib.sha256(native_bytes).hexdigest(),
        "capabilities": list(SURFACES),
        "canary": {
            "resource_id": "validation_canary",
            "assessment_owned": True,
            "before_absent": True,
            "created": True,
            "removed": True,
            "cleanup_verified": True,
            "evidence_ids": ["before", "created", "removed"],
        },
    }
    with tempfile.TemporaryDirectory() as canary_root:
        validated_receipt = validate_bridge_receipt(
            load_bridge_receipt_bytes(
                json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
            ),
            native_bytes,
            Path(canary_root),
        )
    _require(validated_receipt["export_sha256"] == receipt["export_sha256"], "receipt hash mismatch")

    collector = (PACKAGE / "scripts" / "collect-windows.ps1").read_text()
    for required in (
        "Get-CimInstance -ClassName Win32_Service",
        "System32\\Tasks",
        "whoami.exe",
        "AlwaysInstallElevated",
        "Get-Acl",
        "DefaultPassword",
        "token_impersonation_family",
        "Remove-Item -LiteralPath $canaryPath",
    ):
        _require(required in collector, f"native Windows collector is missing {required}")
    for prohibited in ("Invoke-Expression", "Start-Process", "GetValue(\"DefaultPassword\""):
        _require(prohibited not in collector, f"native Windows collector contains {prohibited}")
    try:
        load_report_bytes(b'{"schema_version":"1.0","raw_password":"must-not-echo"}')
    except ContractError as exc:
        _require("must-not-echo" not in str(exc), "Linux credential value leaked")
    else:
        raise RuntimeError("raw credential field was accepted")
    try:
        load_report_bytes(b'{"schema_version":"windows-1.0","raw_password":"must-not-echo"}')
    except ContractError as exc:
        _require("must-not-echo" not in str(exc), "Windows credential value leaked")
    else:
        raise RuntimeError("Windows raw credential field was accepted")

    command = [sys.executable, str(PACKAGE / "scripts" / "demo.py")]
    outputs = [subprocess.run(command, capture_output=True, text=True, check=True, timeout=30).stdout for _ in range(2)]
    _require(outputs[0] == outputs[1], "demo output is not deterministic")
    _require(json.loads(outputs[0])["mode"] == "offline_import", "demo mode mismatch")
    print(
        json.dumps(
            {
                "status": "passed",
                "reproducible": True,
                "modes": ["offline_import", "native_bridge_import"],
                "native_bridge_contract": "validated",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
