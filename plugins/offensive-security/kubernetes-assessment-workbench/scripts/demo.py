#!/usr/bin/env python3
"""Exercise the public offline importer and verify its evidence boundaries."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_case(directory: Path, name: str, record: dict, expected_error: str | None = None) -> dict:
    source = directory / f"{name}.json"
    source.write_text(json.dumps(record), encoding="utf-8")
    source.chmod(0o600)
    result = subprocess.run(
        [sys.executable, str(PACKAGE / "scripts/assess.py"), str(source)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if expected_error:
        require(
            result.returncode == 2 and result.stderr.strip() == f"error: {expected_error}",
            result.stderr,
        )
        require(not result.stdout, f"{name} emitted a report for rejected input")
        return {"rejected": expected_error}
    require(result.returncode == 0, result.stderr)
    report = json.loads(result.stdout)
    require(report["live_execution_ready"] is False, f"{name} incorrectly reported live readiness")
    require(report["network_requests"] == 0, f"{name} reported network activity")
    require(report["evidence_origin"] == "sanitized_offline_export", f"{name} evidence origin changed")
    return report


def main() -> int:
    fixture = json.loads((PACKAGE / "fixtures/synthetic/context.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="cops-kubernetes-playback-") as temporary:
        directory = Path(temporary)
        matched = run_case(directory, "matched", fixture)
        require(matched["cluster_identity"]["status"] == "matched_sanitized_export", "cluster identity did not match")
        require(matched["namespaces"] == [{"namespace": "payments", "status": "accessible"}], "namespace result changed")
        require(matched["blockers"] == [], "matched input reported blockers")
        require(matched == run_case(directory, "matched-rerun", fixture), "matched playback was not repeatable")

        limited_input = copy.deepcopy(fixture)
        del limited_input["observation"]["identity_anchor"]
        limited_input["observation"]["namespace_access"][0]["status"] = "denied"
        limited_input["observation"]["surface_access"] = []
        limited_input["observation"]["cluster_facts"] = {"control_plane_access": "managed_unavailable"}
        limited = run_case(directory, "limited", limited_input)
        require(limited["cluster_identity"]["status"] == "unresolved", "limited identity did not remain unresolved")
        require(limited["namespaces"][0]["status"] == "denied", "limited namespace denial was lost")
        require(set(limited["blockers"]) == {
            "stable_identity_unresolved", "namespace_access_incomplete", "surface_access_incomplete",
        }, "limited blockers changed")
        require(
            set(limited["limitations"]) == {"control_plane_unavailable", "node_access_unavailable"},
            "limited coverage did not preserve unavailable surfaces",
        )

        switched = copy.deepcopy(fixture)
        switched["observation"]["current_context"]["cluster"] = "different-cluster"
        rejected = run_case(directory, "switched", switched, "context_mismatch")
        print(json.dumps({"status": "passed", "mode": "offline", "cases": {
            "matched": matched, "limited": limited, "switched": rejected,
        }}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
