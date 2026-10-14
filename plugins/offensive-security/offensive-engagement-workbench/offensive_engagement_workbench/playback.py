"""Offline playback for the COPS Offensive Engagement Workbench."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cops.engagement import build_action_plan, validate_engagement_intake
from cops.routing import propose_specialist_handoff


class PlaybackError(RuntimeError):
    """Raised when the inert playback cannot prove its expected semantics."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PlaybackError(message)


@dataclass(frozen=True)
class DispatchResult:
    """Raw result from the local inert subprocess boundary."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class Dispatcher(Protocol):
    """Minimal injectable dispatcher contract used by the playback."""

    def dispatch(self, payload: dict[str, Any]) -> DispatchResult: ...


_CHILD_PROGRAM = r"""
import json
import sys

payload = json.loads(sys.stdin.buffer.read())
observation = {
    "dispatcher": "local-inert",
    "engagement_id": payload["engagement_id"],
    "mode": payload["mode"],
    "network_requests": 0,
    "operation_ids": [operation["step_id"] for operation in payload["operations"]],
    "operations_count": len(payload["operations"]),
    "target": payload["target"],
}
sys.stdout.buffer.write(
    (json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
)
""".strip()


class InertSubprocessDispatcher:
    """Dispatch a plan summary to an isolated local Python process."""

    def dispatch(self, payload: dict[str, Any]) -> DispatchResult:
        argv = (sys.executable, "-I", "-c", _CHILD_PROGRAM)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            completed = subprocess.run(
                argv,
                input=encoded,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PlaybackError(f"inert subprocess dispatch failed: {exc}") from exc
        return DispatchResult(argv, completed.returncode, completed.stdout, completed.stderr)


def _read_manifest(source: Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, Path):
        try:
            value = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlaybackError(f"cannot read engagement manifest: {exc}") from exc
    else:
        value = dict(source)
    _require(isinstance(value, dict), "engagement manifest must be a JSON object")
    return value


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def run_playback(
    engagement_manifest: Path | dict[str, Any],
    *,
    output_dir: Path,
    tool_versions: Mapping[str, str],
    target: str = "10.100.0.10",
    scenario_id: str = "COPS-E03.01-S01",
    root: Path | None = None,
    dispatcher: Dispatcher | None = None,
) -> dict[str, Any]:
    """Run the planning-only playback and atomically write its evidence artifacts."""
    output_dir = Path(output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        stale_result = output_dir / "playback-result.json"
        stale_result.unlink(missing_ok=True)
    except OSError as exc:
        raise PlaybackError(f"cannot prepare output directory: {exc}") from exc

    raw_engagement = _read_manifest(engagement_manifest)
    validated = validate_engagement_intake(raw_engagement)
    _require(validated.get("mode") == "planning", "playback accepts planning mode only")

    plan = build_action_plan(
        engagement=validated,
        scenario=scenario_id,
        target=target,
        tool_versions=tool_versions,
        specialist_id="cops-pentest-specialist",
        mode="planning",
        root=root,
    )
    plan_dict = plan.to_dict()
    operations = plan_dict.get("operations")
    _require(isinstance(operations, list), "action plan operations must be a list")
    _require(len(operations) == 1, "synthetic playback must compile exactly one operation")
    _require(plan_dict.get("target") == target, "action plan target differs from requested target")
    _require(plan_dict.get("status") == "draft", "playback action plan must remain draft")
    _require(plan_dict.get("limits", {}).get("egress_allowed") is False, "planning plan must prohibit egress")

    handoff = propose_specialist_handoff(
        validated,
        plan,
        "Review the synthetic planning operation and its evidence requirements",
        validated["operator"],
        specialist_id="cops-pentest-specialist",
        workflow_skill_id="engagement-intake-and-planning",
        capability_id="cops-pentest-specialist",
        handoff_id="hnd-eng-synthetic-e03-planning",
        registry_path=(root / "agents" / "registry.json") if root is not None else None,
    ).to_dict()
    _require(handoff.get("status") == "proposed", "specialist handoff must remain proposed")
    _require(handoff.get("approval_status") == "pending", "specialist handoff must remain approval-pending")

    _atomic_write_json(output_dir / "engagement.json", validated)
    _atomic_write_json(output_dir / "action-plan.json", plan_dict)
    _atomic_write_json(output_dir / "handoff.json", handoff)

    request = {
        "engagement_id": validated["engagement_id"],
        "mode": validated["mode"],
        "operations": operations,
        "target": target,
    }
    dispatch_result = (dispatcher or InertSubprocessDispatcher()).dispatch(request)
    _require(dispatch_result.returncode == 0, "inert subprocess returned a non-zero status")
    _require(dispatch_result.stderr == b"", "inert subprocess wrote to stderr")
    try:
        observation = json.loads(dispatch_result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlaybackError(f"inert subprocess returned invalid JSON: {exc}") from exc
    _require(isinstance(observation, dict), "inert subprocess observation must be a JSON object")
    expected_observation = {
        "dispatcher": "local-inert",
        "engagement_id": "eng-synthetic-e03",
        "mode": "planning",
        "network_requests": 0,
        "operation_ids": [operations[0]["step_id"]],
        "operations_count": 1,
        "target": "10.100.0.10",
    }
    _require(observation == expected_observation, "inert subprocess observation failed semantic validation")

    evidence = {
        "argv": list(dispatch_result.argv),
        "returncode": dispatch_result.returncode,
        "stderr_bytes": len(dispatch_result.stderr),
        "stderr_sha256": _sha256(dispatch_result.stderr),
        "stdout_bytes": len(dispatch_result.stdout),
        "stdout_sha256": _sha256(dispatch_result.stdout),
    }
    _atomic_write_json(output_dir / "inert-observation.json", observation)
    _atomic_write_json(output_dir / "execution-evidence.json", evidence)

    result = {
        "engagement_id": "eng-synthetic-e03",
        "mode": "planning",
        "network_requests": 0,
        "operations_count": 1,
        "status": "passed",
        "target": "10.100.0.10",
    }
    _atomic_write_json(output_dir / "playback-result.json", result)
    return result
