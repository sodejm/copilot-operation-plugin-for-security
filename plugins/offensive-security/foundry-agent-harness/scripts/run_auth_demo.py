#!/usr/bin/env python3
"""Run the complete local agent/MCP authorization acceptance demonstration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PLUGIN_ROOT))

from cops.contracts import ActionPlan, Engagement  # noqa: E402
from cops.execution.authorization import (  # noqa: E402
    AuthorizationSigner,
    create_execution_authorization,
)
from cops.execution.store import ApprovalStore  # noqa: E402
from foundryharness import auth_laboratory  # noqa: E402

WORKER_IDENTITY = "fixture-worker"
CASES_PATH = PLUGIN_ROOT / "auth_cases"
CLI_PATH = PLUGIN_ROOT / "foundryharness/cli.py"
SIGNING_SECRET_ENV = "COPS_AGENT_MCP_DEMO_SIGNING_KEY"
OBSERVER_BOUNDARY = (
    "Provider-neutral separate process on the same host and trust boundary; this demonstration "
    "does not claim external attestation, live-provider authorization, or an OS network sandbox."
)
LIMITATIONS = (
    "no_native_provider_authority",
    "no_independently_authenticated_external_observer",
    "no_windows_runtime_acceptance",
    "no_os_enforced_egress_containment",
    "no_durable_host_loss_recovery",
)


class DemoError(RuntimeError):
    """The demonstration did not satisfy its fixed acceptance contract."""


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoError(message)


def _run_cli(arguments: list[str], *, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=environment,
    )


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.parent.chmod(0o700)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)


def _prepare_public_cli_run(
    root: Path,
) -> tuple[list[Any], list[str], dict[str, str]]:
    cases = auth_laboratory.load_auth_cases(CASES_PATH)
    now = datetime.now(UTC).replace(microsecond=0)
    plan_id = f"plan-auth-demo-{uuid.uuid4().hex[:12]}"
    engagement_id = f"eng-auth-demo-{uuid.uuid4().hex[:12]}"
    plan_path = root / "plan.json"
    engagement_path = root / "engagement.json"
    authorization_path = root / "authorization.json"
    trust_store_path = root / "trust-store.json"
    approval_store_path = root / "approval" / "authorization.sqlite3"
    environment = os.environ.copy()

    plan_result = _run_cli(
        [
            "auth-plan",
            "--cases",
            str(CASES_PATH),
            "--plan-id",
            plan_id,
            "--engagement-id",
            engagement_id,
            "--created-at",
            _iso(now),
            "--output",
            str(plan_path),
        ],
        environment=environment,
    )
    _require(plan_result.returncode == 0, "public auth-plan command failed")
    plan = ActionPlan.from_dict(json.loads(plan_path.read_text(encoding="utf-8")))
    engagement = Engagement.from_dict(
        {
            "schema_version": "cops.engagement/v1",
            "engagement_id": plan.engagement_id,
            "name": "Synthetic agent MCP authorization demonstration",
            "status": "active",
            "scope": {"included_targets": [plan.target], "excluded_targets": []},
            "window": {
                "started_at": _iso(now - timedelta(minutes=1)),
                "authorized_until_utc": _iso(now + timedelta(hours=1)),
            },
            "operator": "secops-lead",
            "rules_of_engagement": {
                "max_intensity": "low",
                "allowed_actions": sorted({str(operation["action"]) for operation in plan.operations}),
                "emergency_contact": "soc@example.test",
                "safe_mode": True,
            },
            "created_at": _iso(now),
            "mode": "laboratory",
        }
    )
    secret_value = secrets.token_hex(32)
    valid_from = _iso(now - timedelta(minutes=5))
    valid_until = _iso(now + timedelta(hours=2))
    key_id = "auth-demo-ephemeral-v1"
    signer = AuthorizationSigner(
        key_id=key_id,
        operator=engagement.operator,
        secret=secret_value.encode("utf-8"),
        valid_from=valid_from,
        valid_until=valid_until,
    )
    authorization = create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity=WORKER_IDENTITY,
        issued_at=_iso(now),
        authorized_until_utc=_iso(now + timedelta(minutes=30)),
    )
    _write_private_json(engagement_path, engagement.to_dict())
    _write_private_json(authorization_path, authorization.to_dict())
    _write_private_json(
        trust_store_path,
        {
            "schema_version": "cops.authorization-trust-store/v1",
            "keys": [
                {
                    "key_id": key_id,
                    "operator_identity": engagement.operator,
                    "algorithm": "hmac-sha256",
                    "secret_env": SIGNING_SECRET_ENV,
                    "valid_from_utc": valid_from,
                    "valid_until_utc": valid_until,
                    "status": "active",
                }
            ],
        },
    )
    ApprovalStore(approval_store_path).store_authorization(authorization)
    environment[SIGNING_SECRET_ENV] = secret_value
    return cases, [
        "auth-lab",
        "--cases",
        str(CASES_PATH),
        "--plan",
        str(plan_path),
        "--engagement",
        str(engagement_path),
        "--authorization",
        str(authorization_path),
        "--trust-store",
        str(trust_store_path),
        "--worker-identity",
        WORKER_IDENTITY,
        "--approval-store",
        str(approval_store_path),
        "--json",
    ], environment


def _validate_report(report: dict[str, Any], cases: list[Any]) -> None:
    schema = json.loads((PLUGIN_ROOT / "schemas/auth-report.schema.json").read_text())
    jsonschema.validate(report, schema)
    required = auth_laboratory.required_auth_coverage()
    case_ids = [case.case_id for case in cases]
    _require(
        len(case_ids) == len(set(case_ids)) and set(case_ids) == set(required),
        "bundled cases do not match the fixed 22-case matrix",
    )
    _require(len(case_ids) == 22, "authorization demonstration must execute exactly 22 cases")
    _require(report["planned_case_count"] == 22, "report planned case count drifted")
    _require(report["completed_case_count"] == 22, "report did not complete every case")
    _require(report["pending_case_ids"] == [], "report contains pending cases")
    _require(report["cancelled"] is False, "authorization demonstration was cancelled")
    _require(report["execution_failure"] is None, "authorization demonstration recorded an execution failure")
    _require(report["next_action"] is None, "authorization demonstration requires operator recovery")
    _require(report["recovery_actions"] == [], "authorization demonstration recorded recovery actions")
    _require(report["all_expectations_met"] is True, "one or more authorization expectations failed")
    _require(report["security_pass"] is True, "authorization security assessment did not pass")
    _require(report["redacted"] is True, "authorization report is not fully redacted")
    _require(
        report["assessment_authorization"]["signed_receipt_verified"] is True,
        "signed authorization receipt was not verified",
    )
    _require(
        report["assessment_authorization"]["consumed_once_for_batch"] is True,
        "authorization was not consumed exactly once for the batch",
    )
    _require(
        report["source_snapshot"]
        == {"verified": True, "private_directory_removed": True, "reason": None, "failures": []},
        "approved source snapshot verification or cleanup failed",
    )
    results = {result["case_id"]: result for result in report["results"]}
    _require(list(results) == case_ids, "report case order or membership drifted")
    for case_id, (grant, flow, decisions, reasons, effect_count) in required.items():
        result = results[case_id]
        _require(result["grant_alias"] == grant, f"{case_id}: grant alias drifted")
        _require(result["flow"] == flow, f"{case_id}: flow drifted")
        _require(result["outcome"] == "pass", f"{case_id}: outcome was not pass")
        _require(result["reason"] == "expectations_met", f"{case_id}: expectations did not match")
        for field in ("environment_verified", "evidence_complete", "expectation_met", "security_pass", "redacted"):
            _require(result[field] is True, f"{case_id}: {field} was not true")
        _require(
            result["cleanup"] == {"process_exit_observed": True, "private_directory_removed": True},
            f"{case_id}: process or private-directory cleanup failed",
        )
        observations = result["observations"]
        _require(
            tuple(row["target"]["decision"] for row in observations) == decisions,
            f"{case_id}: target decisions drifted",
        )
        _require(
            tuple(row["target"]["reason"] for row in observations) == reasons,
            f"{case_id}: target reasons drifted",
        )
        _require(len(result["observed_effects"]) == effect_count, f"{case_id}: effect count drifted")
        normalized = result["normalized_observations"]
        _require(len(normalized) == len(observations), f"{case_id}: normalized evidence is incomplete")
        for row in normalized:
            _require(row["redacted"] is True, f"{case_id}: normalized observation is not redacted")
            _require(
                row["effect"]["trust_relation"] == "separate_process_same_trust_boundary"
                and row["effect"]["observer_identity"] == "fixed-effect-observer"
                and row["effect"]["observation_channel"] == "separate_process_private_ledger",
                f"{case_id}: observer provenance drifted",
            )
    _require(
        sum(len(result["observed_effects"]) for result in report["results"]) == 8,
        "complete matrix must contain exactly eight independently observed fixture effects",
    )


def _write_report(path: Path, report: dict[str, Any]) -> tuple[int, str]:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        if os.name == "posix":
            path.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary_name).unlink(missing_ok=True)
    return len(payload), hashlib.sha256(payload).hexdigest()


def run(output: Path) -> dict[str, Any]:
    private_root: Path | None = None
    with tempfile.TemporaryDirectory(prefix="cops-agent-mcp-auth-demo-") as directory:
        private_root = Path(directory)
        cases, auth_lab_arguments, environment = _prepare_public_cli_run(private_root)
        auth_lab_result = _run_cli(auth_lab_arguments, environment=environment)
        _require(auth_lab_result.returncode == 0, "public auth-lab command failed")
        report = json.loads(auth_lab_result.stdout)
        _validate_report(report, cases)
        replay_result = _run_cli(auth_lab_arguments, environment=environment)
        _require(replay_result.returncode == 2, "same approval replay did not fail with CLI usage status")
        _require(
            "already consumed or revoked" in replay_result.stderr.lower(),
            "same approval replay did not report the stable consumed-or-revoked denial",
        )
    _require(private_root is not None and not private_root.exists(), "ephemeral approval directory was not removed")
    report_bytes, report_sha256 = _write_report(output, report)
    return {
        "schema_version": "cops.agent-mcp-auth-demo-summary/v1",
        "status": "passed",
        "case_count": 22,
        "report": str(output.resolve()),
        "report_bytes": report_bytes,
        "report_sha256": report_sha256,
        "approval_private_directory_removed": True,
        "observer_boundary": OBSERVER_BOUNDARY,
        "public_cli": {
            "auth_plan_exit_code": 0,
            "auth_lab_exit_code": 0,
            "replayed_auth_lab_exit_code": 2,
            "same_approval_replay_denied": True,
            "replay_denial_reason": "already_consumed_or_revoked",
        },
        "declared_limitations": list(LIMITATIONS),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="path for the validated JSON report")
    args = parser.parse_args()
    try:
        summary = run(args.output)
    except (
        DemoError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        jsonschema.ValidationError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"authorization demo failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
