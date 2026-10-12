"""Trusted admission bootstrap; execution payloads load only from approved bytes.

This module, the CLI, bounded JSON reader, COPS verifier/store, Python and the OS
are the installed trusted computing base. The six execution sources are separate
approval-bound payloads, including their controller and all relative imports.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import signal
import sys
import tempfile
import threading
import time
import types
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest
from cops.execution.authorization import AuthorizationTrustStore, verify_execution_authorization
from cops.execution.store import ApprovalStore

from .bounded_json import JSONInputError, decode_json, read_regular_file

SOURCE_FILES = (
    "auth_approval.py", "auth_fixture_server.py", "auth_laboratory.py",
    "auth_peer_fixture.py", "bounded_json.py", "laboratory.py",
)


def normalize_case_inputs(cases: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bound and canonicalize data without importing any execution source."""
    rows = []
    seen = set()
    for source in cases:
        if len(rows) >= 100 or not isinstance(source, dict):
            raise ValueError("Authorization cases must be bounded JSON objects")
        # Strict JSON cloning excludes arbitrary objects and mutable shared inputs.
        import json

        row = decode_json(json.dumps(source, allow_nan=False).encode(), max_bytes=65536)
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", case_id) or len(case_id) > 64:
            raise ValueError("Invalid authorization case ID")
        if case_id in seen:
            raise ValueError("Duplicate authorization case ID")
        seen.add(case_id)
        row.setdefault("surface", "local_synthetic_fixture")
        row.setdefault("expected_outcome", "pass")
        attempts = row.get("attempts")
        if not isinstance(attempts, list) or not 1 <= len(attempts) <= 6:
            raise ValueError("Invalid authorization attempts")
        for attempt in attempts:
            if not isinstance(attempt, dict):
                raise ValueError("Invalid authorization attempt")
            attempt.setdefault("peer_action", "trusted_forward")
            attempt.setdefault("fault_mode", "none")
        rows.append(row)
    if not rows:
        raise ValueError("Authorization batch must contain at least one case")
    return rows


def load_case_inputs(path: Path) -> list[dict[str, Any]]:
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    if not files or len(files) > 100:
        raise ValueError("Authorization batch requires 1 to 100 case files")
    try:
        return normalize_case_inputs(
            decode_json(read_regular_file(file, max_bytes=65536), max_bytes=65536)
            for file in files
        )
    except JSONInputError:
        raise ValueError("Authorization cases require bounded regular files containing strict JSON") from None


@contextmanager
def _cancellation_handlers():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def cancel(_number, _frame):
        raise KeyboardInterrupt

    try:
        for number in previous:
            signal.signal(number, cancel)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


@contextmanager
def _defer_cancellation(interrupted: list[bool]):
    """Do not lose a consumed receipt or an unregistered child to cancellation."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def defer(_number, _frame):
        interrupted[0] = True

    try:
        for number in previous:
            signal.signal(number, defer)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _check_binding(plan: ActionPlan, rows: list[dict[str, Any]], sources: dict[str, bytes]) -> None:
    if len(plan.operations) != 1:
        raise ValueError("Action plan does not bind the fixed authorization batch")
    # ActionPlan freezes nested mappings; compare its canonical JSON snapshot.
    manifest = plan.approved_snapshot(include_digest=True)["operations"][0].get("arguments")
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "cops.agent-mcp-auth-manifest/v1"
        or manifest.get("case_input_sha256") != digest(rows)
        or not isinstance(manifest.get("adapter"), dict)
        or manifest["adapter"].get("source_sha256") != hashes
    ):
        raise ValueError("Action plan does not exactly bind the current immutable authorization manifest")
    expected = ActionPlan.create(
        plan_id=plan.plan_id, engagement_id=plan.engagement_id, created_at=plan.created_at,
        scenario_id="COPS-E16.01", target="local-synthetic-agent-mcp-authorization-fixture",
        specialist_id="cops-agent-mcp-authorization-lab",
        operations=[{
            "step_id": "auth-lab-batch", "tool": "foundry-agent-harness/auth-lab", "tool_version": "1",
            "action": "run_authorization_batch", "arguments": manifest, "timeout_seconds": 120,
            "cleanup": manifest.get("cleanup"), "idempotent": False,
            "expected_evidence": ["peer forwarding observation", "target authorization decision",
                                  "independent canary ledger", "process exit observation",
                                  "private directory removal observation"],
            "side_effects": ["private staged source and work directories", "local synthetic canary ledger writes"],
        }],
        limits={"max_duration_seconds": 120, "max_output_bytes": 1048576, "egress_allowed": False},
        credential_references=[], platform_prerequisites=["python-standard-library", "local-stdio-processes"],
        batch={"mode": "sequential", "max_operations": 1, "fail_fast": False},
    )
    if plan.approved_snapshot(include_digest=True) != expected.approved_snapshot(include_digest=True):
        raise ValueError("Action plan does not bind the fixed authorization batch")


def _load_executor(source_root: Path):
    """A fresh namespace prevents already-loaded, differently signed code reuse."""
    name = "_cops_auth_approved_" + uuid.uuid4().hex
    package = types.ModuleType(name)
    package.__path__ = [str(source_root)]
    package.__package__ = name
    sys.modules[name] = package
    try:
        return importlib.import_module(name + ".auth_approval")
    except BaseException:
        _unload_executor(name)
        raise


def _unload_executor(name: str) -> None:
    for key in list(sys.modules):
        if key == name or key.startswith(name + "."):
            sys.modules.pop(key, None)


def _partial_report(plan, consumed, worker, rows, started):
    return {
        "schema_version": "cops.agent-mcp-auth-run/v1",
        "environment": "local-synthetic-mcp-auth-fixture",
        "assessment_authorization": {
            "signed_receipt_verified": True, "authorization_ref": consumed.authorization_id,
            "plan_id": plan.plan_id, "plan_digest": plan.plan_digest,
            "engagement_id": plan.engagement_id, "worker_identity": worker,
            "consumed_once_for_batch": True,
        },
        "test_identity": "synthetic-fixture-runner",
        "source_snapshot": {"verified": False, "private_directory_removed": False, "reason": None},
        "cancelled": True,
        "budget": {"max_duration_seconds": 120, "cleanup_reserve_seconds": 8,
                   "elapsed_seconds": round(time.monotonic() - started, 3),
                   "max_observed_fixture_bytes": 1048576, "observed_output_bytes": 0,
                   "accounting_scope": "received_response_bytes_and_new_ledger_bytes", "stop_reason": None},
        "pending_case_ids": [row["case_id"] for row in rows],
        "next_action": "approve_a_new_plan_for_pending_cases",
        "planned_case_count": len(rows), "completed_case_count": 0,
        "all_expectations_met": False, "security_pass": False, "results": [], "redacted": True,
    }


def run_auth_cases(
    cases: Iterable[dict[str, Any]], *, plan: ActionPlan | dict[str, Any], authorization: Any,
    engagement: Any, trust_store: AuthorizationTrustStore, worker_identity: str,
    approval_store: ApprovalStore, source_root: Path | None = None,
) -> dict[str, Any]:
    """Verify, consume, stage, then import and execute the approved controller."""
    rows = normalize_case_inputs(cases)
    plan = ActionPlan.from_dict(plan) if isinstance(plan, dict) else plan
    if not isinstance(plan, ActionPlan):
        raise ValueError("Authorization laboratory requires a COPS ActionPlan")
    sources = {}
    for name in SOURCE_FILES:
        try:
            sources[name] = read_regular_file((source_root or Path(__file__).parent) / name, max_bytes=1048576)
        except JSONInputError:
            raise ValueError("Authorization fixture source unavailable: " + name) from None
    _check_binding(plan, rows, sources)
    if (
        not isinstance(trust_store, AuthorizationTrustStore) or not isinstance(approval_store, ApprovalStore)
        or not isinstance(worker_identity, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", worker_identity)
        or not hasattr(os, "geteuid") or not approval_store.require_secure_perms
    ):
        raise ValueError("Authorization verifier, private approval store, or worker identity is invalid")
    approval_store.assert_protected_owner(os.geteuid())
    verified = verify_execution_authorization(
        authorization, plan, trust_store=trust_store, engagement=engagement, worker_identity=worker_identity,
    )
    started = time.monotonic()
    interrupted = [False]
    directory = None
    executor = None
    report = None
    consumed = None
    cleanup_failure = None
    snapshot_verified = False
    with _cancellation_handlers():
        try:
            with _defer_cancellation(interrupted):
                consumed = approval_store.atomically_consume(
                    verified.authorization_id, expected_authorization=verified,
                    worker_identity=worker_identity, minimum_remaining_seconds=9,
                )
            report = _partial_report(plan, consumed, worker_identity, rows, started)
            if interrupted[0]:
                raise KeyboardInterrupt
            with _defer_cancellation(interrupted):
                directory = tempfile.TemporaryDirectory(prefix="cops-auth-source-")
            if interrupted[0]:
                raise KeyboardInterrupt
            staged = Path(directory.name)
            for name, raw in sources.items():
                with (staged / name).open("xb") as destination:
                    destination.write(raw)
                os.chmod(staged / name, 0o400)
            os.chmod(staged, 0o500)
            snapshot_verified = True
            with _defer_cancellation(interrupted):
                executor = _load_executor(staged)
            if interrupted[0]:
                raise KeyboardInterrupt
            normalized = executor._coerce_cases(rows)
            rebuilt = executor.build_auth_plan(
                normalized, plan_id=plan.plan_id, engagement_id=plan.engagement_id,
                created_at=plan.created_at, _sources=sources,
            )
            if rebuilt.approved_snapshot(include_digest=True) != plan.approved_snapshot(include_digest=True):
                raise ValueError("Approved payload and cases do not reconstruct the signed plan")
            report = executor._run_bound_batch(normalized, plan, consumed, worker_identity, staged)
        except KeyboardInterrupt:
            interrupted[0] = True
            if consumed is None:
                raise ValueError("Authorization admission was cancelled before consumption") from None
            if report is None:
                report = _partial_report(plan, consumed, worker_identity, rows, started)
        except (OSError, ValueError):
            if consumed is None:
                raise
            cleanup_failure = "source_snapshot_setup_or_execution_failure"
            report = report or _partial_report(plan, consumed, worker_identity, rows, started)
            report["cancelled"] = False
        finally:
            with _defer_cancellation(interrupted):
                if executor is not None:
                    _unload_executor(executor.__package__)
                if directory is not None:
                    try:
                        os.chmod(directory.name, 0o700)
                        directory.cleanup()
                    except OSError:
                        cleanup_failure = "source_snapshot_cleanup_failure"
        removed = directory is None or not Path(directory.name).exists()
        if not removed:
            cleanup_failure = cleanup_failure or "source_snapshot_removal_not_observed"
        report["source_snapshot"] = {
            "verified": snapshot_verified, "private_directory_removed": removed, "reason": cleanup_failure,
        }
        report["cancelled"] = report["cancelled"] or interrupted[0]
        if cleanup_failure is not None or report["cancelled"] or not snapshot_verified or not removed:
            report["all_expectations_met"] = report["security_pass"] = False
        if cleanup_failure is not None:
            report["next_action"] = "inspect_source_snapshot_cleanup_before_new_approval"
        elif report["cancelled"] and not report["pending_case_ids"]:
            report["next_action"] = "review_partial_run_evidence"
        return report
