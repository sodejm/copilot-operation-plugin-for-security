"""Trusted admission bootstrap; execution payloads load only from approved bytes.

This module, the CLI, COPS data-only planner/verifier/store, Python and the OS
are the installed trusted computing base. The seven execution sources are separate
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
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest
from cops.execution.authorization import AuthorizationTrustStore, verify_execution_authorization
from cops.execution.store import ApprovalStore
from cops.laboratory.agent_mcp import (
    SOURCE_FILES,
    JSONInputError,
    build_auth_plan,
    normalize_case_inputs,
    read_regular_file,
)


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


def _check_binding(plan: ActionPlan, rows: tuple[dict[str, Any], ...], sources: dict[str, bytes]) -> None:
    if len(plan.operations) != 1:
        raise ValueError("Action plan does not bind the fixed authorization batch")
    # ActionPlan freezes nested mappings; compare its canonical JSON snapshot.
    manifest = plan.approved_snapshot(include_digest=True)["operations"][0].get("arguments")
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "cops.agent-mcp-auth-manifest/v1"
        or manifest.get("case_input_sha256") != digest(list(rows))
        or not isinstance(manifest.get("adapter"), dict)
        or manifest["adapter"].get("source_sha256") != hashes
    ):
        raise ValueError("Action plan does not exactly bind the current immutable authorization manifest")
    expected = build_auth_plan(
        rows,
        plan_id=plan.plan_id,
        engagement_id=plan.engagement_id,
        created_at=plan.created_at,
        _sources=sources,
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
            "signed_receipt_verified": True,
            "authorization_ref": consumed.authorization_id,
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "engagement_id": plan.engagement_id,
            "worker_identity": worker,
            "consumed_once_for_batch": True,
        },
        "test_identity": "synthetic-fixture-runner",
        "source_snapshot": {"verified": False, "private_directory_removed": False, "reason": None, "failures": []},
        "cancelled": True,
        "execution_failure": None,
        "budget": {
            "max_duration_seconds": 120,
            "cleanup_reserve_seconds": 8,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "max_observed_fixture_bytes": 1048576,
            "observed_output_bytes": 0,
            "accounting_scope": "received_response_bytes_and_new_ledger_bytes",
            "stop_reason": None,
        },
        "pending_case_ids": [row["case_id"] for row in rows],
        "next_action": "approve_a_new_plan_for_pending_cases",
        "recovery_actions": ["approve_a_new_plan_for_pending_cases"],
        "planned_case_count": len(rows),
        "completed_case_count": 0,
        "all_expectations_met": False,
        "security_pass": False,
        "results": [],
        "redacted": True,
    }


def run_auth_cases(
    cases: Iterable[dict[str, Any]],
    *,
    plan: ActionPlan | dict[str, Any],
    authorization: Any,
    engagement: Any,
    trust_store: AuthorizationTrustStore,
    worker_identity: str,
    approval_store: ApprovalStore,
    source_root: Path | None = None,
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
        not isinstance(trust_store, AuthorizationTrustStore)
        or not isinstance(approval_store, ApprovalStore)
        or not isinstance(worker_identity, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", worker_identity)
        or not hasattr(os, "geteuid")
        or not approval_store.require_secure_perms
    ):
        raise ValueError("Authorization verifier, private approval store, or worker identity is invalid")
    approval_store.assert_protected_owner(os.geteuid())
    verified = verify_execution_authorization(
        authorization,
        plan,
        trust_store=trust_store,
        engagement=engagement,
        worker_identity=worker_identity,
    )
    started = time.monotonic()
    interrupted = [False]
    directory = None
    executor = None
    report = None
    consumed = None
    snapshot_failures = []
    snapshot_verified = False
    with _cancellation_handlers():
        try:
            with _defer_cancellation(interrupted):
                consumed = approval_store.atomically_consume(
                    verified.authorization_id,
                    expected_authorization=verified,
                    worker_identity=worker_identity,
                    minimum_remaining_seconds=9,
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
                normalized,
                plan_id=plan.plan_id,
                engagement_id=plan.engagement_id,
                created_at=plan.created_at,
                _sources=sources,
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
        except (Exception, SystemExit):
            if consumed is None:
                raise
            snapshot_failures.append("source_snapshot_setup_or_execution_failure")
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
                        snapshot_failures.append("source_snapshot_cleanup_failure")
        removed = directory is None or not Path(directory.name).exists()
        if not removed:
            snapshot_failures.append("source_snapshot_removal_not_observed")
        report["source_snapshot"] = {
            "verified": snapshot_verified,
            "private_directory_removed": removed,
            "reason": snapshot_failures[0] if snapshot_failures else None,
            "failures": snapshot_failures,
        }
        report["cancelled"] = report["cancelled"] or interrupted[0]
        if snapshot_failures or report["cancelled"] or not snapshot_verified or not removed:
            report["all_expectations_met"] = report["security_pass"] = False
        recovery = []
        if report.get("execution_failure"):
            recovery.append("reconcile_uncertain_execution_effects_before_new_approval")
        if "source_snapshot_setup_or_execution_failure" in snapshot_failures:
            recovery.append("inspect_execution_initialization_before_new_approval")
        if any(
            failure in snapshot_failures
            for failure in (
                "source_snapshot_cleanup_failure",
                "source_snapshot_removal_not_observed",
            )
        ):
            recovery.append("inspect_source_snapshot_cleanup_before_new_approval")
        if report["pending_case_ids"]:
            recovery.append("approve_a_new_plan_for_pending_cases")
        elif report["cancelled"]:
            recovery.append("review_partial_run_evidence")
        report["recovery_actions"] = recovery
        report["next_action"] = recovery[0] if recovery else None
        return report
