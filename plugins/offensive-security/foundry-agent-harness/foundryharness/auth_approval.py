"""COPS-approved execution wrapper for the fixed MCP authorization laboratory."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import EvidenceError, decode_json, digest, timestamp, utc_now
from cops.execution.authorization import AuthorizationTrustStore, verify_execution_authorization
from cops.execution.store import ApprovalStore

from .auth_fixture_server import (
    ARGUMENT_ALIASES,
    ARGUMENT_FIELDS,
    FAULT_MODES,
    GRANTS,
    PEER_ACTIONS,
    PROTOCOL_VERSION,
    REQUIRED_ARGUMENT_FIELDS,
    SCOPES,
    SERVER_IDENTITY,
    SERVER_INFO,
    SYNTHETIC_GRANT_ALIASES,
    TEST_IDENTITY,
    TOOL_INPUT_SCHEMAS,
    TOOL_PERMISSIONS,
    TOOLS,
)
from .auth_laboratory import AUTHENTICATION_REASONS, DECISIONS, PHASES, REASONS, AuthCase
from .laboratory import LabError, _JsonLineProcess, _McpClient

ADAPTER_ID = "local-synthetic-mcp-auth-fixture"
SCENARIO_ID = "COPS-E16.01"
TARGET = "local-synthetic-agent-mcp-authorization-fixture"
SPECIALIST_ID = "cops-agent-mcp-authorization-lab"
PEER_IDENTITIES = {
    "trusted_forward": "trusted-forwarding-peer",
    "mutate_tenant": "hostile-forwarding-peer",
    "omit_tenant": "hostile-forwarding-peer",
    "mutate_operation": "hostile-forwarding-peer",
    "substitute_receipt": "hostile-forwarding-peer",
}
SOURCE_FILES = (
    "auth_approval.py",
    "auth_fixture_server.py",
    "auth_laboratory.py",
    "auth_peer_fixture.py",
    "bounded_json.py",
    "laboratory.py",
)
LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "request_id",
        "canary_id",
        "plan_digest",
        "test_identity",
        "server_identity",
        "kind",
        "tenant",
        "resource",
        "operation",
        "redacted",
    }
)
DECISION_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "request_id",
        "canary_id",
        "plan_digest",
        "test_identity",
        "server_identity",
        "target_grant_alias",
        "decision",
        "phase",
        "reason",
        "redacted",
    }
)
PEER_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "peer_action",
        "peer_identity",
        "attempt_id",
        "request_id",
        "canary_id",
        "plan_digest",
        "test_identity",
        "forwarded_request",
        "forwarded_request_digest",
        "redacted",
    }
)


class _BatchBudgetStop(LabError):
    """Stop admission without treating missing observations as a denial."""


class _BatchBudget:
    """Account observed bytes and reserve time for both fixed child cleanups."""

    def __init__(self, plan: ActionPlan, authorized_until_utc: str) -> None:
        self.started = time.monotonic()
        self.authorized_until = timestamp(authorized_until_utc)
        remaining = (self.authorized_until - timestamp(utc_now())).total_seconds()
        self.duration_limit = plan.limits["max_duration_seconds"]
        self.output_limit = plan.limits["max_output_bytes"]
        self.cleanup_reserve = 8
        self.deadline = self.started + max(0, min(self.duration_limit, remaining) - self.cleanup_reserve)
        self.window_limited = remaining < self.duration_limit
        self.output_bytes = 0
        self.ledgers: dict[Path, bytes] = {}
        self.stop_reason: str | None = None

    def stop(self, reason: str) -> None:
        self.stop_reason = reason
        raise _BatchBudgetStop(reason)

    def admit(self) -> None:
        if timestamp(utc_now()) >= self.authorized_until:
            self.stop("authorization_expired")
        if time.monotonic() >= self.deadline:
            self.stop("authorization_window_exhausted" if self.window_limited else "duration_budget_exhausted")
        if self.output_bytes >= self.output_limit:
            self.stop("output_budget_exhausted")

    def response_timeout(self) -> float:
        self.admit()
        return max(0.001, min(1, self.deadline - time.monotonic()))

    def account_response(self, raw: bytes) -> None:
        self.output_bytes += len(raw)
        if self.output_bytes > self.output_limit:
            self.stop("output_budget_exhausted")

    def account_ledger(self, ledger: Path, raw: bytes) -> None:
        previous = self.ledgers.get(ledger, b"")
        if not raw.startswith(previous):
            raise LabError("Independent effect ledger changed previously observed bytes")
        self.account_response(raw[len(previous):])
        self.ledgers[ledger] = raw

    def report(self) -> dict[str, Any]:
        return {
            "max_duration_seconds": self.duration_limit,
            "cleanup_reserve_seconds": self.cleanup_reserve,
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "max_output_bytes": self.output_limit,
            "observed_output_bytes": self.output_bytes,
            "accounting_scope": "received_response_bytes_and_new_ledger_bytes",
            "stop_reason": self.stop_reason,
        }


def _coerce_cases(cases: Iterable[AuthCase | dict[str, Any]]) -> tuple[AuthCase, ...]:
    normalized: list[AuthCase] = []
    seen: set[str] = set()
    for source in cases:
        if len(normalized) >= 100:
            raise LabError("Authorization batch exceeds 100 cases")
        case = AuthCase.from_dict(source.to_dict() if isinstance(source, AuthCase) else source)
        if case.case_id in seen:
            raise LabError(f"Duplicate authorization case ID: {case.case_id}")
        seen.add(case.case_id)
        normalized.append(case)
    if not normalized:
        raise LabError("Authorization batch must contain at least one case")
    return tuple(normalized)


def _source_digests() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    values: dict[str, str] = {}
    for name in SOURCE_FILES:
        source = root / name
        if source.is_symlink() or not source.is_file():
            raise LabError(f"Authorization fixture source unavailable: {name}")
        values[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    return values


def _attempt_ids(case: AuthCase, index: int) -> dict[str, str]:
    prefix = f"{case.case_id}-{index}"
    return {
        "attempt_id": prefix,
        "request_id": f"request-{prefix}",
        "canary_id": f"canary-{prefix}",
    }


def _planned_cases(cases: tuple[AuthCase, ...]) -> list[dict[str, Any]]:
    planned: list[dict[str, Any]] = []
    for case in cases:
        attempts = []
        for index, (attempt, decision, reason) in enumerate(
            zip(case.attempts, case.expected_decisions, case.expected_reasons, strict=True),
            start=1,
        ):
            attempts.append(
                {
                    **_attempt_ids(case, index),
                    "request": {
                        "grant": case.grant,
                        "flow": case.flow,
                        **dict(attempt),
                    },
                    "expectation": {
                        "decision": decision,
                        "reason": reason,
                        "effect_delta": 1 if decision == "allowed" and attempt["tool"] == "canary/write" else 0,
                    },
                }
            )
        planned.append(
            {
                "schema_version": "cops.agent-mcp-auth-planned-case/v1",
                "surface": case.surface,
                "case_id": case.case_id,
                "title": case.title,
                "attempts": attempts,
                "expected_effect_count": case.expected_effect_count,
                "expected_outcome": case.expected_outcome,
            }
        )
    return planned



def _manifest(cases: tuple[AuthCase, ...]) -> dict[str, Any]:
    return {
        "schema_version": "cops.agent-mcp-auth-manifest/v1",
        "test_identity": TEST_IDENTITY,
        "adapter": {
            "adapter_id": ADAPTER_ID,
            "source_sha256": _source_digests(),
            "protocol_version": PROTOCOL_VERSION,
            "server_info": SERVER_INFO,
            "transport": "stdio",
            "tools": list(TOOLS),
            "tool_input_schemas": TOOL_INPUT_SCHEMAS,
            "tool_permissions": list(TOOL_PERMISSIONS),
            "peer_actions": list(PEER_ACTIONS),
        },
        "cases": _planned_cases(cases),
        "fault_modes": {
            "supported": list(FAULT_MODES),
            "hung_server_timeout_seconds": 1,
            "missing_identity_telemetry_outcome": "inconclusive",
            "observer_failure_outcome": "inconclusive",
        },
        "limits": {
            "max_cases": 100,
            "max_attempts_per_case": 6,
            "max_ledger_bytes": 65536,
            "max_response_bytes": 65536,
            "network_egress": False,
        },
        "cleanup": {
            "terminate_fixture_processes": True,
            "verify_process_exit": True,
            "remove_private_work_directory": True,
            "verify_private_directory_removal": True,
        },
    }


def build_auth_plan(
    cases: Iterable[AuthCase | dict[str, Any]],
    *,
    plan_id: str,
    engagement_id: str,
    created_at: str,
) -> ActionPlan:
    """Compile the exact fixed batch into the existing COPS signing lifecycle."""
    normalized = _coerce_cases(cases)
    if len(normalized) > 100:
        raise LabError("Authorization batch exceeds the fixed case limit")
    manifest = _manifest(normalized)
    return ActionPlan.create(
        plan_id=plan_id,
        engagement_id=engagement_id,
        scenario_id=SCENARIO_ID,
        target=TARGET,
        specialist_id=SPECIALIST_ID,
        operations=[
            {
                "step_id": "auth-lab-batch",
                "tool": "foundry-agent-harness/auth-lab",
                "tool_version": "1",
                "action": "run_authorization_batch",
                "arguments": manifest,
                "timeout_seconds": 120,
                "cleanup": manifest["cleanup"],
                "idempotent": False,
                "expected_evidence": [
                    "peer forwarding observation",
                    "target authorization decision",
                    "independent canary ledger",
                    "process exit observation",
                    "private directory removal observation",
                ],
                "side_effects": ["local synthetic canary ledger writes"],
            }
        ],
        limits={
            "max_duration_seconds": 120,
            "max_output_bytes": 1048576,
            "egress_allowed": False,
        },
        credential_references=[],
        created_at=created_at,
        platform_prerequisites=["python-standard-library", "local-stdio-processes"],
        batch={"mode": "sequential", "max_operations": 1, "fail_fast": False},
    )


def _read_effects(ledger: Path, budget: _BatchBudget) -> list[dict[str, Any]]:
    budget.admit()
    try:
        descriptor = os.open(ledger, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
                raise LabError("Independent effect observer is unavailable or oversized")
            raw = stream.read(65537)
        if len(raw) > 65536 or (raw and not raw.endswith(b"\n")):
            raise LabError("Independent effect observer is unavailable or oversized")
        budget.account_ledger(ledger, raw)
        events = [decode_json(line, max_bytes=65536) for line in raw.splitlines()]
    except (OSError, EvidenceError) as exc:
        raise LabError("Independent effect observer returned malformed evidence") from exc
    for event in events:
        if (
            not isinstance(event, dict)
            or set(event) != LEDGER_FIELDS
            or event["schema_version"] != "cops.agent-mcp-auth-ledger-event/v1"
            or event["server_identity"] != SERVER_IDENTITY
            or event["test_identity"] != TEST_IDENTITY
            or event["kind"] != "canary_write"
            or event["operation"] != "write"
            or event["redacted"] is not True
        ):
            raise LabError("Independent effect observer returned malformed evidence")
    return events


def _request(case: AuthCase, attempt: dict[str, Any], index: int, plan_digest: str) -> dict[str, Any]:
    request = {
        "grant": case.grant,
        "flow": case.flow,
        **{
            key: value
            for key, value in attempt.items()
            if key not in {"tool", "peer_action", "fault_mode"}
        },
        **_attempt_ids(case, index),
        "plan_digest": plan_digest,
        "test_identity": TEST_IDENTITY,
        "fault_mode": attempt["fault_mode"],
    }
    return request


def _validate_request(value: dict[str, Any]) -> None:
    if set(value) not in (REQUIRED_ARGUMENT_FIELDS, ARGUMENT_FIELDS):
        raise LabError("Peer forwarded a request outside the fixed schema")
    for key, allowed in ARGUMENT_ALIASES.items():
        if key == "tenant" and key not in value:
            continue
        if not isinstance(value.get(key), str) or value[key] not in allowed:
            raise LabError("Peer forwarded a request outside fixed aliases")
    if (
        not isinstance(value["scopes"], list)
        or len(value["scopes"]) != 1
        or not isinstance(value["scopes"][0], str)
        or value["scopes"][0] not in SCOPES
        or type(value["depth"]) is not int
        or not 0 <= value["depth"] <= 3
        or type(value["tick"]) is not int
        or not 0 <= value["tick"] <= 10
        or value["test_identity"] != TEST_IDENTITY
        or not isinstance(value["fault_mode"], str)
        or value["fault_mode"] not in FAULT_MODES
    ):
        raise LabError("Peer forwarded malformed fixed request values")


def _validate_peer(
    value: dict[str, Any],
    original: dict[str, Any],
    action: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != PEER_OBSERVATION_FIELDS
        or value["schema_version"] != "cops.agent-mcp-auth-peer-observation/v1"
        or value["peer_action"] != action
        or value["peer_identity"] != PEER_IDENTITIES[action]
        or value["redacted"] is not True
    ):
        raise LabError("Peer delegation observation is malformed")
    for key in ("attempt_id", "request_id", "canary_id", "plan_digest", "test_identity"):
        if value[key] != original[key]:
            raise LabError("Peer delegation correlation mismatch")
    forwarded = value["forwarded_request"]
    if not isinstance(forwarded, dict):
        raise LabError("Peer did not forward a request object")
    _validate_request(forwarded)
    if value["forwarded_request_digest"] != digest(forwarded):
        raise LabError("Peer forwarded-request digest mismatch")
    changed = {
        key
        for key in set(original) | set(forwarded)
        if original.get(key, object()) != forwarded.get(key, object())
    }
    expected_changes = {
        "trusted_forward": set(),
        "mutate_tenant": {"tenant"},
        "omit_tenant": {"tenant"},
        "mutate_operation": {"operation"},
        "substitute_receipt": {"grant"},
    }[action]
    if changed != expected_changes:
        raise LabError("Peer changed fields outside its approved synthetic mutation")
    return forwarded


def _validate_decision(value: dict[str, Any], request: dict[str, Any]) -> bool:
    if not isinstance(value, dict):
        raise LabError("Target authorization decision is malformed")
    identity_present = "server_identity" in value
    expected_fields = DECISION_FIELDS if identity_present else DECISION_FIELDS - {"server_identity"}
    if (
        set(value) != expected_fields
        or value["schema_version"] != "cops.agent-mcp-auth-decision/v1"
        or value["target_grant_alias"] != request["grant"]
        or not isinstance(value["decision"], str)
        or value["decision"] not in DECISIONS
        or not isinstance(value["phase"], str)
        or value["phase"] not in PHASES
        or not isinstance(value["reason"], str)
        or value["reason"] not in REASONS
        or value["redacted"] is not True
    ):
        raise LabError("Target authorization decision is malformed")
    for key in ("attempt_id", "request_id", "canary_id", "plan_digest", "test_identity"):
        if value[key] != request[key]:
            raise LabError("Target authorization decision correlation mismatch")
    if identity_present and value["server_identity"] != SERVER_IDENTITY:
        raise LabError("Target authorization identity mismatch")
    expected_phase = (
        "setup"
        if value["reason"] == "missing_context"
        else "authentication"
        if value["reason"] in AUTHENTICATION_REASONS
        else "authorization"
    )
    expected_decision = (
        "inconclusive"
        if value["reason"] == "missing_context"
        else "allowed"
        if value["reason"] == "allowed"
        else "denied"
    )
    if value["phase"] != expected_phase or value["decision"] != expected_decision:
        raise LabError("Target authorization decision is internally inconsistent")
    return identity_present


def _unsupported_result(case: AuthCase, plan_digest: str) -> dict[str, Any]:
    return {
        "schema_version": "cops.agent-mcp-auth-result/v1",
        "case_id": case.case_id,
        "plan_digest": plan_digest,
        "test_identity": TEST_IDENTITY,
        "grant_alias": case.grant,
        "flow": case.flow,
        "outcome": "unsupported",
        "reason": "surface_not_supported_by_local_fixed_adapter",
        "environment_verified": False,
        "observations": [],
        "observed_effects": [],
        "cleanup": {
            "process_exit_observed": None,
            "private_directory_removed": None,
        },
        "redacted": True,
        "expectation_met": case.expected_outcome == "unsupported",
        "revocation_window": None,
    }


def _run_auth_case(case: AuthCase, plan_digest: str, budget: _BatchBudget) -> tuple[dict[str, Any], bool]:
    if case.surface != "local_synthetic_fixture":
        return _unsupported_result(case, plan_digest), False

    observations: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    failure: str | None = None
    cancelled = False
    environment_verified = False
    process_exit_observed = False
    workdir_path: Path | None = None

    try:
        with tempfile.TemporaryDirectory(prefix="cops-auth-lab-") as workdir:
            workdir_path = Path(workdir)
            ledger = workdir_path / "effects.jsonl"
            ledger.touch(mode=0o600, exist_ok=False)
            server: _JsonLineProcess | None = None
            peer: _JsonLineProcess | None = None
            closed: list[bool] = []
            try:
                server = _JsonLineProcess(
                    "auth_fixture_server.py",
                    workdir,
                    response_timeout_seconds=1,
                    admission_check=budget.admit,
                    response_timeout_provider=budget.response_timeout,
                    account_response=budget.account_response,
                )
                peer = _JsonLineProcess(
                    "auth_peer_fixture.py",
                    workdir,
                    response_timeout_seconds=1,
                    admission_check=budget.admit,
                    response_timeout_provider=budget.response_timeout,
                    account_response=budget.account_response,
                )
                mcp = _McpClient(
                    server,
                    expected_tools=frozenset(TOOLS),
                    expected_server_info=SERVER_INFO,
                    expected_input_schemas=TOOL_INPUT_SCHEMAS,
                )
                mcp.initialize()
                events = _read_effects(ledger, budget)
                environment_verified = True
                for index, (attempt, expected_decision, expected_reason) in enumerate(
                    zip(case.attempts, case.expected_decisions, case.expected_reasons, strict=True),
                    start=1,
                ):
                    original = _request(case, attempt, index, plan_digest)
                    ids = _attempt_ids(case, index)
                    peer_value = peer.exchange(
                        {
                            "jsonrpc": "2.0",
                            "id": index,
                            "method": "peer/forward",
                            "params": {
                                "schema_version": "cops.agent-mcp-auth-peer-request/v1",
                                "peer_action": attempt["peer_action"],
                                "peer_identity": PEER_IDENTITIES[attempt["peer_action"]],
                                **ids,
                                "plan_digest": plan_digest,
                                "test_identity": TEST_IDENTITY,
                                "request": original,
                            },
                        }
                    )
                    if (
                        peer_value is None
                        or peer_value.get("jsonrpc") != "2.0"
                        or peer_value.get("id") != index
                        or "error" in peer_value
                        or not isinstance(peer_value.get("result"), dict)
                    ):
                        raise LabError("Peer delegation process rejected the fixed request")
                    peer_observation = peer_value["result"]
                    forwarded = _validate_peer(peer_observation, original, attempt["peer_action"])
                    decision = mcp.call(attempt["tool"], forwarded)
                    identity_present = _validate_decision(decision, forwarded)
                    observed = _read_effects(ledger, budget)
                    if observed[:len(events)] != events:
                        raise LabError("Independent effect ledger changed previously observed events")
                    delta = observed[len(events):]
                    for event in delta:
                        if any(event[key] != forwarded[key] for key in (
                            "attempt_id",
                            "request_id",
                            "canary_id",
                            "plan_digest",
                            "test_identity",
                            "tenant",
                            "resource",
                        )):
                            raise LabError("Independent effect correlation mismatch")
                    observations.append(
                        {
                            "schema_version": "cops.agent-mcp-auth-observation/v1",
                            "case_id": case.case_id,
                            **ids,
                            "plan_digest": plan_digest,
                            "test_identity": TEST_IDENTITY,
                            "tool": attempt["tool"],
                            "peer": peer_observation,
                            "target": decision,
                            "observed_effect_count": len(delta),
                            "expected_decision": expected_decision,
                            "expected_reason": expected_reason,
                            "redacted": (
                                peer_observation["redacted"] is True
                                and decision["redacted"] is True
                                and all(event["redacted"] is True for event in delta)
                            ),
                        }
                    )
                    events = observed
                    if not identity_present:
                        failure = "missing_identity_telemetry"
                        break
            except KeyboardInterrupt:
                failure = "cancelled"
                cancelled = True
            except _BatchBudgetStop as exc:
                failure = str(exc)
            except LabError as exc:
                message = str(exc)
                if "timed out" in message:
                    failure = "fixture_timeout"
                elif "effect observer" in message or "ledger" in message:
                    failure = "observer_failure"
                elif "Peer" in message or "peer" in message:
                    failure = "peer_setup_or_observation_failure"
                else:
                    failure = "fixture_setup_or_protocol_failure"
            except (OSError, ValueError, TypeError):
                failure = "fixture_setup_or_observation_failure"
            finally:
                for process in (peer, server):
                    if process is not None:
                        try:
                            closed.append(process.close())
                        except (OSError, ValueError, subprocess.SubprocessError):
                            closed.append(False)
                process_exit_observed = len(closed) == 2 and all(closed)
    except (OSError, ValueError):
        failure = failure or "private_directory_setup_or_cleanup_failure"

    private_directory_removed = workdir_path is not None and not workdir_path.exists()
    if not process_exit_observed:
        failure = failure or "process_exit_not_observed"
    if not private_directory_removed:
        failure = failure or "private_directory_removal_not_observed"

    expected_deltas = [
        1 if decision == "allowed" and attempt["tool"] == "canary/write" else 0
        for attempt, decision in zip(case.attempts, case.expected_decisions, strict=True)
    ]
    evidence_complete = (
        failure is None
        and environment_verified
        and process_exit_observed
        and private_directory_removed
        and len(observations) == len(case.attempts)
    )
    expectations_match = (
        evidence_complete
        and [row["target"]["decision"] for row in observations] == list(case.expected_decisions)
        and [row["target"]["reason"] for row in observations] == list(case.expected_reasons)
        and [row["observed_effect_count"] for row in observations] == expected_deltas
        and len(events) == case.expected_effect_count
        and all(row["redacted"] is True for row in observations)
    )
    missing_context = any(row["target"]["decision"] == "inconclusive" for row in observations)
    outcome = "inconclusive" if missing_context else "pass" if expectations_match else "fail" if evidence_complete else "inconclusive"
    revocation_window = None
    revoked_at = GRANTS[case.grant].get("revoked_at")
    if revoked_at is not None:
        ticks = [row["peer"]["forwarded_request"]["tick"] for row in observations]
        denied_ticks = [
            row["peer"]["forwarded_request"]["tick"] for row in observations
            if row["target"]["reason"] == "revoked_grant"
        ]
        revocation_window = {
            "clock": "synthetic_logical_ticks",
            "revoked_at_tick": revoked_at,
            "observed_start_tick": min(ticks) if ticks else None,
            "observed_end_tick": max(ticks) if ticks else None,
            "pre_revocation_control_observed": any(
                row["peer"]["forwarded_request"]["tick"] < revoked_at
                and row["target"]["decision"] == "allowed"
                and row["observed_effect_count"] == 1 for row in observations
            ),
            "post_revocation_denial_observed": bool(denied_ticks),
            "observed_denial_lag_ticks": min(denied_ticks) - revoked_at if denied_ticks else None,
            "provider_propagation_measured": False,
        }
    result = {
        "schema_version": "cops.agent-mcp-auth-result/v1",
        "case_id": case.case_id,
        "plan_digest": plan_digest,
        "test_identity": TEST_IDENTITY,
        "grant_alias": case.grant,
        "flow": case.flow,
        "outcome": outcome,
        "reason": failure or ("missing_context" if missing_context else "expectations_met" if expectations_match else "expectation_mismatch"),
        "environment_verified": environment_verified,
        "observations": observations,
        "observed_effects": events,
        "cleanup": {
            "process_exit_observed": process_exit_observed,
            "private_directory_removed": private_directory_removed,
        },
        "redacted": all(row.get("redacted") is True for row in observations)
        and all(event.get("redacted") is True for event in events),
        "expectation_met": outcome == case.expected_outcome and (expectations_match or not evidence_complete),
        "revocation_window": revocation_window,
    }
    return result, cancelled


def run_auth_cases(
    cases: Iterable[AuthCase | dict[str, Any]],
    *,
    plan: ActionPlan | dict[str, Any],
    authorization: Any,
    engagement: Any,
    trust_store: AuthorizationTrustStore,
    worker_identity: str,
    approval_store: ApprovalStore,
) -> dict[str, Any]:
    """Verify and consume one COPS approval before starting the fixed batch."""
    normalized = _coerce_cases(cases)
    supplied_plan = ActionPlan.from_dict(plan) if isinstance(plan, dict) else plan
    if not isinstance(supplied_plan, ActionPlan):
        raise LabError("Authorization laboratory requires a COPS ActionPlan")
    rebuilt = build_auth_plan(
        normalized,
        plan_id=supplied_plan.plan_id,
        engagement_id=supplied_plan.engagement_id,
        created_at=supplied_plan.created_at,
    )
    if supplied_plan.approved_snapshot(include_digest=True) != rebuilt.approved_snapshot(include_digest=True):
        raise LabError("Action plan does not exactly bind the current immutable authorization manifest")
    if (
        not isinstance(trust_store, AuthorizationTrustStore)
        or not isinstance(approval_store, ApprovalStore)
        or not isinstance(worker_identity, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", worker_identity)
    ):
        raise LabError("Authorization verifier, private approval store, or worker identity is invalid")
    if not hasattr(os, "geteuid") or not approval_store.require_secure_perms:
        raise LabError("Authorization laboratory requires a private owner-protected approval store")
    approval_store.assert_protected_owner(os.geteuid())
    verified = verify_execution_authorization(
        authorization,
        supplied_plan,
        trust_store=trust_store,
        engagement=engagement,
        worker_identity=worker_identity,
    )
    consumed = approval_store.atomically_consume(
        verified.authorization_id,
        expected_authorization=verified,
        worker_identity=worker_identity,
    )
    budget = _BatchBudget(supplied_plan, verified.authorized_until_utc)

    results: list[dict[str, Any]] = []
    cancelled = False
    interrupted_case: str | None = None
    for case in normalized:
        try:
            budget.admit()
        except _BatchBudgetStop:
            break
        result, case_cancelled = _run_auth_case(case, supplied_plan.plan_digest, budget)
        results.append(result)
        if case_cancelled:
            cancelled = True
            interrupted_case = case.case_id
            break
        if budget.stop_reason is not None:
            interrupted_case = case.case_id
            break
    pending = [case.case_id for case in normalized[len(results):]]
    if interrupted_case is not None:
        pending.insert(0, interrupted_case)
    return {
        "schema_version": "cops.agent-mcp-auth-run/v1",
        "environment": "local-synthetic-mcp-auth-fixture",
        "assessment_authorization": {
            "signed_receipt_verified": True,
            "authorization_ref": consumed.authorization_id,
            "plan_id": supplied_plan.plan_id,
            "plan_digest": supplied_plan.plan_digest,
            "engagement_id": supplied_plan.engagement_id,
            "worker_identity": worker_identity,
            "consumed_once_for_batch": True,
        },
        "test_identity": TEST_IDENTITY,
        "cancelled": cancelled,
        "budget": budget.report(),
        "pending_case_ids": pending,
        "next_action": "approve_a_new_plan_for_pending_cases" if pending else None,
        "planned_case_count": len(normalized),
        "completed_case_count": len(results),
        "all_expectations_met": not cancelled and budget.stop_reason is None and len(results) == len(normalized)
        and all(result["expectation_met"] for result in results),
        "results": results,
        "redacted": all(result["redacted"] is True for result in results),
    }
