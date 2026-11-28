"""COPS-approved execution wrapper for the fixed MCP authorization laboratory."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import EvidenceError, decode_json, digest, timestamp, utc_now
from cops.execution.authorization import AuthorizationTrustStore
from cops.execution.store import ApprovalStore, ApprovalStoreConflictError
from cops.laboratory.agent_mcp import build_auth_plan as _build_trusted_auth_plan

from .auth_fixture_server import (
    ARGUMENT_ALIASES,
    ARGUMENT_FIELDS,
    FAULT_MODES,
    GRANTS,
    ID_PATTERN,
    REQUIRED_ARGUMENT_FIELDS,
    SCOPES,
    SERVER_IDENTITY,
    SERVER_INFO,
    TEST_IDENTITY,
    TOOL_DESCRIPTORS,
    TOOL_INPUT_SCHEMAS,
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
MINIMUM_AUTHORIZATION_SECONDS = 9
LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "case_id",
        "attempt_id",
        "request_id",
        "canary_id",
        "plan_digest",
        "test_identity",
        "server_identity",
        "kind",
        "principal",
        "tool",
        "tenant",
        "resource",
        "operation",
        "redacted",
        "observer_identity",
        "observer_key_id",
        "observer_session_id",
        "observer_sequence",
        "signature_algorithm",
        "observer_signature",
    }
)


@dataclass(frozen=True)
class _ObserverVerifier:
    identity: str
    key_id: str
    session_id: str
    public_key: Ed25519PublicKey


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_observer_ready(value: Any, challenge: str) -> _ObserverVerifier:
    fields = {
        "ready",
        "observer_identity",
        "observer_challenge",
        "observer_public_key",
        "observer_key_id",
        "observer_session_id",
        "signature_algorithm",
        "observer_signature",
    }
    try:
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError
        unsigned = dict(value)
        signature = base64.b64decode(unsigned.pop("observer_signature"), validate=True)
        public_raw = base64.b64decode(value["observer_public_key"], validate=True)
        if (
            value["ready"] is not True
            or value["observer_identity"] != "fixed-effect-observer"
            or value["observer_challenge"] != challenge
            or value["signature_algorithm"] != "ed25519"
            or len(public_raw) != 32
            or value["observer_key_id"] != hashlib.sha256(public_raw).hexdigest()
            or value["observer_session_id"]
            != hashlib.sha256(f"{challenge}:{value['observer_key_id']}".encode()).hexdigest()
        ):
            raise ValueError
        public_key = Ed25519PublicKey.from_public_bytes(public_raw)
        public_key.verify(signature, _canonical_bytes(unsigned))
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise LabError("Effect observer returned unauthenticated readiness evidence") from exc
    return _ObserverVerifier(
        value["observer_identity"], value["observer_key_id"], value["observer_session_id"], public_key
    )


def _verify_observer_event(event: Any, verifier: _ObserverVerifier, sequence: int) -> None:
    try:
        if not isinstance(event, dict) or set(event) != LEDGER_FIELDS:
            raise ValueError
        unsigned = dict(event)
        signature = base64.b64decode(unsigned.pop("observer_signature"), validate=True)
        if (
            event["observer_identity"] != verifier.identity
            or event["observer_key_id"] != verifier.key_id
            or event["observer_session_id"] != verifier.session_id
            or event["observer_sequence"] != sequence
            or event["signature_algorithm"] != "ed25519"
        ):
            raise ValueError
        verifier.public_key.verify(signature, _canonical_bytes(unsigned))
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise LabError("Effect observer ledger returned unauthenticated evidence") from exc


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
    """Account observed bytes and reserve time for fixed child cleanups."""

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
        if len(raw) > self.output_limit - self.output_bytes:
            self.stop("output_budget_exhausted")
        self.output_bytes += len(raw)

    def remaining_bytes(self) -> int:
        self.admit()
        return self.output_limit - self.output_bytes

    def account_ledger(self, ledger: Path, raw: bytes) -> None:
        previous = self.ledgers.get(ledger, b"")
        if not raw.startswith(previous):
            raise LabError("Effect observer ledger changed previously observed bytes")
        self.account_response(raw[len(previous) :])
        self.ledgers[ledger] = raw

    def report(self) -> dict[str, Any]:
        return {
            "max_duration_seconds": self.duration_limit,
            "cleanup_reserve_seconds": self.cleanup_reserve,
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "max_observed_fixture_bytes": self.output_limit,
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


@contextmanager
def _defer_cancellation(interrupted: list[bool]):
    """Keep process registration and cleanup atomic against SIGINT and SIGTERM."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def defer(_signum, _frame):
        interrupted[0] = True

    try:
        for number in previous:
            signal.signal(number, defer)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


@contextmanager
def _private_directory(prefix: str, interrupted: list[bool]):
    directory = None
    try:
        with _defer_cancellation(interrupted):
            directory = tempfile.TemporaryDirectory(prefix=prefix)
        if interrupted[0]:
            raise KeyboardInterrupt
        yield Path(directory.name)
    finally:
        if directory is not None:
            with _defer_cancellation(interrupted):
                # Staged source directories are read-only during execution.
                os.chmod(directory.name, 0o700)
                try:
                    directory.cleanup()
                except KeyboardInterrupt:
                    interrupted[0] = True
                    directory.cleanup()


def _attempt_ids(case: AuthCase, index: int) -> dict[str, str]:
    prefix = f"{case.case_id}-{index}"
    return {
        "attempt_id": prefix,
        "request_id": f"request-{prefix}",
        "canary_id": f"canary-{prefix}",
    }


def build_auth_plan(
    cases: Iterable[AuthCase | dict[str, Any]],
    *,
    plan_id: str,
    engagement_id: str,
    created_at: str,
    _sources: dict[str, bytes] | None = None,
) -> ActionPlan:
    """Compile the exact fixed batch with the trusted data-only planner."""
    return _build_trusted_auth_plan(
        [case.to_dict() for case in _coerce_cases(cases)],
        plan_id=plan_id,
        engagement_id=engagement_id,
        created_at=created_at,
        source_root=Path(__file__).resolve().parent,
        _sources=_sources,
    )


def _read_effects(ledger: Path, budget: _BatchBudget, verifier: _ObserverVerifier) -> list[dict[str, Any]]:
    budget.admit()
    try:
        descriptor = os.open(ledger, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
                raise LabError("Effect observer ledger is unavailable or oversized")
            previous = budget.ledgers.get(ledger, b"")
            remaining = budget.remaining_bytes()
            if metadata.st_size - len(previous) > remaining:
                budget.stop("output_budget_exhausted")
            raw = stream.read(min(65537, len(previous) + remaining))
            if stream.read(1):
                budget.stop("output_budget_exhausted")
        if len(raw) > 65536 or (raw and not raw.endswith(b"\n")):
            raise LabError("Effect observer ledger is unavailable or oversized")
        budget.account_ledger(ledger, raw)
        events = [decode_json(line, max_bytes=65536) for line in raw.splitlines()]
    except (OSError, EvidenceError) as exc:
        raise LabError("Effect observer ledger returned malformed evidence") from exc
    for sequence, event in enumerate(events, start=1):
        _verify_observer_event(event, verifier, sequence)
        if (
            not isinstance(event, dict)
            or set(event) != LEDGER_FIELDS
            or event["schema_version"] != "cops.agent-mcp-auth-ledger-event/v1"
            or event["server_identity"] != SERVER_IDENTITY
            or event["test_identity"] != TEST_IDENTITY
            or not isinstance(event["operation"], str)
            or event["operation"] not in {"read", "write"}
            or event["kind"] != "canary_" + event["operation"]
            or event["tool"] != "canary/" + event["operation"]
            or any(
                not isinstance(event[key], str) or event[key] not in ARGUMENT_ALIASES[key]
                for key in ("principal", "tenant", "resource")
            )
            or not isinstance(event["case_id"], str)
            or not 1 <= len(event["case_id"]) <= 64
            or re.fullmatch(ID_PATTERN, event["case_id"]) is None
            or any(
                not isinstance(event[key], str)
                or not 1 <= len(event[key]) <= 128
                or re.fullmatch(ID_PATTERN, event[key]) is None
                for key in ("attempt_id", "request_id", "canary_id")
            )
            or not isinstance(event["plan_digest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", event["plan_digest"]) is None
            or event["redacted"] is not True
        ):
            raise LabError("Effect observer ledger returned malformed evidence")
    return events


def _request(case: AuthCase, attempt: dict[str, Any], index: int, plan_digest: str) -> dict[str, Any]:
    request = {
        "case_id": case.case_id,
        "grant": case.grant,
        "flow": case.flow,
        **{key: value for key, value in attempt.items() if key not in {"tool", "peer_action", "fault_mode"}},
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
        or not isinstance(value["case_id"], str)
        or not 1 <= len(value["case_id"]) <= 64
        or re.fullmatch(ID_PATTERN, value["case_id"]) is None
        or any(
            not isinstance(value[key], str)
            or not 1 <= len(value[key]) <= 128
            or re.fullmatch(ID_PATTERN, value[key]) is None
            for key in ("attempt_id", "request_id", "canary_id")
        )
        or not isinstance(value["plan_digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["plan_digest"]) is None
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
        key for key in set(original) | set(forwarded) if original.get(key, object()) != forwarded.get(key, object())
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
        "evidence_complete": False,
        "security_pass": False,
        "observations": [],
        "normalized_observations": [],
        "observed_effects": [],
        "cleanup": {
            "process_exit_observed": None,
            "private_directory_removed": None,
        },
        "redacted": True,
        "expectation_met": False,
        "revocation_window": None,
    }


def _run_auth_case(
    case: AuthCase, plan_digest: str, budget: _BatchBudget, source_root: Path
) -> tuple[dict[str, Any], bool, bool]:
    if case.surface != "local_synthetic_fixture":
        return _unsupported_result(case, plan_digest), False, False

    observations: list[dict[str, Any]] = []
    normalized_observations: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    failure: str | None = None
    cancelled = False
    environment_verified = False
    process_exit_observed = False
    workdir_path: Path | None = None
    interrupted = [False]
    dispatched: tuple[dict[str, Any], str] | None = None
    uncertain_execution = False

    try:
        with _private_directory("cops-auth-lab-", interrupted) as workdir_path:
            workdir = str(workdir_path)
            ledger = workdir_path / "effects.jsonl"
            ledger.touch(mode=0o600, exist_ok=False)
            observer: _JsonLineProcess | None = None
            server: _JsonLineProcess | None = None
            peer: _JsonLineProcess | None = None
            closed: list[bool] = []
            spawned: list[_JsonLineProcess] = []
            try:

                def start(script: str) -> _JsonLineProcess:
                    with _defer_cancellation(interrupted):
                        process = _JsonLineProcess(
                            script,
                            workdir,
                            response_timeout_seconds=1,
                            admission_check=budget.admit,
                            response_timeout_provider=budget.response_timeout,
                            account_response=budget.account_response,
                            response_bytes_remaining=budget.remaining_bytes,
                            source_root=source_root,
                            on_spawn=spawned.append,
                        )
                    if interrupted[0]:
                        raise KeyboardInterrupt
                    return process

                observer = start("auth_effect_observer.py")
                observer_challenge = secrets.token_hex(32)
                ready = observer.exchange({"command": "ready", "observer_challenge": observer_challenge})
                verifier = _verify_observer_ready(ready, observer_challenge)
                server = start("auth_fixture_server.py")
                peer = start("auth_peer_fixture.py")
                mcp = _McpClient(
                    server,
                    expected_tools=frozenset(TOOLS),
                    expected_server_info=SERVER_INFO,
                    expected_capabilities={"tools": {}},
                    expected_input_schemas=TOOL_INPUT_SCHEMAS,
                    expected_tool_descriptors=TOOL_DESCRIPTORS,
                )
                mcp.initialize()
                events = _read_effects(ledger, budget, verifier)
                environment_verified = True

                def observe_effects(
                    forwarded: dict[str, Any], tool: str
                ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
                    observed = _read_effects(ledger, budget, verifier)
                    if observed[: len(events)] != events:
                        raise LabError("Effect observer ledger changed previously observed events")
                    delta = observed[len(events) :]
                    for event in delta:
                        if (
                            any(
                                event[key] != forwarded[key]
                                for key in (
                                    "case_id",
                                    "attempt_id",
                                    "request_id",
                                    "canary_id",
                                    "plan_digest",
                                    "test_identity",
                                    "tenant",
                                    "resource",
                                    "principal",
                                    "operation",
                                )
                            )
                            or event["tool"] != tool
                        ):
                            raise LabError("Effect observer ledger correlation mismatch")
                    return observed, delta

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

                    def mark_dispatch_attempt(
                        forwarded_request: dict[str, Any] = forwarded,
                        tool_name: str = attempt["tool"],
                    ) -> None:
                        nonlocal dispatched
                        dispatched = (forwarded_request, tool_name)

                    decision = mcp.call(attempt["tool"], forwarded, on_dispatch_attempt=mark_dispatch_attempt)
                    identity_present = _validate_decision(decision, forwarded)
                    observed, delta = observe_effects(forwarded, attempt["tool"])
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
                    normalized_observations.append(
                        {
                            "schema_version": "cops.agent-mcp-auth-normalized-observation/v1",
                            "correlation": {
                                "plan_digest": plan_digest,
                                "case_id": case.case_id,
                                **ids,
                                "test_identity": TEST_IDENTITY,
                            },
                            "request": {
                                "principal": forwarded["principal"],
                                "agent": forwarded["agent"],
                                "peer": peer_observation["peer_identity"],
                                "tenant": forwarded.get("tenant"),
                                "resource": forwarded["resource"],
                                "operation": forwarded["operation"],
                                "audience": forwarded["audience"],
                                "downstream_service": forwarded["downstream_service"],
                                "tool": attempt["tool"],
                                "requested_scopes": forwarded["scopes"],
                                "delegation_depth": forwarded["depth"],
                                "authorization_alias": forwarded["grant"],
                            },
                            "target_authority": {
                                "server_identity": decision.get("server_identity"),
                                "decision": decision["decision"],
                                "phase": decision["phase"],
                                "reason": decision["reason"],
                            },
                            "effect": {
                                "status": "observed" if delta else "absent",
                                "kinds": [event["kind"] for event in delta],
                                "count": len(delta),
                                "observer_identity": ready["observer_identity"],
                                "observer_key_id": verifier.key_id,
                                "observer_session_id": verifier.session_id,
                                "record_authentication": "ed25519_observer_process",
                                "signing_authority": "observer_process_private_key",
                                "observation_channel": "separate_process_private_ledger",
                                "trust_relation": "separate_process_same_trust_boundary",
                            },
                            "redacted": observations[-1]["redacted"],
                        }
                    )
                    events = observed
                    dispatched = None
                    if not identity_present:
                        failure = "missing_identity_telemetry"
                        break
                    if decision["decision"] == expected_decision == "allowed" and not delta:
                        failure = "positive_effect_not_observed"
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
                with _defer_cancellation(interrupted):
                    for process in reversed(spawned):
                        try:
                            closed.append(process.close())
                        except KeyboardInterrupt:
                            interrupted[0] = True
                            try:
                                closed.append(process.close())
                            except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
                                closed.append(False)
                        except (OSError, ValueError, subprocess.SubprocessError):
                            closed.append(False)
                process_exit_observed = bool(spawned) and len(closed) == len(spawned) and all(closed)
                if dispatched is not None:
                    uncertain_execution = True
                    try:
                        # The tool may have committed an effect before its response
                        # disappeared. Retain only correlated observer-ledger events.
                        observed, _ = observe_effects(*dispatched)
                        events = observed
                    except (_BatchBudgetStop, LabError, OSError, ValueError, TypeError):
                        pass
    except KeyboardInterrupt:
        interrupted[0] = True
    except (OSError, ValueError):
        failure = failure or "private_directory_setup_or_cleanup_failure"

    if interrupted[0]:
        cancelled = True
        failure = "cancelled"

    private_directory_removed = workdir_path is not None and not workdir_path.exists()
    if not process_exit_observed:
        failure = failure or "process_exit_not_observed"
    if not private_directory_removed:
        failure = failure or "private_directory_removal_not_observed"

    expected_deltas = [
        1 if decision == "allowed" else 0
        for attempt, decision in zip(case.attempts, case.expected_decisions, strict=True)
    ]
    evidence_complete = (
        failure is None
        and environment_verified
        and process_exit_observed
        and private_directory_removed
        and len(observations) == len(case.attempts)
        and len(normalized_observations) == len(case.attempts)
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
    outcome = (
        "inconclusive"
        if missing_context
        else "pass"
        if expectations_match
        else "fail"
        if evidence_complete
        else "inconclusive"
    )
    revocation_window = None
    revoked_at = GRANTS[case.grant].get("revoked_at")
    if revoked_at is not None:
        ticks = [row["peer"]["forwarded_request"]["tick"] for row in observations]
        denied_ticks = [
            row["peer"]["forwarded_request"]["tick"]
            for row in observations
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
                and row["observed_effect_count"] == 1
                for row in observations
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
        "reason": failure
        or (
            "missing_context"
            if missing_context
            else "expectations_met"
            if expectations_match
            else "expectation_mismatch"
        ),
        "environment_verified": environment_verified,
        "evidence_complete": evidence_complete,
        "security_pass": outcome == "pass" and expectations_match,
        "observations": observations,
        "normalized_observations": normalized_observations,
        "observed_effects": events,
        "cleanup": {
            "process_exit_observed": process_exit_observed,
            "private_directory_removed": private_directory_removed,
        },
        "redacted": all(row.get("redacted") is True for row in observations)
        and all(event.get("redacted") is True for event in events),
        "expectation_met": outcome == case.expected_outcome and expectations_match,
        "revocation_window": revocation_window,
    }
    return result, cancelled, uncertain_execution


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
    """Compatibility entry point; admission loads a fresh approved controller."""
    from .auth_bootstrap import run_auth_cases as admit_and_run

    try:
        return admit_and_run(
            [case.to_dict() if isinstance(case, AuthCase) else case for case in cases],
            plan=plan,
            authorization=authorization,
            engagement=engagement,
            trust_store=trust_store,
            worker_identity=worker_identity,
            approval_store=approval_store,
            source_root=Path(__file__).resolve().parent,
        )
    except ApprovalStoreConflictError:
        raise
    except ValueError as exc:
        raise LabError(str(exc)) from exc


def _run_bound_batch(normalized, supplied_plan, consumed, worker_identity, source_root):
    """Execute only after the trusted bootstrap binds and consumes approval."""
    budget = _BatchBudget(supplied_plan, consumed.authorized_until_utc)
    results = []
    cancelled = False
    interrupted_case = None
    execution_failure = None
    try:
        for case in normalized:
            try:
                budget.admit()
            except _BatchBudgetStop:
                break
            try:
                result, case_cancelled, uncertain_execution = _run_auth_case(
                    case,
                    supplied_plan.plan_digest,
                    budget,
                    source_root,
                )
            except (Exception, SystemExit):
                # A request may have reached the fixture before its result was
                # returned. Keep earlier observations and stop without retrying
                # or exposing exception payloads from untrusted runtime code.
                execution_failure = {
                    "case_id": case.case_id,
                    "reason": "case_execution_failed",
                    "effect_status": "uncertain",
                }
                break
            results.append(result)
            if uncertain_execution:
                execution_failure = {
                    "case_id": case.case_id,
                    "reason": "case_execution_failed",
                    "effect_status": "uncertain",
                }
            if case_cancelled or budget.stop_reason is not None or uncertain_execution:
                cancelled = case_cancelled
                interrupted_case = case.case_id
                break
    except KeyboardInterrupt:
        cancelled = True
    pending = [case.case_id for case in normalized[len(results) :]]
    if interrupted_case is not None:
        pending.insert(0, interrupted_case)
    all_expectations_met = (
        not cancelled
        and execution_failure is None
        and budget.stop_reason is None
        and len(results) == len(normalized)
        and all(result["expectation_met"] for result in results)
    )
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
        "execution_failure": execution_failure,
        "pending_case_ids": pending,
        "next_action": (
            "reconcile_uncertain_execution_effects_before_new_approval"
            if execution_failure
            else "approve_a_new_plan_for_pending_cases"
            if pending
            else None
        ),
        "planned_case_count": len(normalized),
        "completed_case_count": len(results) - int(interrupted_case is not None),
        "all_expectations_met": all_expectations_met,
        "security_pass": all_expectations_met and all(result["security_pass"] for result in results),
        "results": results,
        "redacted": all(result["redacted"] is True for result in results),
    }
