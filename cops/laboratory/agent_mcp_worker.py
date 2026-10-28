"""Supervisor-owned, data-only contract for one agent/MCP laboratory dispatch.

This capability selects no command, transport, credential, or destination. The
supervisor supplies the trusted dispatcher; approved content identifies its
immutable inputs by digest. This module grants no execution authorization.
"""

from __future__ import annotations

import json
import math
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from time import monotonic
from types import MappingProxyType
from typing import Any

from cops.evidence.canonical import canonical, digest

AGENT_MCP_TOOL = "cops.agent-mcp.laboratory-worker"
AGENT_MCP_VERSION = "1"
ENVELOPE_VERSION = "cops.agent-mcp-laboratory-envelope/v1"
RESULT_VERSION = "cops.agent-mcp-laboratory-result/v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_FIELDS = frozenset(
    {"engagement_id", "scenario_id", "session_id", "role_id", "tenant_id", "case_id", "dispatcher_id"}
)
_ENVELOPE_FIELDS = _IDENTITY_FIELDS | {"schema_version", "request_digest", "scenario_digest", "limits"}


class AgentMcpError(ValueError):
    """A laboratory capability, binding, budget, or result is invalid."""


def _closed(value: Any, fields: set[str] | frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AgentMcpError(f"invalid {label} fields")
    return value


def _sha(value: Any) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise AgentMcpError("invalid binding digest")
    return value


def _snapshot(value: Any, *, max_bytes: int) -> bytes:
    # Plans use frozen mappings and tuples. Bound conversion before allocating
    # untrusted output, and preserve canonical JSON's strict scalar checks.
    nodes = 0
    characters = 0

    def owned(item: Any, depth: int = 0) -> Any:
        nonlocal nodes, characters
        nodes += 1
        if depth > 16 or nodes > 100000:
            raise AgentMcpError("laboratory JSON structure limit exceeded")
        if isinstance(item, Mapping):
            if len(item) > 100000:
                raise AgentMcpError("laboratory JSON structure limit exceeded")
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise AgentMcpError("laboratory JSON keys must be strings")
                characters += len(key)
                result[key] = owned(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            if len(item) > 100000:
                raise AgentMcpError("laboratory JSON structure limit exceeded")
            return [owned(child, depth + 1) for child in item]
        if type(item) is str:
            characters += len(item)
        if characters > max_bytes:
            raise AgentMcpError("laboratory JSON byte limit exceeded")
        return item

    try:
        return canonical(owned(value), max_bytes=max_bytes, max_depth=16)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise AgentMcpError("laboratory value must be bounded finite JSON") from None


def _completed_dispatch_receipt(value: Any, *, max_bytes: int) -> tuple[dict[str, Any], bytes]:
    """Accept only a bounded dispatcher receipt that proves safe completion."""
    encoded = _snapshot(value, max_bytes=max_bytes)
    receipt = json.loads(encoded)
    cleanup = receipt.get("cleanup") if isinstance(receipt, dict) else None
    if (
        not isinstance(receipt, dict)
        or receipt.get("status") != "completed"
        or not isinstance(cleanup, dict)
        or cleanup.get("verified") is not True
    ):
        raise AgentMcpError("laboratory dispatcher did not confirm completion and cleanup")
    return receipt, encoded


@dataclass(frozen=True, init=False)
class AgentMcpEnvelope:
    """Validated immutable capability; every export is a detached snapshot."""

    _canonical_json: bytes

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AgentMcpEnvelope:
        encoded = _snapshot(value, max_bytes=16384)
        document = json.loads(encoded)
        _closed(document, _ENVELOPE_FIELDS, "laboratory envelope")
        if document["schema_version"] != ENVELOPE_VERSION:
            raise AgentMcpError("unsupported laboratory envelope version")
        for field in _IDENTITY_FIELDS:
            item = document[field]
            if type(item) is not str or not _IDENTIFIER.fullmatch(item):
                raise AgentMcpError("invalid laboratory identifier")
        _sha(document["request_digest"])
        _sha(document["scenario_digest"])
        limits = _closed(document["limits"], {"max_duration_seconds", "max_output_bytes"}, "laboratory limits")
        for field, maximum in (("max_duration_seconds", 300), ("max_output_bytes", 2097152)):
            if type(limits[field]) is not int or not 1 <= limits[field] <= maximum:
                raise AgentMcpError("invalid laboratory limit")
        result = object.__new__(cls)
        object.__setattr__(result, "_canonical_json", encoded)
        return result

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical_json)

    @property
    def digest(self) -> str:
        return digest(self.to_dict(), max_bytes=16384)


def validate_agent_mcp_operation(operation: Mapping[str, Any]) -> AgentMcpEnvelope:
    """Validate the typed operation; the compiler remains authorization authority."""
    if not isinstance(operation, Mapping) or (
        operation.get("tool") != AGENT_MCP_TOOL
        or operation.get("tool_version") != AGENT_MCP_VERSION
        or operation.get("action") != "run"
        or operation.get("idempotent") is not False
    ):
        raise AgentMcpError("invalid laboratory operation")
    arguments = _closed(operation.get("arguments"), {"envelope"}, "laboratory arguments")
    if operation.get("egress_policy", {}) != {}:
        raise AgentMcpError("laboratory operation cannot select egress")
    return AgentMcpEnvelope.from_dict(arguments["envelope"])


class AgentMcpMediator:
    """Consume one exactly approved envelope through a supervisor dispatcher.

    The dispatcher must cooperate with cancellation. Broker process teardown
    supplies the hard boundary for dispatchers that fail to return promptly.
    """

    def __init__(
        self,
        *,
        envelope: AgentMcpEnvelope,
        plan_digest: str,
        approval_digest: str,
        dispatcher: Callable[..., Any],
    ) -> None:
        self._envelope = AgentMcpEnvelope.from_dict(envelope.to_dict())
        self._plan_digest = _sha(plan_digest)
        self._approval_digest = _sha(approval_digest)
        if not callable(dispatcher):
            raise AgentMcpError("trusted laboratory dispatcher is required")
        self._dispatcher = dispatcher
        self._consumed = False
        self._lock = threading.Lock()

    @property
    def envelope(self) -> AgentMcpEnvelope:
        return self._envelope

    @property
    def plan_digest(self) -> str:
        return self._plan_digest

    @property
    def approval_digest(self) -> str:
        return self._approval_digest

    def dispatch(
        self,
        value: Mapping[str, Any],
        *,
        plan_digest: str,
        approval_digest: str,
        cancellation_event: Any = None,
        deadline: float | None = None,
        dispatch_observer: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        candidate = AgentMcpEnvelope.from_dict(value)
        if (
            _sha(plan_digest) != self.plan_digest
            or _sha(approval_digest) != self.approval_digest
            or candidate.digest != self.envelope.digest
        ):
            raise AgentMcpError("laboratory approval binding mismatch")
        if deadline is not None and (
            isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)
        ):
            raise AgentMcpError("invalid laboratory deadline")
        limits = self.envelope.to_dict()["limits"]
        expires = min(monotonic() + limits["max_duration_seconds"], deadline if deadline is not None else math.inf)
        with self._lock:
            if self._consumed:
                raise AgentMcpError("laboratory capability is already consumed")
            self._consumed = True
        cancelled = threading.Event()
        done = threading.Event()
        outcome: list[Any] = []

        def check() -> None:
            if cancellation_event is not None and cancellation_event.is_set():
                cancelled.set()
                raise AgentMcpError("laboratory dispatch cancelled")
            if monotonic() >= expires:
                cancelled.set()
                raise AgentMcpError("laboratory dispatch deadline exceeded")

        def run() -> None:
            try:
                check()
                if dispatch_observer is not None:
                    dispatch_observer()
                raw = self._dispatcher(
                    self.envelope.to_dict(),
                    deadline=expires,
                    cancellation_event=cancelled,
                    dispatch_context=MappingProxyType(
                        {
                            "plan_digest": self.plan_digest,
                            "approval_digest": self.approval_digest,
                            "envelope_digest": self.envelope.digest,
                        }
                    ),
                )
                receipt, encoded = _completed_dispatch_receipt(raw, max_bytes=limits["max_output_bytes"])
                outcome.append(
                    {
                        "schema_version": RESULT_VERSION,
                        "status": "completed",
                        "envelope_digest": self.envelope.digest,
                        "plan_digest": self.plan_digest,
                        "approval_digest": self.approval_digest,
                        "result_digest": digest(receipt, max_bytes=limits["max_output_bytes"]),
                        "result_bytes": len(encoded),
                    }
                )
            except BaseException:
                # Dispatcher exceptions can contain hostile content or secrets.
                outcome.append(None)
            finally:
                done.set()

        check()
        thread = threading.Thread(target=run, name="cops-agent-mcp-dispatch", daemon=True)
        thread.start()
        try:
            while not done.wait(min(0.02, max(0.001, expires - monotonic()))):
                check()
            check()
            if not outcome or outcome[0] is None:
                raise AgentMcpError("laboratory dispatcher failed or exceeded output budget")
            return outcome[0]
        finally:
            cancelled.set()
