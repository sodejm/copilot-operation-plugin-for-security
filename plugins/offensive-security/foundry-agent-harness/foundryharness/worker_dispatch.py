"""Fixed supervisor dispatcher for approved, network-free canary laboratories.

Approval and one-shot consumption belong to the supervisor mediator. This module
binds that approval to package-owned case and executable snapshots and projects
the private laboratory report into bounded, content-free evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from time import monotonic
from types import MappingProxyType
from typing import Any

from cops.evidence.canonical import canonical, digest
from cops.laboratory.agent_mcp_worker import AgentMcpEnvelope, AgentMcpError

from . import laboratory as lab

DISPATCHER_ID = "cops-agent-mcp-disposable-lab-v1"
OBSERVATION_VERSION = "cops.agent-mcp-lab-observation/v1"
_ROOT = Path(__file__).resolve().parent
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_STOP_REASONS = frozenset(
    {
        "cancelled",
        "deadline_exhausted",
        "response_budget_exhausted",
        "cancellation_check_failed",
        "cleanup_deadline_exhausted",
    }
)
_RUNTIME_FILES = ("worker_dispatch.py", "laboratory.py", "bounded_json.py", "fixture_agent.py", "mcp_fixture_server.py")


def _runtime_snapshot() -> dict[str, str]:
    # These names are constant and cannot be influenced by an envelope.
    return {name: hashlib.sha256((_ROOT / name).read_bytes()).hexdigest() for name in _RUNTIME_FILES}


_RUNTIME = MappingProxyType(_runtime_snapshot())
_RUNTIME_DIGEST = digest(dict(_RUNTIME))


def _case_bytes(case: lab.LabCase) -> bytes:
    if not isinstance(case, lab.LabCase):
        raise AgentMcpError("invalid fixed laboratory case")
    data = asdict(case)
    data["tool_permissions"] = list(case.tool_permissions)
    data["schema_version"] = "cops.agent-mcp-lab-case/v1"
    # Revalidate a detached snapshot: LabCase's frozen dataclass contains a dict.
    encoded = canonical(data, max_bytes=16384)
    lab.LabCase.from_dict(json.loads(encoded))
    return encoded


_CASES = MappingProxyType({case.case_id: _case_bytes(case) for case in lab.load_lab_cases(_ROOT.parent / "lab_cases")})


def registered_lab_case(case_id: str) -> lab.LabCase:
    """Return a detached case from the fixed, immutable in-package registry."""
    if type(case_id) is not str or case_id not in _CASES:
        raise AgentMcpError("unknown fixed laboratory case")
    return lab.LabCase.from_dict(json.loads(_CASES[case_id]))


def lab_case_bindings(case: lab.LabCase) -> dict[str, str]:
    """Derive approval bindings from validated case data and pinned runtime code."""
    encoded = _case_bytes(case)
    document = json.loads(encoded)
    case_digest = hashlib.sha256(encoded).hexdigest()
    scenario_id = "scen-agent-mcp-lab-" + case.case_id
    if not re.fullmatch(r"scen-[a-z0-9_-]{4,64}", scenario_id):
        raise AgentMcpError("invalid fixed laboratory scenario identifier")
    scenario = {
        "schema_version": "cops.agent-mcp-lab-scenario-binding/v1",
        "dispatcher_id": DISPATCHER_ID,
        "scenario_id": scenario_id,
        "case_digest": case_digest,
        "runtime_digest": _RUNTIME_DIGEST,
    }
    request = {
        "schema_version": "cops.agent-mcp-lab-request-binding/v1",
        "scenario_digest": digest(scenario),
        "principal_tenant": document["principal_tenant"],
        "approved_call": document["approved_call"],
        "untrusted_text": document["untrusted_text"],
        "tool_permissions": document["tool_permissions"],
        "control_profile": document["control_profile"],
    }
    return {
        "dispatcher_id": DISPATCHER_ID,
        "scenario_id": scenario_id,
        "tenant_id": case.principal_tenant,
        "case_digest": case_digest,
        "request_digest": digest(request),
        "scenario_digest": digest(scenario),
        "runtime_digest": _RUNTIME_DIGEST,
    }


def _context(value: Any, envelope: AgentMcpEnvelope) -> dict[str, str]:
    fields = {"plan_digest", "approval_digest", "envelope_digest"}
    if not isinstance(value, MappingProxyType) or set(value) != fields:
        raise AgentMcpError("immutable supervisor dispatch context is required")
    result = dict(value)
    if any(type(item) is not str or not _SHA.fullmatch(item) for item in result.values()):
        raise AgentMcpError("invalid supervisor dispatch binding")
    if result["envelope_digest"] != envelope.digest:
        raise AgentMcpError("supervisor envelope binding mismatch")
    return result


def _cleanup(exc: Exception) -> dict[str, Any]:
    raw = getattr(exc, "cleanup_evidence", {})
    if not isinstance(raw, dict):
        raw = {}
    result = {
        key: raw.get(key) is True
        for key in ("reset_attempted", "reset_verified", "processes_terminated", "temporary_directory_removed")
    }
    result["verified"] = bool(
        result["processes_terminated"]
        and result["temporary_directory_removed"]
        and (not result["reset_attempted"] or result["reset_verified"])
    )
    received = raw.get("response_bytes")
    result["response_bytes"] = received if type(received) is int and 0 <= received <= 1048576 else None
    return result


def _observations(case: lab.LabCase, report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if (
        report.get("schema_version") != "cops.agent-mcp-lab-report/v1"
        or report.get("case_id") != case.case_id
        or report.get("environment_verified") is not True
        or report.get("cleanup_verified") is not True
        or report.get("agent_origin") != lab.AGENT_ORIGIN
        or report.get("mcp_transport") != "local-stdio"
        or report.get("mcp_protocol_version") != lab.PROTOCOL_VERSION
    ):
        raise AgentMcpError("unverified laboratory observation")
    attempted, denied, executed = (report.get(key) for key in ("attempted_calls", "denied_calls", "executed_calls"))
    if (
        type(attempted) is not list
        or len(attempted) != 1
        or type(attempted[0]) is not dict
        or set(attempted[0]) != {"name", "arguments", "origin"}
        or attempted[0]["origin"] not in ("trusted_task", "untrusted_content")
        or type(denied) is not list
        or type(executed) is not list
    ):
        raise AgentMcpError("invalid laboratory call observations")
    proposal = {key: attempted[0][key] for key in ("name", "arguments")}
    denial = lab._authorize(case, proposal)
    expected_denied = [{**proposal, "reason": denial}] if denial else []
    seed = (
        [
            {
                "name": "lookup_account",
                "arguments": {"tenant_id": "tenant-contoso-01", "account_id": "acct-001"},
                "origin": "trusted_seed_read",
            }
        ]
        if case.attack_surface == "tool_response"
        else []
    )
    expected_executed = seed if denial else [*seed, attempted[0]]
    if denied != expected_denied or executed != expected_executed:
        raise AgentMcpError("laboratory call observation mismatch")
    before, after = report.get("state_before"), report.get("state_after")
    if type(before) is not dict or type(after) is not dict:
        raise AgentMcpError("missing independent laboratory state observation")
    effects = lab._observed_effects(before, after)
    if effects != report.get("executed_effects") or (denied and effects):
        raise AgentMcpError("laboratory effect observation mismatch")
    outcome = "denied" if denied else "executed_effect" if effects else "executed_no_effect"
    observations: dict[str, Any] = {}
    for name, items in (("attempted", attempted), ("denied", denied), ("executed", executed), ("effects", effects)):
        observations[name + "_count"] = len(items)
        observations[name + "_digest"] = digest(items, max_bytes=16384)
    observations["before_state_digest"] = digest(before, max_bytes=16384)
    observations["after_state_digest"] = digest(after, max_bytes=16384)
    return outcome, observations


def dispatch_lab_case(
    envelope: AgentMcpEnvelope | Mapping[str, Any],
    *,
    deadline: float,
    cancellation_event: threading.Event,
    dispatch_context: Mapping[str, str],
) -> dict[str, Any]:
    """Execute only the exact package case bound by an approved supervisor call.

    Results contain no model text, arguments, canary values, or raw state. Failed
    runs preserve cleanup evidence and leave observations unknown. The mediator
    remains responsible for approval verification and capability consumption.
    """
    approved = AgentMcpEnvelope.from_dict(envelope.to_dict() if isinstance(envelope, AgentMcpEnvelope) else envelope)
    context = _context(dispatch_context, approved)
    document = approved.to_dict()
    case = registered_lab_case(document["case_id"])
    bindings = lab_case_bindings(case)
    if any(
        document[key] != bindings[key]
        for key in ("dispatcher_id", "scenario_id", "tenant_id", "request_digest", "scenario_digest")
    ):
        raise AgentMcpError("fixed laboratory approval binding mismatch")
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise AgentMcpError("invalid laboratory dispatcher deadline")
    if not isinstance(cancellation_event, threading.Event):
        raise AgentMcpError("supervisor cancellation event is required")
    if _runtime_snapshot() != dict(_RUNTIME):
        raise AgentMcpError("fixed laboratory runtime changed")
    limits = document["limits"]
    expires = min(deadline, monotonic() + limits["max_duration_seconds"])
    result: dict[str, Any] = {
        "schema_version": OBSERVATION_VERSION,
        "case_id": case.case_id,
        "scenario_id": bindings["scenario_id"],
        "tenant_id": bindings["tenant_id"],
        "dispatcher_id": DISPATCHER_ID,
        "bindings": {**context, **{key: value for key, value in bindings.items() if key.endswith("_digest")}},
        "status": "failed",
        "outcome": "laboratory_failed",
        "observations": None,
        "cleanup": {"verified": False},
    }
    try:
        report = lab.run_lab_case(
            case,
            cancellation_check=cancellation_event.is_set,
            deadline_monotonic=expires,
            max_response_bytes=min(1048576, limits["max_output_bytes"]),
        )
        result["cleanup"] = {"verified": report.get("cleanup_verified") is True}
        outcome, observations = _observations(case, report)
        result.update(status="completed", outcome=outcome, observations=observations)
    except Exception as exc:
        if result["cleanup"] == {"verified": False}:
            result["cleanup"] = _cleanup(exc)
        raw = getattr(exc, "cleanup_evidence", {})
        reason = raw.get("stop_reason") if isinstance(raw, dict) else None
        result["outcome"] = reason if type(reason) is str and reason in _STOP_REASONS else "laboratory_failed"
    if result["status"] == "completed":
        stopped = (
            "cancelled" if cancellation_event.is_set() else "deadline_exhausted" if monotonic() >= expires else None
        )
        if stopped:
            result.update(status="failed", outcome=stopped, observations=None)
    # The same approved cap bounds both private stdio responses and projected JSON.
    # Very small caps cannot represent even a failure receipt, so fail closed.
    try:
        canonical(result, max_bytes=limits["max_output_bytes"])
    except ValueError:
        error = AgentMcpError("laboratory observation exceeds approved output budget")
        error.cleanup_evidence = result["cleanup"]
        raise error from None
    return result


dispatcher = dispatch_lab_case
