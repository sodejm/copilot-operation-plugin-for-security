"""Run fixed, offline MCP authorization cases with observer-ledger effects."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auth_fixture_server import (
    ARGUMENT_ALIASES,
    FAULT_MODES,
    GRANTS,
    PEER_ACTIONS,
    SCOPES,
    TOOLS,
)
from .bounded_json import JSONInputError, decode_json, read_regular_file
from .laboratory import LabError

CASE_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "case_id",
        "title",
        "grant",
        "flow",
        "attempts",
        "expected_decisions",
        "expected_reasons",
        "expected_effect_count",
    }
)
CASE_OPTIONAL_FIELDS = frozenset({"surface", "expected_outcome"})
ATTEMPT_REQUIRED_FIELDS = frozenset(
    {
        "principal",
        "agent",
        "downstream_service",
        "audience",
        "resource",
        "operation",
        "scopes",
        "depth",
        "tick",
        "tool",
    }
)
ATTEMPT_OPTIONAL_FIELDS = frozenset({"tenant", "peer_action", "fault_mode"})
DECISIONS = {"allowed", "denied", "inconclusive"}
PHASES = {"setup", "authentication", "authorization"}
AUTHENTICATION_REASONS = {"unrecognized_grant_or_actor", "expired_grant", "revoked_grant", "one_time_replay"}
REASONS = {
    "allowed",
    "missing_context",
    "unrecognized_grant_or_actor",
    "expired_grant",
    "revoked_grant",
    "one_time_replay",
    "flow_mismatch",
    "principal_or_agent_binding",
    "downstream_service_mismatch",
    "audience_mismatch",
    "tenant_mismatch",
    "missing_tenant",
    "resource_mismatch",
    "delegation_depth_exceeded",
    "tool_not_permitted",
    "operation_mismatch",
    "scope_mismatch",
}
SURFACES = {"local_synthetic_fixture", "unsupported_provider_surface"}
OUTCOMES = {"pass", "fail", "inconclusive", "unsupported"}


@dataclass(frozen=True)
class AuthCase:
    surface: str
    case_id: str
    title: str
    grant: str
    flow: str
    attempts: tuple[dict[str, Any], ...]
    expected_decisions: tuple[str, ...]
    expected_reasons: tuple[str, ...]
    expected_effect_count: int
    expected_outcome: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthCase:
        if (
            not isinstance(data, dict)
            or set(data) - CASE_REQUIRED_FIELDS - CASE_OPTIONAL_FIELDS
            or CASE_REQUIRED_FIELDS - set(data)
            or data.get("schema_version") != "cops.agent-mcp-auth-case/v1"
        ):
            raise LabError("Invalid authorization case fields or version")
        if (
            not isinstance(data["case_id"], str)
            or len(data["case_id"]) > 64
            or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", data["case_id"])
        ):
            raise LabError("Invalid authorization case ID")
        if not isinstance(data["title"], str) or not 1 <= len(data["title"].strip()) <= 160:
            raise LabError("Invalid authorization case title")
        if (
            not isinstance(data["grant"], str)
            or data["grant"] not in GRANTS
            or not isinstance(data["flow"], str)
            or data["flow"] not in {"delegated", "autonomous"}
        ):
            raise LabError("Unsupported synthetic grant or flow")
        attempts = data["attempts"]
        if not isinstance(attempts, list) or not 1 <= len(attempts) <= 6:
            raise LabError("Authorization case needs one to six attempts")
        normalized_attempts: list[dict[str, Any]] = []
        for source in attempts:
            if (
                not isinstance(source, dict)
                or set(source) - ATTEMPT_REQUIRED_FIELDS - ATTEMPT_OPTIONAL_FIELDS
                or ATTEMPT_REQUIRED_FIELDS - set(source)
            ):
                raise LabError("Invalid authorization attempt fields")
            attempt = deepcopy(source)
            attempt.setdefault("peer_action", "trusted_forward")
            attempt.setdefault("fault_mode", "none")
            if any(
                key in attempt and (not isinstance(attempt[key], str) or attempt[key] not in allowed)
                for key, allowed in ARGUMENT_ALIASES.items()
                if key not in {"grant", "flow", "fault_mode"}
            ):
                raise LabError("Authorization attempt leaves fixed synthetic aliases")
            if (
                not isinstance(attempt["tool"], str)
                or attempt["tool"] not in TOOLS
                or not isinstance(attempt["peer_action"], str)
                or attempt["peer_action"] not in PEER_ACTIONS
                or not isinstance(attempt["fault_mode"], str)
                or attempt["fault_mode"] not in FAULT_MODES
                or not isinstance(attempt["scopes"], list)
                or len(attempt["scopes"]) != 1
                or not isinstance(attempt["scopes"][0], str)
                or attempt["scopes"][0] not in SCOPES
                or type(attempt["depth"]) is not int
                or not 0 <= attempt["depth"] <= 3
                or type(attempt["tick"]) is not int
                or not 0 <= attempt["tick"] <= 10
            ):
                raise LabError("Invalid synthetic scope, depth, or logical time")
            normalized_attempts.append(attempt)
        expected = data["expected_decisions"]
        if (
            not isinstance(expected, list)
            or len(expected) != len(attempts)
            or any(not isinstance(value, str) or value not in DECISIONS for value in expected)
        ):
            raise LabError("Invalid expected decisions")
        expected_reasons = data["expected_reasons"]
        if (
            not isinstance(expected_reasons, list)
            or len(expected_reasons) != len(attempts)
            or any(not isinstance(value, str) or value not in REASONS for value in expected_reasons)
        ):
            raise LabError("Invalid expected reasons")
        effect_count = data["expected_effect_count"]
        if type(effect_count) is not int or not 0 <= effect_count <= len(attempts):
            raise LabError("Invalid expected effect count")
        surface = data.get("surface", "local_synthetic_fixture")
        expected_outcome = data.get("expected_outcome", "pass")
        if (
            not isinstance(surface, str)
            or surface not in SURFACES
            or not isinstance(expected_outcome, str)
            or expected_outcome not in OUTCOMES
        ):
            raise LabError("Invalid authorization surface or expected outcome")
        if surface == "unsupported_provider_surface" and expected_outcome != "unsupported":
            raise LabError("Unsupported surfaces must expect the unsupported outcome")
        return cls(
            surface,
            data["case_id"],
            data["title"],
            data["grant"],
            data["flow"],
            tuple(normalized_attempts),
            tuple(expected),
            tuple(expected_reasons),
            effect_count,
            expected_outcome,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.agent-mcp-auth-case/v1",
            "surface": self.surface,
            "case_id": self.case_id,
            "title": self.title,
            "grant": self.grant,
            "flow": self.flow,
            "attempts": deepcopy(list(self.attempts)),
            "expected_decisions": list(self.expected_decisions),
            "expected_reasons": list(self.expected_reasons),
            "expected_effect_count": self.expected_effect_count,
            "expected_outcome": self.expected_outcome,
        }


def load_auth_cases(path: Path) -> list[AuthCase]:
    """Load only versioned synthetic cases, rejecting duplicates."""
    if path.is_symlink():
        raise LabError("Authorization case paths cannot be symbolic links")
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(path.glob("*.json"))
    else:
        raise LabError("Authorization cases not found")
    if not files:
        raise LabError("No authorization cases found")
    if len(files) > 100:
        raise LabError("Authorization batch exceeds 100 cases")
    cases: list[AuthCase] = []
    seen: set[str] = set()
    for file in files:
        try:
            data = decode_json(read_regular_file(file, max_bytes=65536), max_bytes=65536)
        except (OSError, JSONInputError) as exc:
            raise LabError(f"Invalid authorization case: {file.name}") from exc
        if not isinstance(data, dict):
            raise LabError("Authorization case root must be an object")
        case = AuthCase.from_dict(data)
        if case.case_id in seen:
            raise LabError(f"Duplicate authorization case ID: {case.case_id}")
        seen.add(case.case_id)
        cases.append(case)
    return cases


def validate_default_auth_coverage(cases: list[AuthCase]) -> None:
    """Require meaningful controls and hostile-peer tests in the shipped corpus."""
    required: list[tuple[str, str, dict[str, Any], str, str, int, str]] = []
    for grant_name in ("delegated-write", "delegated-write-fabrikam", "autonomous-write"):
        grant = GRANTS[grant_name]
        attempt = {
            "principal": grant["principal"],
            "agent": grant["agent"],
            "downstream_service": "service-canary",
            "audience": "mcp://auth-fixture",
            "tenant": grant["tenant"],
            "resource": "res-canary",
            "operation": "write",
            "scopes": ["canary:write"],
            "depth": 1,
            "tick": 1,
            "tool": "canary/write",
            "peer_action": "trusted_forward",
            "fault_mode": "none",
        }
        required.append((grant_name, grant["mode"], attempt, "allowed", "allowed", 1, "pass"))
        if grant_name != "autonomous-write":
            cross = deepcopy(attempt)
            cross["tenant"] = "tenant-fabrikam-02" if grant["tenant"] == "tenant-contoso-01" else "tenant-contoso-01"
            required.append((grant_name, "delegated", cross, "denied", "tenant_mismatch", 0, "pass"))
        if grant_name == "delegated-write":
            for action, decision, reason, outcome in (
                ("mutate_tenant", "denied", "tenant_mismatch", "pass"),
                ("omit_tenant", "denied", "missing_tenant", "pass"),
                ("mutate_operation", "denied", "operation_mismatch", "pass"),
                ("substitute_receipt", "denied", "unrecognized_grant_or_actor", "pass"),
            ):
                hostile = deepcopy(attempt)
                hostile["peer_action"] = action
                required.append((grant_name, "delegated", hostile, decision, reason, 0, outcome))
    for grant, flow, attempt, decision, reason, effects, outcome in required:
        if not any(
            case.surface == "local_synthetic_fixture"
            and case.grant == grant
            and case.flow == flow
            and case.attempts == (attempt,)
            and case.expected_decisions == (decision,)
            and case.expected_reasons == (reason,)
            and case.expected_effect_count == effects
            and case.expected_outcome == outcome
            for case in cases
        ):
            raise LabError("Default authorization cases lack required two-tenant or hostile-peer coverage")


def run_auth_case(case: AuthCase) -> dict[str, Any]:
    """Fail closed: authorization cases must be approved and run as one immutable batch."""
    raise LabError("Direct authorization-case execution is disabled; use run_auth_cases with signed COPS approval")
