"""Lifecycle state machines and transition validation for COPS operational contracts."""

from __future__ import annotations

from typing import Final


class ContractError(ValueError):
    """Base exception for operational contract and lifecycle violations."""

    def __init__(self, code: str = "invalid_contract", message: str | None = None):
        self.code = code
        self.message = message or code
        super().__init__(self.message)


ENGAGEMENT_STATES: Final[frozenset[str]] = frozenset(
    {"planned", "active", "completed", "cancelled", "aborted"}
)

ENGAGEMENT_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "planned": frozenset({"active", "cancelled"}),
    "active": frozenset({"completed", "cancelled", "aborted"}),
    "completed": frozenset(),
    "cancelled": frozenset(),
    "aborted": frozenset(),
}

ACTION_PLAN_STATES: Final[frozenset[str]] = frozenset(
    {"draft", "pending_approval", "approved", "executing", "fulfilled", "rejected", "cancelled"}
)

ACTION_PLAN_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "draft": frozenset({"pending_approval", "cancelled"}),
    "pending_approval": frozenset({"approved", "rejected", "cancelled"}),
    "approved": frozenset({"executing", "cancelled"}),
    "executing": frozenset({"fulfilled", "cancelled"}),
    "fulfilled": frozenset(),
    "rejected": frozenset(),
    "cancelled": frozenset(),
}

EXECUTION_AUTHORIZATION_STATES: Final[frozenset[str]] = frozenset(
    {"approved", "consumed", "revoked", "expired"}
)

EXECUTION_AUTHORIZATION_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "approved": frozenset({"consumed", "revoked", "expired"}),
    "consumed": frozenset(),
    "revoked": frozenset(),
    "expired": frozenset(),
}

SPECIALIST_HANDOFF_STATES: Final[frozenset[str]] = frozenset(
    {"proposed", "accepted", "in_review", "completed", "rejected"}
)

SPECIALIST_HANDOFF_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "proposed": frozenset({"accepted", "rejected"}),
    "accepted": frozenset({"in_review", "rejected"}),
    "in_review": frozenset({"completed", "rejected"}),
    "completed": frozenset(),
    "rejected": frozenset(),
}

LABORATORY_ENVIRONMENT_STATES: Final[frozenset[str]] = frozenset(
    {"registered", "verified", "active", "resetting", "torn_down", "failed"}
)

LABORATORY_ENVIRONMENT_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "registered": frozenset({"verified", "failed", "torn_down"}),
    "verified": frozenset({"active", "resetting", "failed", "torn_down"}),
    "active": frozenset({"verified", "resetting", "failed", "torn_down"}),
    "resetting": frozenset({"verified", "failed", "torn_down"}),
    "failed": frozenset({"resetting", "torn_down"}),
    "torn_down": frozenset(),
}

RUN_RESULT_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "partial", "cancelled", "failed", "uncertain", "not_assessed"}
)


def validate_transition(current_state: str, next_state: str, contract_type: str) -> None:
    """Validate that moving from current_state to next_state is legally allowed."""
    if contract_type == "engagement":
        if current_state not in ENGAGEMENT_STATES:
            raise ContractError("invalid_contract", f"unknown engagement state: {current_state}")
        if next_state not in ENGAGEMENT_STATES:
            raise ContractError("invalid_contract", f"unknown target engagement state: {next_state}")
        allowed = ENGAGEMENT_TRANSITIONS.get(current_state, frozenset())
        if next_state not in allowed:
            raise ContractError(
                "illegal_transition",
                f"illegal engagement transition from '{current_state}' to '{next_state}'"
            )
    elif contract_type in ("action_plan", "action-plan"):
        if current_state not in ACTION_PLAN_STATES:
            raise ContractError("invalid_contract", f"unknown action plan state: {current_state}")
        if next_state not in ACTION_PLAN_STATES:
            raise ContractError("invalid_contract", f"unknown target action plan state: {next_state}")
        allowed = ACTION_PLAN_TRANSITIONS.get(current_state, frozenset())
        if next_state not in allowed:
            raise ContractError(
                "illegal_transition",
                f"illegal action plan transition from '{current_state}' to '{next_state}'"
            )
    elif contract_type in ("execution_authorization", "execution-authorization"):
        if current_state not in EXECUTION_AUTHORIZATION_STATES:
            raise ContractError("invalid_contract", f"unknown execution authorization state: {current_state}")
        if next_state not in EXECUTION_AUTHORIZATION_STATES:
            raise ContractError("invalid_contract", f"unknown target execution authorization state: {next_state}")
        allowed = EXECUTION_AUTHORIZATION_TRANSITIONS.get(current_state, frozenset())
        if next_state not in allowed:
            raise ContractError(
                "illegal_transition",
                f"illegal execution authorization transition from '{current_state}' to '{next_state}'"
            )
    elif contract_type in ("specialist_handoff", "specialist-handoff"):
        if current_state not in SPECIALIST_HANDOFF_STATES:
            raise ContractError("invalid_contract", f"unknown specialist handoff state: {current_state}")
        if next_state not in SPECIALIST_HANDOFF_STATES:
            raise ContractError("invalid_contract", f"unknown target specialist handoff state: {next_state}")
        allowed = SPECIALIST_HANDOFF_TRANSITIONS.get(current_state, frozenset())
        if next_state not in allowed:
            raise ContractError(
                "illegal_transition",
                f"illegal specialist handoff transition from '{current_state}' to '{next_state}'"
            )
    elif contract_type in ("laboratory_environment", "laboratory-environment"):
        if current_state not in LABORATORY_ENVIRONMENT_STATES:
            raise ContractError("invalid_contract", f"unknown laboratory environment state: {current_state}")
        if next_state not in LABORATORY_ENVIRONMENT_STATES:
            raise ContractError("invalid_contract", f"unknown target laboratory environment state: {next_state}")
        allowed = LABORATORY_ENVIRONMENT_TRANSITIONS.get(current_state, frozenset())
        if next_state not in allowed:
            raise ContractError(
                "illegal_transition",
                f"illegal laboratory environment transition from '{current_state}' to '{next_state}'"
            )
    else:
        raise ContractError("invalid_contract", f"contract type '{contract_type}' does not define lifecycle transitions")
