"""COPS engagement intake, scope validation, and execution planning."""

from __future__ import annotations

from .errors import (
    EngagementIntakeError,
    GoalResolutionError,
    IncompatibleWindowError,
    IncompleteBudgetError,
    IncompleteLiveRequestError,
    MissingOwnerError,
    ScopeAmbiguityError,
)
from .intake import create_engagement_contract, validate_engagement_intake
from .goals import resolve_engagement_goal
from .planning import build_action_plan

__all__ = [
    "EngagementIntakeError",
    "GoalResolutionError",
    "MissingOwnerError",
    "ScopeAmbiguityError",
    "IncompatibleWindowError",
    "IncompleteBudgetError",
    "IncompleteLiveRequestError",
    "create_engagement_contract",
    "validate_engagement_intake",
    "resolve_engagement_goal",
    "build_action_plan",
]
