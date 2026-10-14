"""Exceptions for COPS engagement intake and execution planning."""

from __future__ import annotations


class EngagementIntakeError(ValueError):
    """Base error for engagement intake and planning violations."""


class GoalResolutionError(EngagementIntakeError):
    """Raised when a plain-language goal cannot be resolved safely."""

    def __init__(self, message: str, *, code: str, next_action: str) -> None:
        super().__init__(message)
        self.code = code
        self.next_action = next_action


class MissingOwnerError(EngagementIntakeError):
    """Raised when an engagement intake lacks an operator or owner."""


class ScopeAmbiguityError(EngagementIntakeError):
    """Raised when target scope is ambiguous, colliding, or malformed."""


class IncompatibleWindowError(EngagementIntakeError):
    """Raised when an assessment window is invalid, inverted, or expired."""


class IncompleteBudgetError(EngagementIntakeError):
    """Raised when execution budget limits are missing or incomplete."""


class IncompleteLiveRequestError(EngagementIntakeError):
    """Raised when a live execution request lacks required live constraints or safeguards."""
