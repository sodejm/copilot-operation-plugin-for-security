"""Exceptions for COPS engagement intake and execution planning."""

from __future__ import annotations


class EngagementIntakeError(ValueError):
    """Base error for engagement intake and planning violations."""


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
