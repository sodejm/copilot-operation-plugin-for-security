"""Execution runtime framework for COPS security operations."""

from __future__ import annotations

from .authorization import (
    AuthorizationDeniedError,
    AuthorizationError,
    AuthorizationRequiredError,
    LegacyReceiptDeprecationWarning,
    compute_authorization_signature,
    consume_execution_authorization,
    create_execution_authorization,
    request_interactive_plan_authorization,
    verify_execution_authorization,
)

__all__ = [
    "AuthorizationDeniedError",
    "AuthorizationError",
    "AuthorizationRequiredError",
    "LegacyReceiptDeprecationWarning",
    "compute_authorization_signature",
    "consume_execution_authorization",
    "create_execution_authorization",
    "request_interactive_plan_authorization",
    "verify_execution_authorization",
]
