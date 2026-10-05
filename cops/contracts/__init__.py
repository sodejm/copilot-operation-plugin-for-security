"""COPS operational and engagement contracts framework.

Provides versioned schemas, lifecycle state machines, and evidence-envelope bindings
for Engagements, Scenarios, ActionPlans, RunResults, and Findings.
"""

from __future__ import annotations

from .lifecycle import (
    ACTION_PLAN_STATES,
    ACTION_PLAN_TRANSITIONS,
    ContractError,
    ENGAGEMENT_STATES,
    ENGAGEMENT_TRANSITIONS,
    EXECUTION_AUTHORIZATION_STATES,
    EXECUTION_AUTHORIZATION_TRANSITIONS,
    RUN_RESULT_STATUSES,
    validate_transition,
)
from .models import ActionPlan, CleanupReceipt, Engagement, ExecutionAuthorization, Finding, RunResult, Scenario
from .validation import (
    SCHEMAS,
    build_action_plan_digest,
    evaluate_run_result,
    validate_contract,
    validate_identifier,
)

__all__ = [
    "ACTION_PLAN_STATES",
    "ACTION_PLAN_TRANSITIONS",
    "ActionPlan",
    "CleanupReceipt",
    "ContractError",
    "ENGAGEMENT_STATES",
    "ENGAGEMENT_TRANSITIONS",
    "EXECUTION_AUTHORIZATION_STATES",
    "EXECUTION_AUTHORIZATION_TRANSITIONS",
    "Engagement",
    "ExecutionAuthorization",
    "Finding",
    "RUN_RESULT_STATUSES",
    "RunResult",
    "SCHEMAS",
    "Scenario",
    "build_action_plan_digest",
    "evaluate_run_result",
    "validate_contract",
    "validate_identifier",
    "validate_transition",
]
