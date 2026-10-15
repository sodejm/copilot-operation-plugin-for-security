"""Versioned workflow orchestration and purple-team handoff contracts."""

from .contracts import WorkflowContractError, WorkflowDefinition
from .purple import (
    PurpleTeamHandoffContract,
    emit_purple_team_handoff,
    evaluate_purple_team_handoff,
    execute_simple_rule,
)
from .playback import EvidenceBundleSigner
from .runtime import StageExecutionResult, WorkflowRunner, WorkflowRunResult, WorkflowRuntimeError, compile_action_plan

__all__ = [
    "PurpleTeamHandoffContract",
    "EvidenceBundleSigner",
    "StageExecutionResult",
    "WorkflowContractError",
    "WorkflowDefinition",
    "WorkflowRunResult",
    "WorkflowRunner",
    "WorkflowRuntimeError",
    "compile_action_plan",
    "emit_purple_team_handoff",
    "evaluate_purple_team_handoff",
    "execute_simple_rule",
]
