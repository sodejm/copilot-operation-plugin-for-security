"""Scenario laboratory harness runtime for COPS security operations."""

from __future__ import annotations

from .fixtures import (
    make_inert_action_plan,
    make_inert_container_environment,
    make_inert_engagement,
    make_inert_execution_authorization,
    make_inert_vm_environment,
)
from .harness import LaboratoryHarness
from .journal import LaboratoryCaseJournal
from .matrix import parse_version_tuple, verify_platform_matrix, verify_tool_prerequisites, version_ge
from .models import (
    CanaryVerificationError,
    IsolationVerificationError,
    LaboratoryCaseResult,
    LaboratoryError,
    LaboratoryGateError,
    LaboratoryObservation,
    PrerequisiteMismatchError,
    ResetError,
    TestedMatrix,
)
from .receipts import (
    LaboratoryCaseObservation,
    LaboratoryObservationTrustStore,
    LaboratoryResetReceipt,
    verify_receipt_signature,
)

__all__ = [
    "CanaryVerificationError",
    "IsolationVerificationError",
    "LaboratoryCaseResult",
    "LaboratoryCaseJournal",
    "LaboratoryCaseObservation",
    "LaboratoryError",
    "LaboratoryGateError",
    "LaboratoryHarness",
    "LaboratoryObservation",
    "LaboratoryObservationTrustStore",
    "LaboratoryResetReceipt",
    "PrerequisiteMismatchError",
    "ResetError",
    "TestedMatrix",
    "make_inert_action_plan",
    "make_inert_container_environment",
    "make_inert_engagement",
    "make_inert_execution_authorization",
    "make_inert_vm_environment",
    "parse_version_tuple",
    "version_ge",
    "verify_platform_matrix",
    "verify_receipt_signature",
    "verify_tool_prerequisites",
]
