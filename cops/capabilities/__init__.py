"""COPS capability reconciliation and truth-in-advertising package."""

from __future__ import annotations

from .auditor import (
    audit_capabilities,
    build_capability_registry,
    generate_capability_matrix_markdown,
)
from .models import (
    CapabilityEntry,
    CapabilityKind,
    CapabilityMode,
    CapabilityTruthError,
    ValidationStatus,
)

__all__ = [
    "CapabilityEntry",
    "CapabilityKind",
    "CapabilityMode",
    "CapabilityTruthError",
    "ValidationStatus",
    "audit_capabilities",
    "build_capability_registry",
    "generate_capability_matrix_markdown",
]
