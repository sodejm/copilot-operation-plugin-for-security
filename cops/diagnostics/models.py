"""Data models for COPS package workflows and capability diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal


class DiagnosticStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    MISSING = "missing"


@dataclass
class DiagnosticCheck:
    """Individual diagnostic check result."""

    name: str
    status: Literal["passed", "failed", "warning", "missing"]
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolDiagnostic:
    """Diagnostic result for an external security tool."""

    tool: str
    status: Literal["available", "missing", "version_mismatch"]
    installed_version: str | None
    minimum_version: str
    path: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PackageDiagnostic:
    """Diagnostic result for a COPS plugin package."""

    package_id: str
    category: str
    status: Literal["ready", "degraded", "unready"]
    manifest_valid: bool
    skills_count: int
    has_playbook: bool
    has_validation_script: bool
    checks: list[DiagnosticCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "category": self.category,
            "status": self.status,
            "manifest_valid": self.manifest_valid,
            "skills_count": self.skills_count,
            "has_playbook": self.has_playbook,
            "has_validation_script": self.has_validation_script,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class SystemDiagnostic:
    """Host environment and platform diagnostic result."""

    os: str
    distribution: str
    architecture: str
    python_version: str
    is_supported: bool
    checks: list[DiagnosticCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "os": self.os,
            "distribution": self.distribution,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "is_supported": self.is_supported,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class DiagnosticReport:
    """Comprehensive capability and package diagnostic report."""

    timestamp: str
    system: SystemDiagnostic
    tools: list[ToolDiagnostic]
    packages: list[PackageDiagnostic]
    capability_truth_passed: bool
    capability_count: int
    all_ready: bool
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "system": self.system.to_dict(),
            "tools": [t.to_dict() for t in self.tools],
            "packages": [p.to_dict() for p in self.packages],
            "capability_truth_passed": self.capability_truth_passed,
            "capability_count": self.capability_count,
            "all_ready": self.all_ready,
            "summary": self.summary,
        }
