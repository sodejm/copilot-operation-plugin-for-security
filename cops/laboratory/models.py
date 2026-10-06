"""Laboratory harness data models and exceptions for COPS security operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from cops.contracts.models import CleanupReceipt, RunResult


class LaboratoryError(RuntimeError):
    """Base error for laboratory harness and environment operations."""


class PrerequisiteMismatchError(LaboratoryError):
    """Platform, distribution, runtime, or tool versions do not meet tested prerequisites."""


class IsolationVerificationError(LaboratoryError):
    """Laboratory environment failed mandatory isolation or process boundary verification."""


class CanaryVerificationError(LaboratoryError):
    """Laboratory canary token is missing, corrupted, or detected outside authorized boundary."""


class ResetError(LaboratoryError):
    """Laboratory reproducible reset procedure failed to restore clean baseline."""


class LaboratoryGateError(LaboratoryError):
    """Pre-execution authorization, isolation, or egress gate rejected laboratory run."""


@dataclass(frozen=True)
class TestedMatrix:
    """Tested platforms, distributions, runtimes, and tool versions matrix."""

    supported_os: tuple[str, ...] = ("linux", "darwin")
    supported_distributions: tuple[str, ...] = ("ubuntu", "debian", "alpine", "darwin", "macos")
    supported_architectures: tuple[str, ...] = ("x86_64", "aarch64", "arm64")
    supported_runtimes: tuple[str, ...] = ("container", "vm", "process_sandbox", "docker", "containerd", "podman", "qemu", "inert-lab-harness")
    tool_minimum_versions: dict[str, str] = field(default_factory=lambda: {
        "kubectl": "1.24.0",
        "kube-bench": "0.6.0",
        "kube-hunter": "0.6.0",
        "kubescape": "2.0.0",
        "nmap": "7.80",
        "python3": "3.11.0",
    })


@dataclass
class LaboratoryCaseResult:
    """Structured result of executing a laboratory test case."""

    case_type: Literal["positive", "negative", "remediated"]
    status: Literal["success", "failed", "rejected", "remediated"]
    environment_id: str
    plan_id: str
    run_result: RunResult
    canary_verified: bool
    evidence_records: list[str] = field(default_factory=list)
    cleanup_receipt: CleanupReceipt | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_type": self.case_type,
            "status": self.status,
            "environment_id": self.environment_id,
            "plan_id": self.plan_id,
            "run_result": self.run_result.to_dict(),
            "canary_verified": self.canary_verified,
            "evidence_records": self.evidence_records,
            "cleanup_receipt": self.cleanup_receipt.to_dict() if self.cleanup_receipt else None,
            "details": self.details,
        }
