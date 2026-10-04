"""Capability data models and truth-in-advertising exceptions for COPS."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

CapabilityKind = Literal["plugin", "specialist", "scenario"]
CapabilityMode = Literal["planned", "import", "laboratory", "live-validated"]
ValidationStatus = Literal["validated", "unverified"]


class CapabilityTruthError(ValueError):
    """Exception raised when capability claims violate truth-in-advertising rules."""

    def __init__(self, code: str = "invalid_capability_claim", message: str | None = None):
        self.code = code
        self.message = message or code
        super().__init__(self.message)


@dataclass(frozen=True)
class CapabilityEntry:
    """A reconciled capability entry with explicit operational mode and boundaries."""

    id: str
    name: str
    kind: CapabilityKind
    mode: CapabilityMode
    domain: str
    validation_status: ValidationStatus
    truth_boundaries: str
    evidence_requirements: list[str] = field(default_factory=list)
    live_evidence_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityEntry:
        return cls(
            id=data["id"],
            name=data["name"],
            kind=data["kind"],
            mode=data["mode"],
            domain=data["domain"],
            validation_status=data["validation_status"],
            truth_boundaries=data["truth_boundaries"],
            evidence_requirements=list(data.get("evidence_requirements", [])),
            live_evidence_verified=bool(data.get("live_evidence_verified", False)),
        )
