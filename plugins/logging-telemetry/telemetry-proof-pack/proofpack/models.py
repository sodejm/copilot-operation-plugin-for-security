"""Immutable typed data models for Telemetry Proof Pack."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ProofError(ValueError):
    """Raised when proof pack manifest parsing or correlation fails."""


@dataclass(frozen=True)
class RunManifest:
    """Run configuration and scope boundaries for a synthetic test event."""

    run_id: str
    authorized_environment: str
    synthetic_marker: str
    source_event_type: str
    pipeline_route: str  # "cribl_to_splunk" | "cribl_to_sentinel"
    destination: dict[str, Any]
    detection_rule: dict[str, Any]
    time_window: dict[str, Any]
    evidence_capture_policy: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunManifest:
        required = [
            "run_id", "authorized_environment", "synthetic_marker",
            "source_event_type", "pipeline_route", "destination",
            "detection_rule", "time_window", "evidence_capture_policy"
        ]
        for f in required:
            if f not in data:
                raise ProofError(f"Missing required manifest field: {f}")
        return cls(
            run_id=data["run_id"],
            authorized_environment=data["authorized_environment"],
            synthetic_marker=data["synthetic_marker"],
            source_event_type=data["source_event_type"],
            pipeline_route=data["pipeline_route"],
            destination=dict(data["destination"]),
            detection_rule=dict(data["detection_rule"]),
            time_window=dict(data["time_window"]),
            evidence_capture_policy=dict(data["evidence_capture_policy"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.proof-manifest/v1",
            "run_id": self.run_id,
            "authorized_environment": self.authorized_environment,
            "synthetic_marker": self.synthetic_marker,
            "source_event_type": self.source_event_type,
            "pipeline_route": self.pipeline_route,
            "destination": self.destination,
            "detection_rule": self.detection_rule,
            "time_window": self.time_window,
            "evidence_capture_policy": self.evidence_capture_policy,
        }


@dataclass(frozen=True)
class StageObservation:
    """An observed or missing pipeline stage evidence record."""

    stage_name: str
    status: str  # "observed" | "missing" | "unresolved"
    component: str
    evidence_id: str
    timestamp: str = ""
    raw_evidence_hash: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageObservation:
        required = ["stage_name", "status", "component", "evidence_id"]
        for f in required:
            if f not in data:
                raise ProofError(f"Missing required stage observation field: {f}")
        return cls(
            stage_name=data["stage_name"],
            status=data["status"],
            component=data["component"],
            evidence_id=data["evidence_id"],
            timestamp=data.get("timestamp", ""),
            raw_evidence_hash=data.get("raw_evidence_hash", ""),
            details=dict(data.get("details", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "stage_name": self.stage_name,
            "status": self.status,
            "component": self.component,
            "evidence_id": self.evidence_id,
        }
        if self.timestamp:
            res["timestamp"] = self.timestamp
        if self.raw_evidence_hash:
            res["raw_evidence_hash"] = self.raw_evidence_hash
        if self.details:
            res["details"] = self.details
        return res


@dataclass(frozen=True)
class PipelineProof:
    """Correlated multi-stage telemetry proof for a synthetic test event."""

    run_id: str
    synthetic_marker: str
    stages: tuple[StageObservation, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PipelineProof:
        required = ["run_id", "synthetic_marker", "stages"]
        for f in required:
            if f not in data:
                raise ProofError(f"Missing required proof bundle field: {f}")
        return cls(
            run_id=data["run_id"],
            synthetic_marker=data["synthetic_marker"],
            stages=tuple(StageObservation.from_dict(s) for s in data["stages"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cops.proof-bundle/v1",
            "run_id": self.run_id,
            "synthetic_marker": self.synthetic_marker,
            "stages": [s.to_dict() for s in self.stages],
        }
