"""Cryptographic execution evidence capture and run result binding.

Constructs tamper-evident evidence envelopes binding execution telemetry,
redacted outputs, artifact checksums, and authorization context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cops.evidence.canonical import digest, utc_now
from .redaction import StreamRedactor


@dataclass
class CapturedArtifact:
    """Artifact produced during operation execution."""

    name: str
    path: str
    sha256: str
    size_bytes: int


@dataclass
class StepTelemetry:
    """Telemetry captured for a single execution step."""

    step_id: str
    tool: str
    action: str
    exit_code: int
    started_at: str
    finished_at: str
    stdout_sha256: str
    stderr_sha256: str
    output_length: int
    redacted_characters: int = 0


class EvidenceRecorder:
    """Captures, redacts, digests, and stores evidence records."""

    def __init__(
        self,
        workspace_dir: Path,
        redactor: StreamRedactor | None = None,
    ) -> None:
        self.workspace_dir = Path(workspace_dir)
        self.redactor = redactor or StreamRedactor()
        self.artifacts: list[CapturedArtifact] = []
        self.step_telemetry: list[StepTelemetry] = []
        self.evidence_records: list[dict[str, Any]] = []

    def record_step_output(
        self,
        *,
        step_id: str,
        tool: str,
        action: str,
        stdout: bytes,
        stderr: bytes,
        exit_code: int,
        started_at: str,
        finished_at: str,
    ) -> tuple[bytes, CapturedArtifact]:
        """Redact output stream, save artifact file, and record step telemetry."""
        raw_combined = stdout + (b"\n" if stdout and stderr else b"") + stderr
        redacted_bytes = self.redactor.redact_bytes(raw_combined)

        # Write redacted output to artifact file in workspace
        artifacts_dir = self.workspace_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        artifact_filename = f"{step_id}_output.txt"
        artifact_path = artifacts_dir / artifact_filename
        artifact_path.write_bytes(redacted_bytes)

        artifact_sha256 = digest({"step_id": step_id, "data": redacted_bytes.decode("utf-8", errors="replace")})
        rel_path = f"artifacts/{artifact_filename}"
        artifact = CapturedArtifact(
            name=artifact_filename,
            path=rel_path,
            sha256=artifact_sha256,
            size_bytes=len(redacted_bytes),
        )
        self.artifacts.append(artifact)

        telemetry = StepTelemetry(
            step_id=step_id,
            tool=tool,
            action=action,
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
            stdout_sha256=digest(self.redactor.redact_bytes(stdout).decode("utf-8", errors="replace")),
            stderr_sha256=digest(self.redactor.redact_bytes(stderr).decode("utf-8", errors="replace")),
            output_length=len(redacted_bytes),
            redacted_characters=max(0, len(raw_combined) - len(redacted_bytes)),
        )
        self.step_telemetry.append(telemetry)

        # Record structured evidence payload
        evidence_entry = {
            "evidence_id": f"ev-{step_id}",
            "recorded_at": utc_now(),
            "step_id": step_id,
            "tool": tool,
            "action": action,
            "artifact_sha256": artifact_sha256,
            "exit_code": exit_code,
        }
        self.evidence_records.append(evidence_entry)

        return redacted_bytes, artifact

    def get_artifact_dicts(self) -> list[dict[str, Any]]:
        """Return artifacts in schema-compliant dictionary format."""
        return [
            {
                "name": art.name,
                "path": art.path,
                "sha256": art.sha256,
            }
            for art in self.artifacts
        ]

    def get_evidence_hashes(self) -> list[str]:
        """Return list of canonical SHA256 hashes for all recorded evidence entries."""
        return [digest(record) for record in self.evidence_records]
