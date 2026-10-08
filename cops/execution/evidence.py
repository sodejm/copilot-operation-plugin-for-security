"""Cryptographic execution evidence capture and run result binding.

Constructs tamper-evident evidence envelopes binding execution telemetry,
redacted outputs, artifact checksums, and authorization context.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cops.evidence.canonical import digest, utc_now

from .filesystem import open_directory_no_symlinks
from .redaction import StreamRedactor


@dataclass
class CapturedArtifact:
    """Artifact produced during operation execution."""

    name: str
    path: str
    sha256: str
    size_bytes: int


class EvidenceCaptureError(RuntimeError):
    """Evidence could not be written without crossing the workspace boundary."""


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
    truncated_bytes: int = 0


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
        max_output_bytes: int | None = None,
    ) -> tuple[bytes, CapturedArtifact]:
        """Redact output stream, save artifact file, and record step telemetry."""
        raw_combined = stdout + (b"\n" if stdout and stderr else b"") + stderr
        redacted_full = self.redactor.redact_bytes(raw_combined)
        redacted_characters = max(0, len(raw_combined) - len(redacted_full))
        redacted_bytes = redacted_full
        if max_output_bytes is not None:
            if max_output_bytes < 0:
                raise ValueError("max_output_bytes must be non-negative")
            redacted_bytes = redacted_bytes[:max_output_bytes]

        # Sanitize step_id against traversal and invalid filename characters
        clean_step_id = re.sub(r"[^a-zA-Z0-9_-]", "_", step_id)
        existing_names = {art.name for art in self.artifacts}
        base_name = f"{clean_step_id}_output.txt"
        if base_name in existing_names:
            artifact_filename = f"{clean_step_id}_{len(self.artifacts)+1}_output.txt"
        else:
            artifact_filename = base_name

        self._write_artifact(artifact_filename, redacted_bytes)

        artifact_sha256 = hashlib.sha256(redacted_bytes).hexdigest()
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
            redacted_characters=redacted_characters,
            truncated_bytes=len(redacted_full) - len(redacted_bytes),
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

    def _write_artifact(self, filename: str, content: bytes) -> None:
        """Create one evidence file using only protected directory descriptors."""
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise EvidenceCaptureError(
                "symlink-safe evidence writes require POSIX O_NOFOLLOW and directory descriptors"
            )
        nofollow = os.O_NOFOLLOW
        directory = os.O_DIRECTORY
        workspace_fd = -1
        artifacts_fd = -1
        artifact_fd = -1
        try:
            workspace_fd = open_directory_no_symlinks(self.workspace_dir)
            self._validate_private_directory(workspace_fd, "worker workspace")
            try:
                os.mkdir("artifacts", mode=0o700, dir_fd=workspace_fd)
            except FileExistsError:
                pass
            artifacts_fd = os.open(
                "artifacts", os.O_RDONLY | directory | nofollow, dir_fd=workspace_fd
            )
            self._validate_private_directory(artifacts_fd, "evidence artifact directory")
            artifact_fd = os.open(
                filename,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | nofollow
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=artifacts_fd,
            )
            view = memoryview(content)
            while view:
                written = os.write(artifact_fd, view)
                view = view[written:]
            os.fsync(artifact_fd)
        except OSError as err:
            raise EvidenceCaptureError(f"secure evidence artifact write failed: {err}") from err
        finally:
            for fd in (artifact_fd, artifacts_fd, workspace_fd):
                if fd >= 0:
                    os.close(fd)

    @staticmethod
    def _validate_private_directory(fd: int, label: str) -> None:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise EvidenceCaptureError(f"{label} is not a directory")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise EvidenceCaptureError(f"{label} is not owned by the worker account")
        if info.st_mode & 0o022:
            raise EvidenceCaptureError(f"{label} is writable by group or other users")

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
