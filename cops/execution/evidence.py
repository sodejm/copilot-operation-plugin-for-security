"""Cryptographic execution evidence capture and run result binding.

Constructs tamper-evident evidence envelopes binding execution telemetry,
redacted outputs, artifact checksums, and authorization context.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
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
    truncated_bytes: int = 0


@dataclass(frozen=True)
class ArtifactReservation:
    """An empty artifact inode reserved before an operation can have effects."""

    name: str
    path: str
    device: int
    inode: int


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
        self._reservations: dict[str, ArtifactReservation] = {}

    def reserve_step_output(self, step_id: str) -> ArtifactReservation:
        """Reserve a unique evidence inode before executing a step."""
        clean_step_id = re.sub(r"[^a-zA-Z0-9_-]", "_", step_id)
        workspace_fd = -1
        artifacts_fd = -1
        artifact_fd = -1
        filename: str | None = None
        try:
            nofollow, directory = self._required_posix_flags()
            workspace_fd = open_directory_no_symlinks(self.workspace_dir)
            self._validate_private_directory(workspace_fd, "worker workspace")
            try:
                os.mkdir("artifacts", mode=0o700, dir_fd=workspace_fd)
            except FileExistsError:
                pass
            artifacts_fd = os.open("artifacts", os.O_RDONLY | directory | nofollow, dir_fd=workspace_fd)
            self._validate_private_directory(artifacts_fd, "evidence artifact directory")

            base_name = f"{clean_step_id}_output.txt"
            for attempt in range(16):
                candidate = base_name if attempt == 0 else f"{clean_step_id}_{uuid.uuid4().hex}_output.txt"
                try:
                    artifact_fd = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                        dir_fd=artifacts_fd,
                    )
                except FileExistsError:
                    continue
                filename = candidate
                break
            if artifact_fd < 0 or filename is None:
                raise EvidenceCaptureError("secure evidence artifact reservation could not choose a unique name")

            info = os.fstat(artifact_fd)
            self._validate_private_file(info)
            reservation = ArtifactReservation(
                name=filename,
                path=f"artifacts/{filename}",
                device=info.st_dev,
                inode=info.st_ino,
            )
            self._reservations[reservation.path] = reservation
            return reservation
        except EvidenceCaptureError:
            if filename is not None and artifacts_fd >= 0:
                try:
                    os.unlink(filename, dir_fd=artifacts_fd)
                except OSError:
                    pass
            raise
        except OSError as err:
            if filename is not None and artifacts_fd >= 0:
                try:
                    os.unlink(filename, dir_fd=artifacts_fd)
                except OSError:
                    pass
            raise EvidenceCaptureError("secure evidence artifact reservation failed") from err
        finally:
            for fd in (artifact_fd, artifacts_fd, workspace_fd):
                if fd >= 0:
                    os.close(fd)

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
        reservation: ArtifactReservation | None = None,
    ) -> tuple[bytes, CapturedArtifact]:
        """Redact output stream, save artifact file, and record step telemetry."""
        if max_output_bytes is not None and max_output_bytes < 0:
            raise ValueError("max_output_bytes must be non-negative")
        if reservation is None:
            reservation = self.reserve_step_output(step_id)
        if self._reservations.get(reservation.path) != reservation:
            raise EvidenceCaptureError("evidence artifact reservation is not active")
        try:
            raw_combined = stdout + (b"\n" if stdout and stderr else b"") + stderr
            redacted_full = self.redactor.redact_bytes(raw_combined)
            redacted_characters = max(0, len(raw_combined) - len(redacted_full))
            redacted_bytes = redacted_full
            if max_output_bytes is not None:
                redacted_bytes = redacted_bytes[:max_output_bytes]

            truncated_bytes = len(redacted_full) - len(redacted_bytes)
            self._write_reserved_artifact(reservation, redacted_bytes)
        except BaseException:
            self.discard_reservation(reservation)
            raise
        self._reservations.pop(reservation.path, None)

        artifact_sha256 = hashlib.sha256(redacted_bytes).hexdigest()
        artifact = CapturedArtifact(
            name=reservation.name,
            path=reservation.path,
            sha256=artifact_sha256,
            size_bytes=len(redacted_bytes),
            truncated_bytes=truncated_bytes,
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
            truncated_bytes=truncated_bytes,
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
            "artifact_size_bytes": len(redacted_bytes),
            "artifact_truncated_bytes": truncated_bytes,
            "exit_code": exit_code,
        }
        self.evidence_records.append(evidence_entry)

        return redacted_bytes, artifact

    @staticmethod
    def _required_posix_flags() -> tuple[int, int]:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise EvidenceCaptureError(
                "symlink-safe evidence writes require POSIX O_NOFOLLOW and directory descriptors"
            )
        return os.O_NOFOLLOW, os.O_DIRECTORY

    @staticmethod
    def _validate_private_file(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceCaptureError("evidence artifact is not a regular file")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise EvidenceCaptureError("evidence artifact is not owned by the worker account")
        if info.st_mode & 0o077:
            raise EvidenceCaptureError("evidence artifact permissions are not private")

    def _write_reserved_artifact(self, reservation: ArtifactReservation, content: bytes) -> None:
        """Write content through a previously reserved and verified inode."""
        nofollow, directory = self._required_posix_flags()
        workspace_fd = -1
        artifacts_fd = -1
        artifact_fd = -1
        try:
            workspace_fd = open_directory_no_symlinks(self.workspace_dir)
            self._validate_private_directory(workspace_fd, "worker workspace")
            artifacts_fd = os.open("artifacts", os.O_RDONLY | directory | nofollow, dir_fd=workspace_fd)
            self._validate_private_directory(artifacts_fd, "evidence artifact directory")
            artifact_fd = os.open(
                reservation.name,
                os.O_WRONLY | nofollow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=artifacts_fd,
            )
            info = os.fstat(artifact_fd)
            self._validate_private_file(info)
            if (info.st_dev, info.st_ino) != (reservation.device, reservation.inode):
                raise EvidenceCaptureError("evidence artifact reservation identity changed")
            os.ftruncate(artifact_fd, 0)
            view = memoryview(content)
            while view:
                written = os.write(artifact_fd, view)
                view = view[written:]
            os.fsync(artifact_fd)
        except OSError as err:
            raise EvidenceCaptureError("secure evidence artifact write failed") from err
        finally:
            for fd in (artifact_fd, artifacts_fd, workspace_fd):
                if fd >= 0:
                    os.close(fd)

    def discard_reservation(self, reservation: ArtifactReservation) -> None:
        """Remove an unused reservation without following replaced paths."""
        if self._reservations.pop(reservation.path, None) != reservation:
            return
        workspace_fd = -1
        artifacts_fd = -1
        artifact_fd = -1
        try:
            nofollow, directory = self._required_posix_flags()
            workspace_fd = open_directory_no_symlinks(self.workspace_dir)
            artifacts_fd = os.open("artifacts", os.O_RDONLY | directory | nofollow, dir_fd=workspace_fd)
            artifact_fd = os.open(
                reservation.name,
                os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
                dir_fd=artifacts_fd,
            )
            info = os.fstat(artifact_fd)
            if (info.st_dev, info.st_ino) != (reservation.device, reservation.inode):
                return
            os.close(artifact_fd)
            artifact_fd = -1
            os.unlink(reservation.name, dir_fd=artifacts_fd)
        except (OSError, EvidenceCaptureError):
            pass
        finally:
            for fd in (artifact_fd, artifacts_fd, workspace_fd):
                if fd >= 0:
                    os.close(fd)

    def discard_pending_reservations(self) -> None:
        """Remove every reservation that was not completed by a step."""
        for reservation in list(self._reservations.values()):
            self.discard_reservation(reservation)

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
                "size_bytes": art.size_bytes,
                "truncated_bytes": art.truncated_bytes,
            }
            for art in self.artifacts
        ]

    def get_evidence_hashes(self) -> list[str]:
        """Return list of canonical SHA256 hashes for all recorded evidence entries."""
        return [digest(record) for record in self.evidence_records]
