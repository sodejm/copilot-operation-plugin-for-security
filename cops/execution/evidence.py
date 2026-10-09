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
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from cops.evidence.canonical import canonical, digest
from cops.evidence.contract import build_envelope

from .cleanup import CleanupError, CleanupManager, SideEffect
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


class EvidenceCleanupError(EvidenceCaptureError):
    """An evidence capture failed and an artifact could not be removed."""


@dataclass(frozen=True)
class EvidenceContext:
    """Approval and plan provenance attached to every execution evidence record."""

    plan_id: str
    plan_digest: str
    authorization_id: str
    engagement_id: str
    worker_identity: str
    target: str

    def __post_init__(self) -> None:
        identifiers = {
            "plan_id": self.plan_id,
            "authorization_id": self.authorization_id,
            "engagement_id": self.engagement_id,
            "worker_identity": self.worker_identity,
            "target": self.target,
        }
        for field_name, value in identifiers.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"evidence {field_name} must be a non-empty string")
        if not isinstance(self.plan_digest, str) or re.fullmatch(r"[0-9a-f]{64}", self.plan_digest) is None:
            raise ValueError("evidence plan_digest must be a lowercase SHA256 digest")


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
        *,
        portable_inert: bool = False,
        context: EvidenceContext | None = None,
        ephemeral_workspace: bool = False,
        cleanup_manager: CleanupManager | None = None,
    ) -> None:
        self.workspace_dir = Path(workspace_dir)
        self.redactor = redactor or StreamRedactor()
        self.portable_inert = portable_inert
        self.ephemeral_workspace = ephemeral_workspace
        if portable_inert and cleanup_manager is not None:
            raise ValueError("portable inert evidence does not support durable cleanup tracking")
        self._cleanup_manager = cleanup_manager
        if context is None:
            if not portable_inert:
                raise ValueError("complete evidence context is required for executable operations")
            context = EvidenceContext(
                plan_id="portable-inert-plan",
                plan_digest=hashlib.sha256(b"portable-inert-plan").hexdigest(),
                authorization_id="portable-inert-authorization",
                engagement_id="portable-inert-engagement",
                worker_identity="portable-inert-worker",
                target="portable-inert-target",
            )
        self.context = context
        self.artifacts: list[CapturedArtifact] = []
        self.step_telemetry: list[StepTelemetry] = []
        self.evidence_records: list[dict[str, Any]] = []
        self._reservations: dict[str, ArtifactReservation] = {}
        self._reservation_handles: dict[str, BinaryIO] = {}
        self._reservation_dirs: dict[str, tuple[int, int]] = {}
        self._reservation_effects: dict[str, SideEffect] = {}
        self._artifact_directory_effect: SideEffect | None = None

    def reserve_step_output(self, step_id: str) -> ArtifactReservation:
        """Reserve a unique evidence inode before executing a step."""
        return self._reserve_artifact(step_id, "output.txt")

    def _reserve_artifact(self, step_id: str, suffix: str) -> ArtifactReservation:
        """Reserve a private inode for either output or its evidence envelope."""
        if self.portable_inert:
            return self._reserve_portable_artifact(step_id, suffix)

        clean_step_id = re.sub(r"[^a-zA-Z0-9_-]", "_", step_id)
        workspace_fd = -1
        artifacts_fd = -1
        artifact_fd = -1
        filename: str | None = None
        artifact_effect: SideEffect | None = None
        try:
            nofollow, directory = self._required_posix_flags()
            workspace_fd = open_directory_no_symlinks(self.workspace_dir)
            self._validate_private_directory(workspace_fd, "worker workspace")
            if self._cleanup_manager is not None and self._artifact_directory_effect is None:
                directory_effect = self._cleanup_manager.ledger.record_effect(
                    step_id=f"{clean_step_id}-evidence-artifacts",
                    resource_type="directory",
                    target=str(self._absolute_artifact_path("artifacts")),
                    cleanup_action="delete",
                    metadata={"purpose": "execution_evidence_artifacts"},
                )
                # A tracked directory must be created exclusively. Treating a
                # pre-existing path as worker-owned would permit cleanup of an
                # object for which this run never held a creation descriptor.
                os.mkdir("artifacts", mode=0o700, dir_fd=workspace_fd)
            else:
                directory_effect = self._artifact_directory_effect
                try:
                    os.mkdir("artifacts", mode=0o700, dir_fd=workspace_fd)
                except FileExistsError:
                    pass
            artifacts_fd = os.open("artifacts", os.O_RDONLY | directory | nofollow, dir_fd=workspace_fd)
            if directory_effect is not None and directory_effect.creation_identity is None:
                self._cleanup_manager.ledger.record_created_identity(
                    directory_effect,
                    creation_fd=artifacts_fd,
                )
                self._artifact_directory_effect = directory_effect
            self._validate_private_directory(
                artifacts_fd,
                "evidence artifact directory",
                require_owner_private=True,
            )

            base_name = f"{clean_step_id}_{suffix}"
            for attempt in range(16):
                candidate = base_name if attempt == 0 else f"{clean_step_id}_{uuid.uuid4().hex}_{suffix}"
                try:
                    os.stat(candidate, dir_fd=artifacts_fd, follow_symlinks=False)
                except FileNotFoundError:
                    filename = candidate
                    break
                else:
                    continue
            if filename is None:
                raise EvidenceCaptureError("secure evidence artifact reservation could not choose a unique name")

            if self._cleanup_manager is not None:
                artifact_effect = self._cleanup_manager.ledger.record_effect(
                    step_id=f"{clean_step_id}-evidence-{suffix}",
                    resource_type="file",
                    target=str(self._absolute_artifact_path("artifacts", filename)),
                    cleanup_action="delete",
                    metadata={"purpose": "execution_evidence_artifact"},
                )
            artifact_fd = os.open(
                filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=artifacts_fd,
            )

            info = os.fstat(artifact_fd)
            self._validate_private_file(info)
            if artifact_effect is not None:
                self._cleanup_manager.ledger.record_created_identity(
                    artifact_effect,
                    creation_fd=artifact_fd,
                )
            reservation = ArtifactReservation(
                name=filename,
                path=f"artifacts/{filename}",
                device=info.st_dev,
                inode=info.st_ino,
            )
            # Keep the inode allocated until capture or discard. Otherwise an
            # attacker can replace the path and receive the same inode number.
            handle = os.fdopen(artifact_fd, "wb", buffering=0)
            artifact_fd = -1
            self._reservations[reservation.path] = reservation
            self._reservation_handles[reservation.path] = handle
            self._reservation_dirs[reservation.path] = (workspace_fd, artifacts_fd)
            if artifact_effect is not None:
                self._reservation_effects[reservation.path] = artifact_effect
            workspace_fd = -1
            artifacts_fd = -1
            return reservation
        except EvidenceCaptureError:
            if artifact_effect is not None:
                self._cleanup_failed_effect(artifact_effect)
            elif filename is not None and artifacts_fd >= 0:
                try:
                    os.unlink(filename, dir_fd=artifacts_fd)
                except OSError:
                    pass
            raise
        except OSError as err:
            if artifact_effect is not None:
                self._cleanup_failed_effect(artifact_effect)
            elif filename is not None and artifacts_fd >= 0:
                try:
                    os.unlink(filename, dir_fd=artifacts_fd)
                except OSError:
                    pass
            raise EvidenceCaptureError("secure evidence artifact reservation failed") from err
        except CleanupError as err:
            if artifact_effect is not None:
                self._cleanup_failed_effect(artifact_effect)
            raise EvidenceCaptureError("durable evidence ownership tracking failed") from err
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
        tool_version: str = "unknown",
        error: bytes = b"",
        artifact_outputs: Mapping[str | bytes, bytes] | None = None,
        max_output_bytes: int | None = None,
        reservation: ArtifactReservation | None = None,
    ) -> tuple[bytes, CapturedArtifact]:
        """Validate redacted evidence before any operation output is persisted.

        Raw stream and artifact values remain in memory only long enough to be
        redacted.  The evidence envelope stores redacted values or their hashes;
        a redaction or envelope validation failure discards the reservation.
        """
        if self.portable_inert and tool != "inert":
            raise EvidenceCaptureError("portable evidence mode is restricted to inert operations")
        if (
            not isinstance(tool_version, str)
            or not tool_version.strip()
            or (not self.portable_inert and tool_version == "unknown")
        ):
            raise EvidenceCaptureError("tool version is required for executable operation evidence")
        if max_output_bytes is not None and max_output_bytes < 0:
            raise ValueError("max_output_bytes must be non-negative")
        if reservation is None:
            reservation = self.reserve_step_output(step_id)
        if self._reservations.get(reservation.path) != reservation:
            raise EvidenceCaptureError("evidence artifact reservation is not active")
        try:
            combined_output = stdout + (b"\n" if stdout and stderr else b"") + stderr
            redacted_stdout = self.redactor.redact_bytes(stdout)
            redacted_stderr = self.redactor.redact_bytes(stderr)
            redacted_error = self.redactor.redact_bytes(error)
            redacted_action = self.redactor.redact_string(action)
            redacted_artifacts: list[dict[str, Any]] = []
            for raw_path, raw_content in (artifact_outputs or {}).items():
                if isinstance(raw_path, str):
                    raw_path_text = raw_path
                    raw_path_bytes = raw_path.encode("utf-8")
                elif isinstance(raw_path, bytes):
                    raw_path_bytes = raw_path
                    raw_path_text = raw_path.decode("utf-8")
                else:
                    raise TypeError("artifact path must be text or bytes")
                if not isinstance(raw_content, bytes):
                    raise TypeError("artifact content must be bytes")
                _canonical_artifact_identifier(raw_path_text)
                redacted_path = self.redactor.redact_bytes(raw_path_bytes).decode("utf-8")
                redacted_path = _canonical_artifact_identifier(redacted_path)
                redacted_content = self.redactor.redact_bytes(raw_content)
                redacted_artifacts.append(
                    {
                        "path": redacted_path,
                        "content_sha256": hashlib.sha256(redacted_content).hexdigest(),
                        "size_bytes": len(redacted_content),
                    }
                )

            redacted_full = self.redactor.redact_bytes(combined_output)
            redacted_characters = sum(
                max(0, len(raw_value) - len(redacted_value))
                for raw_value, redacted_value in (
                    (combined_output, redacted_full),
                    (error, redacted_error),
                )
            )
            redacted_bytes = redacted_full
            if max_output_bytes is not None:
                redacted_bytes = redacted_bytes[:max_output_bytes]

            truncated_bytes = len(redacted_full) - len(redacted_bytes)
            artifact_sha256 = hashlib.sha256(redacted_bytes).hexdigest()
            context = self.context
            evidence_entry = build_envelope(
                acquisition_id=f"execution:{context.authorization_id}",
                product="cops-worker",
                api="execution",
                tenant=context.engagement_id,
                scope=[context.target],
                identity=context.worker_identity,
                locator=f"plan:{context.plan_id}/step:{step_id}",
                payload={
                    "provenance": {
                        "plan_id": context.plan_id,
                        "plan_digest": context.plan_digest,
                        "authorization_id": context.authorization_id,
                        "engagement_id": context.engagement_id,
                        "worker_identity": context.worker_identity,
                        "target": context.target,
                        "step_id": step_id,
                        "tool": tool,
                        "tool_version": tool_version,
                        "action": redacted_action,
                    },
                    "streams": {
                        "stdout": _redacted_stream_metadata(redacted_stdout),
                        "stderr": _redacted_stream_metadata(redacted_stderr),
                        "error": _redacted_stream_metadata(redacted_error),
                    },
                    "artifacts": redacted_artifacts,
                    "result": {
                        "artifact_sha256": artifact_sha256,
                        "artifact_size_bytes": len(redacted_bytes),
                        "artifact_truncated_bytes": truncated_bytes,
                        "exit_code": exit_code,
                    },
                    "trust": {
                        "classification": "untrusted",
                        "instruction_handling": "data_only",
                    },
                    "lifecycle": {
                        "raw": {
                            "storage": "memory_only",
                            "persistence": "prohibited",
                            "retained": False,
                            "persistence_gate": "redaction_and_schema_validation",
                        },
                        "redacted": {
                            "storage": (
                                "worker_ephemeral_workspace" if self.ephemeral_workspace else "owner_only_workspace"
                            ),
                            "directory_mode": "0700",
                            "file_mode": "0600",
                            "retention_controller": (
                                "worker"
                                if self.ephemeral_workspace and not self.portable_inert
                                else "workspace_owner"
                            ),
                            "automatic_deletion": self.ephemeral_workspace and not self.portable_inert,
                        },
                    },
                },
                acquired_at=finished_at,
                transformed_at=finished_at,
                observed_at=finished_at,
                emitted_at=finished_at,
                request_fingerprint=context.plan_digest,
                page=1,
                source_version=tool_version,
                raw_reference=None,
            )
            # Canonical bytes are the exact artifact bytes and the bytes hashed
            # into the RunResult. The contract also bounds each envelope to 1 MiB.
            envelope_bytes = canonical(evidence_entry)

        except BaseException as error:
            removed = self.discard_reservation(reservation)
            if not removed:
                raise EvidenceCleanupError("evidence cleanup failed; a residual artifact may remain") from None
            if not isinstance(error, Exception):
                raise
            raise EvidenceCaptureError("evidence redaction or validation failed") from None
        # Persist both artifacts as one capture operation. A failed second write
        # removes the already-written output through its held inode.
        envelope_reservation: ArtifactReservation | None = None
        try:
            envelope_reservation = self._reserve_artifact(step_id, "evidence.json")
            self._write_reserved_artifact(reservation, redacted_bytes)
            self._write_reserved_artifact(envelope_reservation, envelope_bytes)
        except BaseException:
            removed_output = self.discard_reservation(reservation)
            removed_envelope = (
                self.discard_reservation(envelope_reservation) if envelope_reservation is not None else True
            )
            if not (removed_output and removed_envelope):
                raise EvidenceCleanupError("evidence cleanup failed; a residual artifact may remain") from None
            raise
        self._complete_reservation(reservation)
        self._complete_reservation(envelope_reservation)

        artifact = CapturedArtifact(
            name=reservation.name,
            path=reservation.path,
            sha256=artifact_sha256,
            size_bytes=len(redacted_bytes),
            truncated_bytes=truncated_bytes,
        )
        self.artifacts.append(artifact)
        self.artifacts.append(
            CapturedArtifact(
                name=envelope_reservation.name,
                path=envelope_reservation.path,
                sha256=hashlib.sha256(envelope_bytes).hexdigest(),
                size_bytes=len(envelope_bytes),
            )
        )

        telemetry = StepTelemetry(
            step_id=step_id,
            tool=tool,
            action=redacted_action,
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
            stdout_sha256=digest(redacted_stdout.decode("utf-8", errors="replace")),
            stderr_sha256=digest(redacted_stderr.decode("utf-8", errors="replace")),
            output_length=len(redacted_bytes),
            redacted_characters=redacted_characters,
            truncated_bytes=truncated_bytes,
        )
        self.step_telemetry.append(telemetry)

        self.evidence_records.append(evidence_entry)

        return redacted_bytes, artifact

    def _complete_reservation(self, reservation: ArtifactReservation) -> None:
        """Release descriptors only after the artifact has been fully persisted."""
        self._reservations.pop(reservation.path)
        self._reservation_effects.pop(reservation.path, None)
        self._reservation_handles.pop(reservation.path).close()
        held_dirs = self._reservation_dirs.pop(reservation.path, None)
        if held_dirs is not None:
            for fd in held_dirs:
                os.close(fd)

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
        if self.portable_inert:
            self._write_portable_reserved_artifact(reservation, content)
            return

        handle = self._reservation_handles.get(reservation.path)
        held_dirs = self._reservation_dirs.get(reservation.path)
        if handle is None or held_dirs is None:
            raise EvidenceCaptureError("evidence artifact reservation is not active")
        workspace_fd, artifacts_fd = held_dirs
        try:
            self._verify_reserved_path(reservation, workspace_fd, artifacts_fd, handle)
            os.ftruncate(handle.fileno(), 0)
            view = memoryview(content)
            while view:
                written = os.write(handle.fileno(), view)
                view = view[written:]
            os.fsync(handle.fileno())
            self._verify_reserved_path(reservation, workspace_fd, artifacts_fd, handle)
        except OSError as err:
            raise EvidenceCaptureError("secure evidence artifact write failed") from err

    def _verify_reserved_path(
        self,
        reservation: ArtifactReservation,
        workspace_fd: int,
        artifacts_fd: int,
        handle: BinaryIO,
    ) -> None:
        """Confirm every advertised path component still names its held inode."""
        current_workspace_fd = open_directory_no_symlinks(self.workspace_dir)
        try:
            current_workspace = os.fstat(current_workspace_fd)
            held_workspace = os.fstat(workspace_fd)
            if (current_workspace.st_dev, current_workspace.st_ino) != (
                held_workspace.st_dev,
                held_workspace.st_ino,
            ):
                raise EvidenceCaptureError("evidence workspace identity changed")
        finally:
            os.close(current_workspace_fd)
        self._validate_private_directory(workspace_fd, "worker workspace")
        self._validate_private_directory(
            artifacts_fd,
            "evidence artifact directory",
            require_owner_private=True,
        )
        current_artifacts = os.stat("artifacts", dir_fd=workspace_fd, follow_symlinks=False)
        held_artifacts = os.fstat(artifacts_fd)
        if (current_artifacts.st_dev, current_artifacts.st_ino) != (
            held_artifacts.st_dev,
            held_artifacts.st_ino,
        ):
            raise EvidenceCaptureError("evidence artifact directory identity changed")
        held_file = os.fstat(handle.fileno())
        path_file = os.stat(reservation.name, dir_fd=artifacts_fd, follow_symlinks=False)
        self._validate_private_file(held_file)
        if (held_file.st_dev, held_file.st_ino) != (reservation.device, reservation.inode) or (
            path_file.st_dev,
            path_file.st_ino,
        ) != (reservation.device, reservation.inode):
            raise EvidenceCaptureError("evidence artifact reservation identity changed")

    def discard_reservation(self, reservation: ArtifactReservation) -> bool:
        """Remove an unused reservation; report when removal is not confirmed."""
        if self._reservations.pop(reservation.path, None) != reservation:
            return False
        effect = self._reservation_effects.pop(reservation.path, None)
        held_handle = self._reservation_handles.pop(reservation.path, None)
        if self.portable_inert:
            return self._discard_portable_reservation(reservation, held_handle)

        held_dirs = self._reservation_dirs.pop(reservation.path, None)
        if effect is not None:
            descriptors_closed = True
            if held_handle is not None:
                try:
                    held_handle.close()
                except OSError:
                    descriptors_closed = False
            if held_dirs is not None:
                for fd in held_dirs:
                    try:
                        os.close(fd)
                    except OSError:
                        descriptors_closed = False
            if not descriptors_closed or self._cleanup_manager is None:
                return False
            try:
                self._cleanup_manager.cleanup_effect(effect)
            except CleanupError:
                return False
            return True

        removed = False
        try:
            if held_dirs is not None:
                artifacts_fd = held_dirs[1]
                try:
                    info = os.stat(reservation.name, dir_fd=artifacts_fd, follow_symlinks=False)
                except FileNotFoundError:
                    removed = True
                else:
                    if (info.st_dev, info.st_ino) == (reservation.device, reservation.inode):
                        os.unlink(reservation.name, dir_fd=artifacts_fd)
                        removed = True
        except (OSError, EvidenceCaptureError):
            pass
        finally:
            if held_dirs is not None:
                for fd in held_dirs:
                    try:
                        os.close(fd)
                    except OSError:
                        removed = False
            if held_handle is not None:
                try:
                    held_handle.close()
                except OSError:
                    removed = False
        return removed

    def _absolute_artifact_path(self, *parts: str) -> Path:
        return Path(os.path.abspath(os.fspath(self.workspace_dir.joinpath(*parts))))

    def _cleanup_failed_effect(self, effect: SideEffect) -> None:
        """Best-effort verified cleanup for a reservation that did not complete."""
        if self._cleanup_manager is None:
            return
        try:
            if effect.status == "pending":
                self._cleanup_manager.cleanup_effect(effect)
        except CleanupError:
            # The manager has durably classified missing, unverified, or
            # replaced resources as unknown/failed. Do not bypass it by name.
            pass

    def _reserve_portable_artifact(self, step_id: str, suffix: str) -> ArtifactReservation:
        """Reserve an inert artifact without relying on POSIX directory descriptors."""
        clean_step_id = re.sub(r"[^a-zA-Z0-9_-]", "_", step_id)
        artifacts_dir = self.workspace_dir / "artifacts"
        artifact_fd = -1
        artifact_path: Path | None = None
        created_info: os.stat_result | None = None
        try:
            self._validate_portable_directory(self.workspace_dir, "worker workspace")
            try:
                artifacts_dir.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self._validate_portable_directory(
                artifacts_dir,
                "evidence artifact directory",
                require_owner_private=True,
            )

            base_name = f"{clean_step_id}_{suffix}"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOINHERIT", 0)
            for attempt in range(16):
                candidate = base_name if attempt == 0 else f"{clean_step_id}_{uuid.uuid4().hex}_{suffix}"
                artifact_path = artifacts_dir / candidate
                try:
                    artifact_fd = os.open(artifact_path, flags, 0o600)
                except FileExistsError:
                    continue
                break
            if artifact_fd < 0 or artifact_path is None:
                raise EvidenceCaptureError("secure evidence artifact reservation could not choose a unique name")

            created_info = os.fstat(artifact_fd)
            self._validate_portable_file(created_info)
            reservation = ArtifactReservation(
                name=artifact_path.name,
                path=f"artifacts/{artifact_path.name}",
                device=created_info.st_dev,
                inode=created_info.st_ino,
            )
            handle = os.fdopen(artifact_fd, "wb", buffering=0)
            artifact_fd = -1
            self._reservations[reservation.path] = reservation
            self._reservation_handles[reservation.path] = handle
            return reservation
        except EvidenceCaptureError:
            if artifact_fd >= 0:
                os.close(artifact_fd)
                artifact_fd = -1
            self._remove_matching_portable_path(artifact_path, created_info)
            raise
        except OSError as err:
            if artifact_fd >= 0:
                os.close(artifact_fd)
                artifact_fd = -1
            self._remove_matching_portable_path(artifact_path, created_info)
            raise EvidenceCaptureError("secure evidence artifact reservation failed") from err
        finally:
            if artifact_fd >= 0:
                os.close(artifact_fd)

    def _write_portable_reserved_artifact(
        self,
        reservation: ArtifactReservation,
        content: bytes,
    ) -> None:
        """Write inert evidence through its held handle after portable identity checks."""
        handle = self._reservation_handles.get(reservation.path)
        if handle is None:
            raise EvidenceCaptureError("evidence artifact reservation is not active")
        artifact_path = self.workspace_dir / reservation.path
        try:
            self._validate_portable_directory(self.workspace_dir, "worker workspace")
            self._validate_portable_directory(
                artifact_path.parent,
                "evidence artifact directory",
                require_owner_private=True,
            )
            held_info = os.fstat(handle.fileno())
            self._validate_portable_file(held_info)
            if not self._matches_reservation(held_info, reservation):
                raise EvidenceCaptureError("evidence artifact reservation identity changed")
            path_info = os.lstat(artifact_path)
            self._validate_portable_file(path_info)
            if not self._matches_reservation(path_info, reservation):
                raise EvidenceCaptureError("evidence artifact reservation identity changed")

            handle.seek(0)
            handle.truncate(0)
            view = memoryview(content)
            while view:
                written = handle.write(view)
                if not written:
                    raise EvidenceCaptureError("secure evidence artifact write made no progress")
                view = view[written:]
            handle.flush()
            os.fsync(handle.fileno())

            final_info = os.lstat(artifact_path)
            self._validate_portable_file(final_info)
            if not self._matches_reservation(final_info, reservation):
                raise EvidenceCaptureError("evidence artifact reservation identity changed")
        except EvidenceCaptureError:
            raise
        except OSError as err:
            raise EvidenceCaptureError("secure evidence artifact write failed") from err

    def _discard_portable_reservation(
        self,
        reservation: ArtifactReservation,
        held_handle: BinaryIO | None,
    ) -> bool:
        """Close a portable reservation and remove only its unchanged pathname."""
        artifact_path = self.workspace_dir / reservation.path
        removed = False
        close_failed = False
        if held_handle is not None:
            try:
                held_handle.close()
            except OSError:
                close_failed = True
        try:
            try:
                path_info = os.lstat(artifact_path)
            except FileNotFoundError:
                removed = True
            else:
                if not self._is_symlink_or_reparse(path_info) and self._matches_reservation(path_info, reservation):
                    path_info = os.lstat(artifact_path)
                    if not self._is_symlink_or_reparse(path_info) and self._matches_reservation(path_info, reservation):
                        artifact_path.unlink()
                        removed = True
        except OSError:
            pass
        return removed and not close_failed

    @classmethod
    def _remove_matching_portable_path(
        cls,
        artifact_path: Path | None,
        created_info: os.stat_result | None,
    ) -> None:
        if artifact_path is None or created_info is None:
            return
        try:
            path_info = os.lstat(artifact_path)
            if cls._is_symlink_or_reparse(path_info):
                return
            if cls._matching_identity(path_info, created_info.st_dev, created_info.st_ino):
                artifact_path.unlink()
        except OSError:
            pass

    @classmethod
    def _validate_portable_directory(
        cls,
        path: Path,
        label: str,
        *,
        require_owner_private: bool = False,
    ) -> None:
        try:
            info = os.lstat(path)
        except OSError as err:
            raise EvidenceCaptureError(f"{label} is unavailable") from err
        if cls._is_symlink_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise EvidenceCaptureError(f"{label} is not a real directory")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise EvidenceCaptureError(f"{label} is not owned by the worker account")
        if os.name == "posix":
            if require_owner_private and stat.S_IMODE(info.st_mode) != 0o700:
                raise EvidenceCaptureError(f"{label} permissions must be exactly 0700")
            if not require_owner_private and info.st_mode & 0o022:
                raise EvidenceCaptureError(f"{label} is writable by group or other users")

    @classmethod
    def _validate_portable_file(cls, info: os.stat_result) -> None:
        if cls._is_symlink_or_reparse(info) or not stat.S_ISREG(info.st_mode):
            raise EvidenceCaptureError("evidence artifact is not a regular file")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise EvidenceCaptureError("evidence artifact is not owned by the worker account")
        if os.name == "posix" and info.st_mode & 0o077:
            raise EvidenceCaptureError("evidence artifact permissions are not private")

    @staticmethod
    def _is_symlink_or_reparse(info: os.stat_result) -> bool:
        if stat.S_ISLNK(info.st_mode):
            return True
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        file_attributes = getattr(info, "st_file_attributes", 0)
        return bool(reparse_flag and file_attributes & reparse_flag)

    @staticmethod
    def _matching_identity(info: os.stat_result, device: int, inode: int) -> bool:
        if device and info.st_dev and device != info.st_dev:
            return False
        if inode and info.st_ino and inode != info.st_ino:
            return False
        return True

    @classmethod
    def _matches_reservation(cls, info: os.stat_result, reservation: ArtifactReservation) -> bool:
        return cls._matching_identity(info, reservation.device, reservation.inode)

    def discard_pending_reservations(self) -> None:
        """Remove every reservation that was not completed by a step."""
        for reservation in list(self._reservations.values()):
            self.discard_reservation(reservation)

    @staticmethod
    def _validate_private_directory(
        fd: int,
        label: str,
        *,
        require_owner_private: bool = False,
    ) -> None:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise EvidenceCaptureError(f"{label} is not a directory")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise EvidenceCaptureError(f"{label} is not owned by the worker account")
        if require_owner_private and stat.S_IMODE(info.st_mode) != 0o700:
            raise EvidenceCaptureError(f"{label} permissions must be exactly 0700")
        if not require_owner_private and info.st_mode & 0o022:
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


def _redacted_stream_metadata(value: bytes) -> dict[str, Any]:
    """Return non-reversible metadata for an already-redacted stream."""
    return {
        "sha256": hashlib.sha256(value).hexdigest(),
        "size_bytes": len(value),
    }


def _canonical_artifact_identifier(value: str) -> str:
    """Return a safe logical artifact identifier without host path details."""
    if not value or "\x00" in value:
        raise ValueError("artifact identifier is invalid")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError("artifact identifier must be workspace-relative")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("artifact identifier contains an unsafe path component")
    return "/".join(parts)
