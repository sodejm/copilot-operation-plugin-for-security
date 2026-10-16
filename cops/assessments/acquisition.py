"""Registered, bounded acquisition of regular files from disposable laboratories.

This adapter copies evidence; it does not acquire native disks, memory, or EVTX.
Every path component is opened relative to a directory descriptor without
following symlinks. Reports contain opaque identities rather than local paths.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from cops.evidence.canonical import EvidenceError, timestamp
from cops.evidence.files import file_identity, open_parent, open_root, relative_parts

ADAPTER_ID = "disposable-file-acquisition@1"
ADAPTERS = {ADAPTER_ID: {"platform": "posix", "prerequisite": "python-stdlib", "version": 1, "scope": "disposable-laboratory-regular-file"}}
_IDENTIFIER = re.compile(r"[a-zA-Z0-9_.:-]{1,96}\Z")


class AcquisitionError(ValueError):
    """Content-free rejection of an unsupported or unsafe acquisition."""


def _parts(value: str) -> tuple[str, ...]:
    try:
        return relative_parts(value)
    except ValueError as exc:
        raise AcquisitionError("invalid_relative_path") from exc


def acquire_disposable_file(
    *, adapter_id: str, lab_root: Path, source_relative: str, output_relative: str,
    expected_sha256: str, source_ref: str, actor_ref: str, collected_at: str,
    collection_authorized: bool, disposable_lab: bool, kind: str = "disk_image",
    max_bytes: int = 1_048_576,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Copy a pinned lab source exclusively and return an artifact plus receipt."""
    if adapter_id not in ADAPTERS or os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionError("unsupported_acquisition_adapter_or_platform")
    if collection_authorized is not True or disposable_lab is not True:
        raise AcquisitionError("disposable_collection_authorization_required")
    if kind not in {"disk_image", "memory_image"}:
        raise AcquisitionError("unsupported_acquisition_kind")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1_048_576:
        raise AcquisitionError("invalid_acquisition_budget")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise AcquisitionError("expected_source_hash_required")
    if any(not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) for value in (source_ref, actor_ref)):
        raise AcquisitionError("opaque_source_and_actor_required")
    try:
        timestamp(collected_at)
    except EvidenceError as exc:
        raise AcquisitionError("collection_timestamp_required") from exc
    source_parts, output_parts = _parts(source_relative), _parts(output_relative)
    if source_parts == output_parts:
        raise AcquisitionError("source_and_output_must_differ")
    root = Path(lab_root).absolute()
    created = False
    output_parent = -1
    try:
        with ExitStack() as stack:
            root_fd = open_root(root, stack)
            source_parent = open_parent(root_fd, source_parts, stack)
            output_parent = open_parent(root_fd, output_parts, stack)
            source_fd = os.open(source_parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_parent)
            stack.callback(os.close, source_fd)
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise AcquisitionError("source_type_or_size_unsupported")
            chunks: list[bytes] = []
            count = 0
            while True:
                chunk = os.read(source_fd, min(65_536, max_bytes + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                if count > max_bytes:
                    raise AcquisitionError("source_size_limit")
            raw = b"".join(chunks)
            after = os.fstat(source_fd)
            if (file_identity(before) != file_identity(after) or
                    file_identity(before) != file_identity(os.stat(source_parts[-1], dir_fd=source_parent, follow_symlinks=False)) or
                    hashlib.sha256(raw).hexdigest() != expected_sha256):
                raise AcquisitionError("source_changed_or_hash_mismatch")
            output_fd = os.open(output_parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=output_parent)
            created = True
            try:
                with os.fdopen(output_fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                if (file_identity(before) != file_identity(os.fstat(source_fd)) or
                        file_identity(before) != file_identity(os.stat(source_parts[-1], dir_fd=source_parent, follow_symlinks=False))):
                    raise AcquisitionError("source_changed_during_collection")
            except BaseException:
                os.unlink(output_parts[-1], dir_fd=output_parent)
                created = False
                raise
    except (OSError, ValueError) as exc:
        if isinstance(exc, AcquisitionError):
            raise
        # The partial file is removed inside the still-open directory context.
        raise AcquisitionError("source_or_destination_unavailable") from exc
    artifact = {
        "artifact_id": "acquired-lab-evidence", "kind": kind, "content": raw,
        "source_ref": source_ref, "sha256": expected_sha256, "collected_at": collected_at,
        "collection_authorized": True,
        "custody": [{"at": collected_at, "actor_ref": actor_ref, "action": "acquire"}],
    }
    receipt = {"schema_version": "cops.lab-acquisition-receipt/v1", "adapter_id": adapter_id,
               "source_ref": source_ref, "sha256": expected_sha256, "bytes": len(raw),
               "collected_at": collected_at, "original_unchanged": True, "exclusive_copy": created}
    return artifact, receipt
