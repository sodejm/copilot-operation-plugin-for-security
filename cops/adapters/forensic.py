"""Read-only integrity import for raw images; no filesystem or memory parsing."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from cops.evidence.canonical import EvidenceError, decode_json, digest, timestamp
from cops.evidence.files import file_identity, open_parent, open_root, relative_parts

from .artifacts import artifact_adapter

ADAPTER_ID = "raw-forensic-image/v1"
MAX_BYTES = 128 * 1024 * 1024
_IDENTIFIER = re.compile(r"[a-zA-Z0-9_.:-]{1,96}\Z")
_FIELDS = {"schema_version", "artifact_id", "source_relative", "kind", "format", "sha256",
           "source_ref", "authorization_ref", "collection_authorized", "collected_at", "as_of", "custody"}


class ForensicImportError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def load_forensic_manifest(path: Path) -> dict[str, Any]:
    """Read bounded metadata without following links or blocking on a pipe."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ForensicImportError("unsupported_forensic_platform")
    path = Path(path).absolute()
    try:
        with ExitStack() as stack:
            parent = open_root(path.parent, stack)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 65_536:
                raise ForensicImportError("manifest_type_or_size_unsupported")
            raw = bytearray()
            while chunk := os.read(fd, 65_537 - len(raw)):
                raw.extend(chunk)
                if len(raw) > 65_536:
                    raise ForensicImportError("manifest_size_limit")
            if (file_identity(before) != file_identity(os.fstat(fd)) or
                    file_identity(before) != file_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
                raise ForensicImportError("manifest_changed")
            manifest = decode_json(bytes(raw), max_bytes=65_536)
            if type(manifest) is not dict:
                raise ForensicImportError("invalid_forensic_manifest")
            return manifest
    except (OSError, ValueError) as exc:
        if isinstance(exc, ForensicImportError):
            raise
        raise ForensicImportError("manifest_unavailable_or_invalid") from exc


def _validate(manifest: dict[str, Any], max_bytes: int) -> tuple[str, ...]:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES:
        raise ForensicImportError("invalid_forensic_budget")
    if type(manifest) is not dict or set(manifest) != _FIELDS:
        raise ForensicImportError("invalid_forensic_manifest")
    if manifest["schema_version"] != "cops.forensic-import-input/v1":
        raise ForensicImportError("unsupported_forensic_contract")
    if manifest["kind"] not in ("disk_image", "memory_image") or manifest["format"] != "raw":
        raise ForensicImportError("unsupported_forensic_format")
    if manifest["collection_authorized"] is not True:
        raise ForensicImportError("collection_authorization_required")
    for field in ("artifact_id", "source_ref", "authorization_ref"):
        if not isinstance(manifest[field], str) or not _IDENTIFIER.fullmatch(manifest[field]):
            raise ForensicImportError("opaque_forensic_reference_required")
    expected = manifest["sha256"]
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ForensicImportError("expected_source_hash_required")
    try:
        collected, as_of = timestamp(manifest["collected_at"]), timestamp(manifest["as_of"])
        if collected > as_of:
            raise ForensicImportError("invalid_collection_time")
        custody = manifest["custody"]
        if type(custody) is not list or not 1 <= len(custody) <= 128:
            raise ForensicImportError("custody_required")
        previous = collected
        for index, event in enumerate(custody):
            if type(event) is not dict or set(event) != {"actor_ref", "action", "at", "sha256"}:
                raise ForensicImportError("invalid_custody_event")
            if not isinstance(event["actor_ref"], str) or not _IDENTIFIER.fullmatch(event["actor_ref"]):
                raise ForensicImportError("invalid_custody_actor")
            if event["sha256"] != expected or event["action"] not in (("acquire",) if index == 0 else ("transfer", "verify")):
                raise ForensicImportError("unbound_custody_event")
            at = timestamp(event["at"])
            if not previous <= at <= as_of or (index == 0 and at != collected):
                raise ForensicImportError("invalid_custody_time")
            previous = at
        return relative_parts(manifest["source_relative"])
    except EvidenceError as exc:
        raise ForensicImportError("invalid_forensic_timestamp") from exc
    except ValueError as exc:
        if isinstance(exc, ForensicImportError):
            raise
        raise ForensicImportError("invalid_relative_path") from exc


def import_forensic_image(root: Path, manifest: dict[str, Any], *, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """Stream a pinned regular file, returning integrity evidence without bytes or paths."""
    adapter = artifact_adapter(ADAPTER_ID)
    parts = _validate(manifest, max_bytes)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ForensicImportError("unsupported_forensic_platform")
    try:
        with ExitStack() as stack:
            root_fd = open_root(root, stack)
            parent = open_parent(root_fd, parts, stack)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= max_bytes:
                raise ForensicImportError("source_type_or_size_unsupported")
            hasher = hashlib.sha256()
            count = 0
            while chunk := os.read(fd, min(65_536, max_bytes + 1 - count)):
                count += len(chunk)
                if count > max_bytes:
                    raise ForensicImportError("source_size_limit")
                hasher.update(chunk)
            # Check both the held descriptor and the directory entry so a replaced
            # pathname cannot be reported as the originally opened source.
            if (file_identity(before) != file_identity(os.fstat(fd)) or
                    file_identity(before) != file_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) or
                    count != before.st_size or hasher.hexdigest() != manifest["sha256"]):
                raise ForensicImportError("source_changed_or_hash_mismatch")
    except (OSError, ValueError) as exc:
        if isinstance(exc, ForensicImportError):
            raise
        raise ForensicImportError("source_unavailable") from exc
    return {
        "schema_version": "cops.forensic-import/v1", "adapter_id": adapter.adapter_id,
        "artifact_id": manifest["artifact_id"], "kind": manifest["kind"], "format": "raw",
        "integrity": "verified", "analysis": "not_performed",
        "source": {"source_ref": manifest["source_ref"], "sha256": hasher.hexdigest(), "bytes": count,
                   "collected_at": manifest["collected_at"], "as_of": manifest["as_of"]},
        "authorization": {"reference": manifest["authorization_ref"], "verification": "caller_asserted"},
        "custody": {"sha256": digest(manifest["custody"]), "events": len(manifest["custody"]),
                   "verification": "ordered_digest_bound_assertions"},
        "limitations": ["Integrity matches caller-supplied metadata; identity and custody authenticity are not established.",
                        "No filesystem, memory, malware or native acquisition analysis was performed.",
                        "Only bounded raw regular files are supported; E01, AFF4, compressed images and device capture require separate adapters."],
    }
