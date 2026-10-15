"""Validate independently recorded native Windows bridge cleanup evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .core import (
    MAX_INPUT_BYTES,
    ContractError,
    _check_json_depth,
    _enum,
    _evidence_ids,
    _exact_keys,
    _object_pairs,
    _reject_constant,
    _token,
    assess_document,
)
from .windows import SURFACES

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _path_identity(value: Any, where: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ContractError(f"{where} must be a bounded absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ContractError(f"{where} must be an absolute path")
    return path


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(os.path.normpath(str(right)))


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)


def validate_windows_existing_path(path: Path, where: str) -> Path:
    """Reject remote drives and reparse ancestors before opening an existing path."""
    path = Path(path)
    if os.name != "nt":
        return path
    import ctypes

    raw = str(path)
    drive, tail = os.path.splitdrive(raw)
    if not drive or not tail.startswith(("\\", "/")) or raw.startswith(("\\\\", "//")):
        raise ContractError(f"{where} must be a fully qualified local drive path")
    components = re.split(r"[\\/]+", tail.lstrip("\\/"))
    if any(not component or component in {".", ".."} or ":" in component for component in components):
        raise ContractError(f"{where} must not contain relative or ambiguous path components")
    if ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") != 3:
        raise ContractError(f"{where} must be on a fixed drive")

    cursor = Path(f"{drive}\\")
    candidates = [cursor]
    for component in components:
        cursor /= component
        candidates.append(cursor)
    for candidate in candidates:
        try:
            if _is_reparse_point(candidate):
                raise ContractError(f"{where} traverses a reparse point")
        except FileNotFoundError as exc:
            raise ContractError(f"{where} must exist") from exc
        except OSError as exc:
            raise ContractError(f"{where} ancestry could not be validated") from exc
    return path


def load_bridge_receipt_bytes(data: bytes) -> dict[str, Any]:
    """Parse a bounded receipt while rejecting duplicate JSON keys."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ContractError("receipt must be at most 1 MiB of JSON bytes")
    _check_json_depth(data)
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("malformed UTF-8 receipt JSON") from exc
    except RecursionError as exc:
        raise ContractError("receipt JSON nesting exceeds parser limit") from exc
    if not isinstance(receipt, dict):
        raise ContractError("receipt must be a JSON object")
    return receipt


def validate_bridge_receipt(receipt: dict[str, Any], export_bytes: bytes, canary_root: Path) -> dict[str, Any]:
    """Bind cleanup evidence to one native export and verify no canary residue remains."""
    document = _exact_keys(
        receipt,
        {"schema_version", "platform", "bridge_mode", "export_sha256", "capabilities", "canary"},
        "receipt",
    )
    if document["schema_version"] != "windows-bridge-receipt-1.2":
        raise ContractError("unsupported bridge receipt schema version")
    _enum(document["platform"], {"windows"}, "receipt.platform")
    _enum(document["bridge_mode"], {"native_windows_bridge"}, "receipt.bridge_mode")
    digest = document["export_sha256"]
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise ContractError("receipt export hash must be lowercase SHA-256")
    if not isinstance(export_bytes, bytes) or hashlib.sha256(export_bytes).hexdigest() != digest:
        raise ContractError("receipt export hash does not match export bytes")
    if len(export_bytes) > MAX_INPUT_BYTES:
        raise ContractError("export must be at most 1 MiB of JSON bytes")
    _check_json_depth(export_bytes)

    raw_capabilities = document["capabilities"]
    if not isinstance(raw_capabilities, list) or len(raw_capabilities) > len(SURFACES):
        raise ContractError("receipt capabilities must be a bounded list")
    capabilities = [_enum(item, set(SURFACES), "receipt.capabilities") for item in raw_capabilities]
    if len(capabilities) != len(set(capabilities)):
        raise ContractError("receipt capabilities has duplicate surfaces")

    try:
        export = json.loads(
            export_bytes.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("malformed UTF-8 export JSON") from exc
    except RecursionError as exc:
        raise ContractError("export JSON nesting exceeds parser limit") from exc
    assessment = assess_document(export)
    if assessment["bridge"]["mode"] != "native_windows_bridge":
        raise ContractError("receipt requires a native Windows bridge export")
    if capabilities != assessment["bridge"]["capabilities"]:
        raise ContractError("receipt capabilities do not match export")

    raw_canary = _exact_keys(
        document["canary"],
        {
            "resource_id",
            "root_identity",
            "resource_identity",
            "ownership_sha256",
            "assessment_owned",
            "before_absent",
            "created",
            "ownership_verified",
            "removed",
            "cleanup_verified",
            "observer_kind",
            "before_observation",
            "after_create_observation",
            "after_cleanup_observation",
            "evidence_ids",
        },
        "receipt.canary",
    )
    for field in (
        "assessment_owned",
        "before_absent",
        "created",
        "ownership_verified",
        "removed",
        "cleanup_verified",
    ):
        if raw_canary[field] is not True:
            raise ContractError(f"receipt.canary.{field} must be asserted true")
    resource_id = _token(raw_canary["resource_id"], "receipt.canary.resource_id")
    root_identity = _path_identity(raw_canary["root_identity"], "receipt.canary.root_identity")
    resource_identity = _path_identity(raw_canary["resource_identity"], "receipt.canary.resource_identity")
    ownership_sha256 = raw_canary["ownership_sha256"]
    if not isinstance(ownership_sha256, str) or not SHA256_PATTERN.fullmatch(ownership_sha256):
        raise ContractError("receipt canary ownership hash must be lowercase SHA-256")
    observer_kind = _enum(
        raw_canary["observer_kind"],
        {"separate_same_token_process"},
        "receipt.canary.observer_kind",
    )
    before_observation = _enum(
        raw_canary["before_observation"], {"resource_absent"}, "receipt.canary.before_observation"
    )
    after_create_observation = _enum(
        raw_canary["after_create_observation"],
        {"readable_owned_marker"},
        "receipt.canary.after_create_observation",
    )
    after_cleanup_observation = _enum(
        raw_canary["after_cleanup_observation"],
        {"resource_absent"},
        "receipt.canary.after_cleanup_observation",
    )
    canary = {
        "resource_id": resource_id,
        "root_identity": str(root_identity),
        "resource_identity": str(resource_identity),
        "ownership_sha256": ownership_sha256,
        "assessment_owned": True,
        "before_absent": True,
        "created": True,
        "ownership_verified": True,
        "removed": True,
        "cleanup_verified": True,
        "observer_kind": observer_kind,
        "before_observation": before_observation,
        "after_create_observation": after_create_observation,
        "after_cleanup_observation": after_cleanup_observation,
        "evidence_ids": _evidence_ids(raw_canary["evidence_ids"], "receipt.canary.evidence_ids", minimum=7),
    }
    canary_root = validate_windows_existing_path(canary_root, "canary root")
    if not canary_root.is_dir():
        raise ContractError("canary root must be an existing directory")
    if _is_reparse_point(canary_root):
        raise ContractError("canary root cannot be a symlink or reparse point")
    try:
        canonical_root = canary_root.resolve(strict=True)
    except OSError as exc:
        raise ContractError("canary root identity cannot be resolved") from exc
    expected_resource = canonical_root / resource_id
    if not _same_path(root_identity, canonical_root):
        raise ContractError("receipt canary root identity does not match supplied root")
    if not _same_path(resource_identity, expected_resource):
        raise ContractError("receipt canary resource identity does not match supplied root")
    if not _same_path(resource_identity.parent, root_identity) or os.path.normcase(
        resource_identity.name
    ) != os.path.normcase(resource_id):
        raise ContractError("receipt canary resource identity is not an owned child")
    if expected_resource.exists() or expected_resource.is_symlink():
        raise ContractError("assessment-owned canary resource remains after cleanup")
    if next(canary_root.iterdir(), None) is not None:
        raise ContractError("canary root is not empty after cleanup")

    return {
        "schema_version": "windows-bridge-receipt-1.2",
        "platform": "windows",
        "bridge_mode": "native_windows_bridge",
        "export_sha256": digest,
        "capabilities": capabilities,
        "canary": canary,
    }
