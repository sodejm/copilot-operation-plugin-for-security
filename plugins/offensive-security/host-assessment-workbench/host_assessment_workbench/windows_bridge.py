"""Validate independently recorded native Windows bridge cleanup evidence."""

from __future__ import annotations

import hashlib
import json
import re
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


def load_bridge_receipt_bytes(data: bytes) -> dict[str, Any]:
    """Parse a bounded receipt while rejecting duplicate JSON keys."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ContractError("receipt must be at most 1 MiB of JSON bytes")
    _check_json_depth(data)
    try:
        receipt = json.loads(
            data.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("malformed UTF-8 receipt JSON") from exc
    except RecursionError as exc:
        raise ContractError("receipt JSON nesting exceeds parser limit") from exc
    if not isinstance(receipt, dict):
        raise ContractError("receipt must be a JSON object")
    return receipt


def validate_bridge_receipt(
    receipt: dict[str, Any], export_bytes: bytes, canary_root: Path
) -> dict[str, Any]:
    """Bind cleanup evidence to one native export and verify no canary residue remains."""
    document = _exact_keys(
        receipt,
        {"schema_version", "platform", "bridge_mode", "export_sha256", "capabilities", "canary"},
        "receipt",
    )
    if document["schema_version"] != "windows-bridge-receipt-1.0":
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
            "assessment_owned",
            "before_absent",
            "created",
            "removed",
            "cleanup_verified",
            "evidence_ids",
        },
        "receipt.canary",
    )
    for field in ("assessment_owned", "before_absent", "created", "removed", "cleanup_verified"):
        if raw_canary[field] is not True:
            raise ContractError(f"receipt.canary.{field} must be asserted true")
    canary = {
        "resource_id": _token(raw_canary["resource_id"], "receipt.canary.resource_id"),
        "assessment_owned": True,
        "before_absent": True,
        "created": True,
        "removed": True,
        "cleanup_verified": True,
        "evidence_ids": _evidence_ids(raw_canary["evidence_ids"], "receipt.canary.evidence_ids", minimum=3),
    }
    canary_root = Path(canary_root)
    if not canary_root.is_dir():
        raise ContractError("canary root must be an existing directory")
    if next(canary_root.iterdir(), None) is not None:
        raise ContractError("canary root is not empty after cleanup")

    return {
        "schema_version": "windows-bridge-receipt-1.0",
        "platform": "windows",
        "bridge_mode": "native_windows_bridge",
        "export_sha256": digest,
        "capabilities": capabilities,
        "canary": canary,
    }
