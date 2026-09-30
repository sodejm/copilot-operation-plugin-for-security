"""Validate export manifests and verify SHA-256 hashes of tenant exports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import EntraError


def load_json_file(path: Path) -> Any:
    """Load and parse a JSON file with error handling."""
    if not path.is_file():
        raise EntraError(f"File not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EntraError(f"Invalid JSON in {path}: {exc}") from exc


def compute_file_sha256(path: Path) -> str:
    """Compute lowercase SHA-256 digest of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def ingest_tenant_export(manifest_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate a tenant export manifest and load its verified sources."""
    manifest_path = manifest_path.resolve()
    manifest_dir = manifest_path.parent
    raw_manifest = load_json_file(manifest_path)

    if not isinstance(raw_manifest, dict):
        raise EntraError(f"Manifest at {manifest_path} must be a JSON object")

    if raw_manifest.get("schema_version") != "entra.export-manifest/v1":
        raise EntraError(
            f"Unsupported manifest schema_version: {raw_manifest.get('schema_version')}"
        )

    tenant_id = str(raw_manifest.get("tenant_id", ""))
    if not tenant_id:
        raise EntraError("Manifest is missing required 'tenant_id'")

    sources_list = raw_manifest.get("sources")
    if not isinstance(sources_list, list) or not sources_list:
        raise EntraError("Manifest must contain a non-empty 'sources' list")

    loaded_sources: dict[str, Any] = {}

    for idx, entry in enumerate(sources_list):
        if not isinstance(entry, dict):
            raise EntraError(f"Manifest source entry at index {idx} must be an object")

        source_id = str(entry.get("source_id", ""))
        rel_path = str(entry.get("path", ""))
        expected_sha = str(entry.get("sha256", "")).lower()

        if not source_id or not rel_path or not expected_sha:
            raise EntraError(f"Manifest source entry at index {idx} is missing required fields")

        file_path = (manifest_dir / rel_path).resolve()
        if not file_path.is_relative_to(manifest_dir):
            raise EntraError(f"Source file {rel_path} escapes tenant directory")

        if not file_path.is_file():
            raise EntraError(f"Source file does not exist: {file_path}")

        actual_sha = compute_file_sha256(file_path)
        if actual_sha != expected_sha:
            raise EntraError(
                f"SHA-256 mismatch for source '{source_id}' ({rel_path}): "
                f"expected {expected_sha}, computed {actual_sha}"
            )

        data = load_json_file(file_path)
        loaded_sources[source_id] = {
            "path": rel_path,
            "sha256": actual_sha,
            "completeness": entry.get("completeness", "unknown"),
            "data": data,
        }

    return raw_manifest, loaded_sources
