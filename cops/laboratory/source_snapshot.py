"""Bounded source manifests shared by the acceptance launcher and its child."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from cops.contracts.validation import SCHEMA_MAP

MAX_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_MANIFEST_BYTES = 1024 * 1024
CONTRACT_SCHEMAS = frozenset(f"catalog/schemas/{name}" for name in SCHEMA_MAP.values())


def allowed_source(relative: str) -> bool:
    path = PurePosixPath(relative)
    if path.as_posix() != relative or path.is_absolute() or "\\" in relative or any(part in {".", ".."} for part in path.parts):
        return False
    return (
        relative == "scripts/check_laboratory.py"
        or relative in CONTRACT_SCHEMAS
        or (path.parts[:1] == ("cops",) and path.suffix == ".py" and "__pycache__" not in path.parts)
        or (path.parts[:3] == ("cops", "laboratory", "service_fixtures")
            and len(path.parts) == 4 and path.suffix in {".json", ".jsonl"})
    )


def bounded_read(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("acceptance source must be a bounded regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("acceptance source exceeds its file budget")
    return raw


def manifest_digest(files: list[dict[str, str]]) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_source_snapshot(root: Path, expected_digest: str) -> None:
    root = root.resolve(strict=True)
    manifest = json.loads(bounded_read(root / "source-manifest.json", MAX_MANIFEST_BYTES))
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("acceptance manifest has an invalid file count")
    if manifest.get("sha256") != expected_digest or manifest_digest(files) != expected_digest:
        raise ValueError("acceptance source manifest does not match its launcher")
    observed: set[str] = set()
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("acceptance manifest entry is invalid")
        relative, digest = item["path"], item["sha256"]
        if not isinstance(relative, str) or not allowed_source(relative) or relative in observed:
            raise ValueError("acceptance manifest path is invalid or duplicated")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("acceptance manifest hash is invalid")
        path = root / relative
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root and root in parent.parents):
            raise ValueError("acceptance source rejects symbolic links")
        raw = bounded_read(path)
        total += len(raw)
        if total > MAX_BYTES or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("acceptance source exceeds its budget or was modified")
        observed.add(relative)
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("acceptance snapshot contains a symbolic link")
        if path.is_file() and path != root / "source-manifest.json":
            actual.add(path.relative_to(root).as_posix())
            if len(actual) > MAX_FILES:
                raise ValueError("acceptance snapshot exceeds its file budget")
    if actual != observed:
        raise ValueError("acceptance snapshot contains unbound files")
