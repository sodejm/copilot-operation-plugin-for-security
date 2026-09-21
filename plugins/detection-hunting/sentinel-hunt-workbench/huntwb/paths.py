"""Package paths and JSON helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = PACKAGE_ROOT.parent
HUNTS_DIR = PACKAGE_ROOT / "hunts"
PROFILES_DIR = PACKAGE_ROOT / "profiles"
FIXTURES_DIR = PACKAGE_ROOT / "fixtures" / "curated"
SKILLS_DIR = PACKAGE_ROOT / "skills"
ADAPTERS_DIR = PACKAGE_ROOT / "adapters"
EVALUATIONS_DIR = PACKAGE_ROOT / "evaluations"
RELEASE_DIR = PACKAGE_ROOT / "release"
EVIDENCE_DIR = RELEASE_DIR / "evidence"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys instead of silently taking the last one."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def parse_json_text(value: str) -> Any:
    """Parse strict JSON text with the same rules used for package files."""

    return json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_json_constant,
    )


def parse_json_bytes(value: bytes) -> Any:
    """Decode strict UTF-8 JSON bytes and reject ambiguous JSON constructs."""

    return parse_json_text(value.decode("utf-8", errors="strict"))


def load_json(path: Path) -> Any:
    """Load strict UTF-8 JSON with no duplicate keys or non-finite numbers."""

    return parse_json_bytes(path.read_bytes())


def canonical_json(value: Any) -> str:
    """Return the stable representation used for content hashes."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    """Write deterministic, human-readable JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n"
    path.write_text(text, encoding="utf-8")


def hunt_paths() -> list[Path]:
    return sorted(HUNTS_DIR.glob("H??.json"))


def profile_paths() -> list[Path]:
    return sorted(PROFILES_DIR.glob("*.json"))


def load_hunts() -> list[dict[str, Any]]:
    return [load_json(path) for path in hunt_paths()]


def load_hunt(hunt_id: str) -> dict[str, Any]:
    normalized = hunt_id.upper()
    path = HUNTS_DIR / f"{normalized}.json"
    if not path.is_file():
        from .errors import ContentError

        raise ContentError(f"unknown hunt id: {hunt_id}")
    return load_json(path)


def load_profiles() -> dict[str, dict[str, Any]]:
    return {profile["id"]: profile for profile in (load_json(path) for path in profile_paths())}


def load_profile(profile_id: str) -> dict[str, Any]:
    profiles = load_profiles()
    if profile_id not in profiles:
        from .errors import ContentError

        raise ContentError(f"unknown surface profile: {profile_id}")
    return profiles[profile_id]
