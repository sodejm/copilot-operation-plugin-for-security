"""Catalog loader and registry interface for specialist agent profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from .models import SpecialistProfile

ROOT = Path(__file__).resolve().parents[2]


class SpecialistCatalogError(ValueError):
    """The specialist profile registry or a profile entry is invalid."""


def load_specialists_registry(registry_path: Path | None = None) -> list[SpecialistProfile]:
    """Load and validate all specialist agent profiles from the canonical registry."""
    path = registry_path if registry_path is not None else ROOT / "agents" / "registry.json"
    if not path.is_file():
        raise SpecialistCatalogError(f"specialist registry file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise SpecialistCatalogError(f"invalid JSON in {path}: {err}") from err

    if not isinstance(data, dict) or "specialists" not in data or not isinstance(data["specialists"], list):
        raise SpecialistCatalogError(f"{path} must contain a top-level 'specialists' array")

    profiles: list[SpecialistProfile] = []
    seen_ids: set[str] = set()

    for index, entry in enumerate(data["specialists"]):
        if not isinstance(entry, dict):
            raise SpecialistCatalogError(f"entry [{index}] in {path} must be an object")

        profile_id = str(entry.get("id", "")).strip()
        if not profile_id:
            raise SpecialistCatalogError(f"entry [{index}] in {path} has missing or empty id")
        if profile_id in seen_ids:
            raise SpecialistCatalogError(f"duplicate specialist profile id: {profile_id}")
        seen_ids.add(profile_id)

        try:
            profile = SpecialistProfile(
                id=profile_id,
                display_name=str(entry["display_name"]),
                domain=str(entry["domain"]),
                criticality=str(entry["criticality"]),
                interactive_authorization_required=bool(entry["interactive_authorization_required"]),
                description=str(entry["description"]),
                primary_plugin=str(entry["primary_plugin"]),
                skills=tuple(str(s) for s in entry["skills"]),
                tools=tuple(str(t) for t in entry["tools"]),
                contract_file=str(entry["contract_file"]),
                intent_keywords=tuple(str(k).lower() for k in entry["intent_keywords"]),
                triad_defaults=dict(entry["triad_defaults"]) if "triad_defaults" in entry else None,
            )
            profiles.append(profile)
        except KeyError as err:
            raise SpecialistCatalogError(f"entry '{profile_id}' is missing required field: {err}") from err

    return profiles


def get_specialist(specialist_id: str, registry_path: Path | None = None) -> SpecialistProfile:
    """Find a specialist profile by exact identifier."""
    profiles = load_specialists_registry(registry_path)
    for profile in profiles:
        if profile.id == specialist_id:
            return profile
    raise SpecialistCatalogError(f"unknown specialist profile id: '{specialist_id}'")
