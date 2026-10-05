"""Unit tests for centralized specialist agent profiles and schema conformance."""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest

from cops.routing.catalog import get_specialist, load_specialists_registry

ROOT = Path(__file__).resolve().parents[1]


def test_specialist_registry_schema():
    """Verify agents/registry.json conforms to specialist-profile.schema.json."""
    schema_path = ROOT / "catalog" / "schemas" / "specialist-profile.schema.json"
    registry_path = ROOT / "agents" / "registry.json"

    assert schema_path.is_file(), f"schema not found: {schema_path}"
    assert registry_path.is_file(), f"registry not found: {registry_path}"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))

    assert "specialists" in registry
    assert len(registry["specialists"]) == 18

    # Validate each entry against the schema
    for specialist in registry["specialists"]:
        jsonschema.validate(instance=specialist, schema=schema)


def test_specialist_profiles_files_exist_and_match_frontmatter():
    """Verify that every profile has a corresponding markdown file with valid frontmatter."""
    profiles = load_specialists_registry()
    assert len(profiles) == 18

    for profile in profiles:
        contract_path = ROOT / profile.contract_file
        assert contract_path.is_file(), f"contract file missing: {contract_path}"

        content = contract_path.read_text(encoding="utf-8")
        match = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", content, re.DOTALL)
        assert match is not None, f"{contract_path} must start with YAML frontmatter"

        # Check key frontmatter attributes
        frontmatter = match.group(1)
        assert f"name: {profile.id}" in frontmatter
        assert f"domain: {profile.domain}" in frontmatter
        assert f"criticality: {profile.criticality}" in frontmatter


def test_specialist_plugins_exist_in_catalog():
    """Verify that every profile points to a valid primary plugin in catalog/plugins.json."""
    plugins_catalog = json.loads((ROOT / "catalog" / "plugins.json").read_text(encoding="utf-8"))
    catalog_ids = {p["id"] for p in plugins_catalog["plugins"]}

    profiles = load_specialists_registry()
    for profile in profiles:
        assert profile.primary_plugin in catalog_ids, (
            f"profile {profile.id} references non-existent plugin '{profile.primary_plugin}'"
        )


def test_get_specialist_lookup():
    """Verify direct profile lookup and error handling."""
    kql = get_specialist("cops-sentinel-kql-engineer")
    assert kql.id == "cops-sentinel-kql-engineer"
    assert kql.domain == "defensive-operations"
    assert not kql.is_critical

    with pytest.raises(ValueError, match="unknown specialist profile id"):
        get_specialist("cops-non-existent-profile")
