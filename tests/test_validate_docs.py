"""Regression checks for catalog-backed public documentation claims."""

from __future__ import annotations

import json

from scripts.agent import validate_docs


def test_catalog_counts_reject_stale_public_claims(tmp_path, monkeypatch):
    monkeypatch.setattr(validate_docs, "ROOT", tmp_path)
    monkeypatch.setattr(validate_docs, "DOCS_DIR", tmp_path / "docs")
    (tmp_path / "catalog").mkdir()
    (tmp_path / "agents").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "catalog/plugins.json").write_text(json.dumps({"plugins": [{}, {}]}))
    (tmp_path / "agents/registry.json").write_text(json.dumps({"specialists": [{}]}))
    (tmp_path / "catalog/scenarios.json").write_text(json.dumps({"scenarios": [{}]}))
    (tmp_path / "README.md").write_text(
        "Explore 13 Plugins. Audit all 63 capabilities (18 specialists, 32 scenarios).\n"
        "Currently 0 capabilities claim live-validated.\n"
    )

    errors: list[str] = []
    validate_docs.validate_catalog_counts(errors)

    assert len(errors) == 4
    assert all(error.startswith("README.md:1:") for error in errors)
    assert any("advertises 13 plugins; canonical catalog has 2" in error for error in errors)
    assert any("advertises 63 capabilities; canonical catalog has 4" in error for error in errors)


def test_plugin_coverage_requires_public_tables(tmp_path, monkeypatch):
    monkeypatch.setattr(validate_docs, "ROOT", tmp_path)
    monkeypatch.setattr(validate_docs, "DOCS_DIR", tmp_path / "docs")
    (tmp_path / "catalog").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "catalog/plugins.json").write_text(
        json.dumps({"plugins": [{"id": "one-plugin"}, {"id": "new-plugin"}]})
    )
    (tmp_path / "README.md").write_text("one-plugin\n")
    (tmp_path / "docs/CAPABILITIES.md").write_text("one-plugin\n")
    (tmp_path / "docs/plugin-guide.md").write_text("one-plugin\nnew-plugin\n")
    (tmp_path / "docs/index.md").write_text("one-plugin\n")

    errors: list[str] = []
    validate_docs.validate_plugin_coverage(errors)

    assert errors == [
        "README.md does not document catalog plugin: new-plugin",
        "docs/CAPABILITIES.md does not document catalog plugin: new-plugin",
        "docs/index.md does not document catalog plugin: new-plugin",
    ]
