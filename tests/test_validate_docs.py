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


def write_qualification_docs(tmp_path, monkeypatch):
    monkeypatch.setattr(validate_docs, "ROOT", tmp_path)
    monkeypatch.setattr(validate_docs, "DOCS_DIR", tmp_path / "docs")
    (tmp_path / "catalog").mkdir()
    (tmp_path / "docs").mkdir()
    package = tmp_path / "plugins/testing/one-plugin"
    (package / "docs").mkdir(parents=True)
    (tmp_path / "catalog/plugins.json").write_text(
        json.dumps({"plugins": [{"id": "one-plugin", "path": "plugins/testing/one-plugin"}]})
    )
    (package / "package.json").write_text(json.dumps({"maturity": "experimental"}))
    (package / "README.md").write_text("[Verify](docs/VERIFICATION.md)\n")
    (package / "docs/VERIFICATION.md").write_text(
        "## Scope and prerequisites\n"
        "## Baseline checks\n"
        "```bash\n"
        "python3 -m cops info one-plugin\n"
        "python3 -m cops demo one-plugin\n"
        "python3 -m cops check one-plugin\n"
        "```\n"
        "## End-to-end exercise\n"
        "## Acceptance criteria\n"
        "## Failure and recovery\n"
        "## Host exercise\n"
        "## Record and promote\n"
    )
    (tmp_path / "docs/plugin-verification.md").write_text(
        "[Verify](https://github.com/sodejm/copilot-operation-plugin-for-security/"
        "blob/main/plugins/testing/one-plugin/docs/VERIFICATION.md)\n"
    )
    badge = '<span class="badge badge-experimental">Experimental</span>'
    table = f"| `one-plugin` | {badge} |\n"
    (tmp_path / "README.md").write_text(table)
    (tmp_path / "docs/CAPABILITIES.md").write_text("| `one-plugin` | **Experimental** |\n")
    (tmp_path / "docs/plugin-guide.md").write_text(
        table
        + f"\n#### One plugin\n- **Maturity**: {badge}\n"
        "- **Playbook**: `plugins/testing/one-plugin/docs/PLAYBOOK.md`\n"
    )
    (tmp_path / "docs/index.md").write_text(
        f'<a href="plugin-guide.html#one-plugin">One plugin</a> {badge}\n'
    )
    return package


def test_verification_and_maturity_accept_complete_catalog_docs(tmp_path, monkeypatch):
    write_qualification_docs(tmp_path, monkeypatch)

    errors: list[str] = []
    validate_docs.validate_plugin_verification(errors)
    validate_docs.validate_public_maturity(errors)

    assert errors == []


def test_verification_requires_each_catalog_playbook(tmp_path, monkeypatch):
    package = write_qualification_docs(tmp_path, monkeypatch)
    (package / "docs/VERIFICATION.md").unlink()

    errors: list[str] = []
    validate_docs.validate_plugin_verification(errors)

    assert errors == [
        "one-plugin: missing end-to-end verification playbook: "
        "plugins/testing/one-plugin/docs/VERIFICATION.md"
    ]


def test_verification_requires_run_recovery_and_discovery_instructions(tmp_path, monkeypatch):
    package = write_qualification_docs(tmp_path, monkeypatch)
    playbook = package / "docs/VERIFICATION.md"
    playbook.write_text(
        playbook.read_text()
        .replace("## Failure and recovery", "## Other")
        .replace("python3 -m cops check one-plugin", "python3 -m cops check other-plugin")
    )
    (package / "README.md").write_text("Verification is available.\n")
    (tmp_path / "docs/plugin-verification.md").write_text("one-plugin\n")

    errors: list[str] = []
    validate_docs.validate_plugin_verification(errors)

    assert len(errors) == 4
    assert any("missing section: Failure and recovery" in error for error in errors)
    assert any("missing baseline command: python3 -m cops check one-plugin" in error for error in errors)
    assert any("README.md must link to docs/VERIFICATION.md" in error for error in errors)
    assert any("verification index must link" in error for error in errors)


def test_public_maturity_rejects_stale_tables_details_and_cards(tmp_path, monkeypatch):
    write_qualification_docs(tmp_path, monkeypatch)
    for relative in ("README.md", "docs/CAPABILITIES.md", "docs/plugin-guide.md", "docs/index.md"):
        path = tmp_path / relative
        path.write_text(path.read_text().replace("experimental", "beta").replace("Experimental", "Beta"))

    errors: list[str] = []
    validate_docs.validate_public_maturity(errors)

    assert len(errors) == 5
    assert all("one-plugin" in error and "manifest is experimental" in error for error in errors)
    assert any("detailed maturity" in error for error in errors)


def test_public_maturity_checks_visible_badge_text(tmp_path, monkeypatch):
    write_qualification_docs(tmp_path, monkeypatch)
    path = tmp_path / "README.md"
    path.write_text(path.read_text().replace(">Experimental<", ">Stable<"))

    errors: list[str] = []
    validate_docs.validate_public_maturity(errors)

    assert len(errors) == 1
    assert "badge text" in errors[0]


def test_public_maturity_requires_tables_and_detailed_labels(tmp_path, monkeypatch):
    write_qualification_docs(tmp_path, monkeypatch)
    (tmp_path / "docs/CAPABILITIES.md").write_text("one-plugin is included.\n")
    path = tmp_path / "docs/plugin-guide.md"
    path.write_text(path.read_text().replace("- **Maturity**:", "- **Notes**:"))

    errors: list[str] = []
    validate_docs.validate_public_maturity(errors)

    assert len(errors) == 2
    assert any("missing maturity table row" in error for error in errors)
    assert any("missing detailed maturity" in error for error in errors)


def test_public_maturity_ignores_examples_and_multi_plugin_cards(tmp_path, monkeypatch):
    write_qualification_docs(tmp_path, monkeypatch)
    path = tmp_path / "README.md"
    path.write_text(path.read_text() + "\n```markdown\n| `one-plugin` | **Stable** |\n```\n")
    catalog = tmp_path / "catalog/plugins.json"
    entries = json.loads(catalog.read_text())
    entries["plugins"].append({"id": "two-plugin", "path": "plugins/testing/two-plugin"})
    catalog.write_text(json.dumps(entries))
    package = tmp_path / "plugins/testing/two-plugin"
    package.mkdir()
    (package / "package.json").write_text(json.dumps({"maturity": "beta"}))
    for relative in ("README.md", "docs/CAPABILITIES.md", "docs/plugin-guide.md"):
        path = tmp_path / relative
        path.write_text(path.read_text() + "| `two-plugin` | **Beta** |\n")
    path = tmp_path / "docs/plugin-guide.md"
    path.write_text(
        path.read_text()
        + "\n#### Two plugin\n- **Maturity**: **Beta**\n"
        "- **Playbook**: `plugins/testing/two-plugin/docs/PLAYBOOK.md`\n"
    )
    path = tmp_path / "docs/index.md"
    path.write_text(
        path.read_text()
        + '<a href="plugin-guide.html#one-plugin">One</a>'
        '<a href="plugin-guide.html#two-plugin">Two</a>'
        '<span class="badge badge-stable">Stable</span>\n'
    )

    errors: list[str] = []
    validate_docs.validate_public_maturity(errors)

    assert errors == []


def test_internal_links_include_plugin_verification_playbooks(tmp_path, monkeypatch):
    package = write_qualification_docs(tmp_path, monkeypatch)
    path = package / "docs/VERIFICATION.md"
    path.write_text(path.read_text() + "[Missing](missing.md)\n")
    line_number = len(path.read_text().splitlines())

    errors: list[str] = []
    validate_docs.validate_internal_links(errors)

    assert errors == [
        f"plugins/testing/one-plugin/docs/VERIFICATION.md:{line_number}: "
        "Broken relative link to: missing.md"
    ]
