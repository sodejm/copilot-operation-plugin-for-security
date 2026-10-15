from __future__ import annotations

import json
from pathlib import Path

import pytest

from cops import portable
from scripts import generate_plugin_playbooks as generator

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _fixture_repository(root: Path) -> Path:
    package = root / "plugins/vulnerability-management/example-workbench"
    (package / "scripts").mkdir(parents=True)
    (package / "docs").mkdir()
    (package / "scripts/demo.py").write_text("raise SystemExit('must not execute')\n", encoding="utf-8")
    (package / "scripts/validate.py").write_text("raise SystemExit('must not execute')\n", encoding="utf-8")
    (package / "docs/PLAYBOOK.md").write_text("# Operator playbook\n", encoding="utf-8")
    _write_json(
        root / "catalog/plugins.json",
        {
            "schema_version": "1.0",
            "plugins": [
                {
                    "id": "example-workbench",
                    "path": "plugins/vulnerability-management/example-workbench",
                }
            ],
        },
    )
    _write_json(
        package / "package.json",
        {
            "schema_version": "1.0",
            "id": "example-workbench",
            "display_name": "Example Workbench",
            "maturity": "experimental",
            "summary": "Inspect a bounded offline example.",
            "support": {
                "structural_validation": "validated",
                "offline_workflow": "validated",
                "host_installation": "unverified",
                "live_integration": "unverified",
            },
            "limitations": ["Offline evidence does not establish live effectiveness or authorization."],
            "demo": {
                "description": "Run the offline example.",
                "command": ["$PYTHON", "plugins/vulnerability-management/example-workbench/scripts/demo.py"],
                "timeout_seconds": 20,
            },
            "validation": [
                {
                    "name": "package validation",
                    "command": [
                        "$PYTHON",
                        "plugins/vulnerability-management/example-workbench/scripts/validate.py",
                    ],
                    "timeout_seconds": 30,
                }
            ],
        },
    )
    return package


def _assert_machine_contract(playbook: object, *, plugin_id: str) -> None:
    assert isinstance(playbook, dict)
    assert playbook["schema_version"] == generator.SCHEMA_VERSION
    assert playbook["plugin_id"] == plugin_id
    assert isinstance(playbook["package_path"], str)
    assert isinstance(playbook["purpose"], str)
    assert isinstance(playbook["status"], dict)
    assert isinstance(playbook["limitations"], list)
    assert isinstance(playbook["links"], dict)
    assert playbook["generation"] == {
        "commands_executed": False,
        "source": "catalog/plugins.json and package metadata",
    }
    assert isinstance(playbook["entrypoints"], list) and playbook["entrypoints"]
    for entrypoint in playbook["entrypoints"]:
        assert {
            "id",
            "purpose",
            "working_directory",
            "argv",
            "timeout_seconds",
            "expectations",
            "effects",
        } <= entrypoint.keys()
        assert isinstance(entrypoint["argv"], list) and len(entrypoint["argv"]) >= 2
        assert isinstance(entrypoint["timeout_seconds"], int)
        assert isinstance(entrypoint["expectations"]["inputs"]["argv"], list)
        assert isinstance(entrypoint["expectations"]["outputs"]["durable_destinations"], list)
        assert isinstance(entrypoint["expectations"]["evidence"], list)
        assert isinstance(entrypoint["effects"]["reads"], list)
        assert isinstance(entrypoint["effects"]["writes"], list)
        assert isinstance(entrypoint["effects"]["authorization"], str)
        assert isinstance(entrypoint["effects"]["network"], str)


def test_generate_and_check_are_deterministic_without_entrypoint_execution(tmp_path: Path, monkeypatch) -> None:
    package = _fixture_repository(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("generation must not execute a package entrypoint")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("os.system", forbidden)

    assert generator.synchronize(tmp_path, check=True, expected_count=1) == [
        Path("plugins/vulnerability-management/example-workbench/playbooks/offline-assessment.json"),
        Path("plugins/vulnerability-management/example-workbench/walkthroughs/offline-assessment.md"),
        Path("plugins/vulnerability-management/example-workbench/docs/PLAYBOOK.md"),
    ]
    assert len(generator.synchronize(tmp_path, check=False, expected_count=1)) == 3
    assert generator.synchronize(tmp_path, check=True, expected_count=1) == []

    playbook = json.loads((package / "playbooks/offline-assessment.json").read_text(encoding="utf-8"))
    _assert_machine_contract(playbook, plugin_id="example-workbench")
    assert playbook["schema_version"] == "cops.plugin-playbook/v1"
    assert playbook["plugin_id"] == "example-workbench"
    assert playbook["generation"]["commands_executed"] is False
    assert all(isinstance(entrypoint["argv"], list) for entrypoint in playbook["entrypoints"])
    assert all(entrypoint["argv"][0] == "python3" for entrypoint in playbook["entrypoints"])
    assert all(entrypoint["effects"]["network"].startswith("none") for entrypoint in playbook["entrypoints"])
    assert playbook["entrypoints"][0]["effects"]["reads"] == [
        "plugins/vulnerability-management/example-workbench/scripts/demo.py"
    ]
    assert playbook["entrypoints"][0]["expectations"]["inputs"]["review_sources"] == [
        "plugins/vulnerability-management/example-workbench/package.json",
        "plugins/vulnerability-management/example-workbench/docs/PLAYBOOK.md",
    ]

    walkthrough = (package / "walkthroughs/offline-assessment.md").read_text(encoding="utf-8")
    assert "python3 plugins/vulnerability-management/example-workbench/scripts/demo.py" in walkthrough
    assert "Expected durable writes: `[]`" in walkthrough
    assert "does not declare a separate corrected/insufficient fixture pair" in walkthrough
    assert "git status --short -- plugins/vulnerability-management/example-workbench" in walkthrough
    assert str(tmp_path) not in walkthrough

    operator_playbook = (package / "docs/PLAYBOOK.md").read_text(encoding="utf-8")
    assert operator_playbook.startswith("# Operator playbook\n")
    assert operator_playbook.count(generator.DOC_BLOCK_START) == 1
    assert operator_playbook.count("../playbooks/offline-assessment.json") == 1
    assert operator_playbook.count("../walkthroughs/offline-assessment.md") == 1


@pytest.mark.parametrize(
    "command",
    [
        "python3 scripts/demo.py",
        ["sh", "-c", "python3 scripts/demo.py"],
        ["$PYTHON", "-c", "print('unsafe')"],
        ["$PYTHON", "../outside.py"],
        ["$PYTHON", "plugins/vulnerability-management/example-workbench/scripts/missing.py"],
    ],
)
def test_rejects_non_argv_inline_traversal_and_missing_commands(tmp_path: Path, command: object) -> None:
    package = _fixture_repository(tmp_path)
    metadata_path = package / "package.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["demo"]["command"] = command
    _write_json(metadata_path, metadata)

    with pytest.raises(generator.GenerationError):
        generator.render_repository(tmp_path, expected_count=1)


def test_repository_assets_cover_all_catalog_plugins_and_are_current() -> None:
    records = json.loads((ROOT / "catalog/plugins.json").read_text(encoding="utf-8"))["plugins"]
    assert len(records) == generator.EXPECTED_PLUGIN_COUNT
    assert generator.synchronize(ROOT, check=True) == []
    assets = generator.render_repository(ROOT)
    assert len(assets) == generator.EXPECTED_PLUGIN_COUNT * 3
    assert {asset.path.parent.name for asset in assets} == {"docs", "playbooks", "walkthroughs"}
    for record in records:
        package = ROOT / record["path"]
        playbook = json.loads((package / generator.PLAYBOOK_RELATIVE).read_text(encoding="utf-8"))
        _assert_machine_contract(playbook, plugin_id=record["id"])
        assert playbook["plugin_id"] == record["id"]
        assert playbook["entrypoints"]
        assert all(entrypoint["argv"] and entrypoint["argv"][0] == "python3" for entrypoint in playbook["entrypoints"])
        assert all(not Path(argument).is_absolute() for entrypoint in playbook["entrypoints"] for argument in entrypoint["argv"][1:])
        operator_playbook = (package / "docs/PLAYBOOK.md").read_text(encoding="utf-8")
        assert operator_playbook.count(generator.DOC_BLOCK_START) == 1
        assert operator_playbook.count(generator.DOC_BLOCK_END) == 1


def test_operator_playbook_managed_block_preserves_author_content(tmp_path: Path) -> None:
    package = _fixture_repository(tmp_path)
    authored = "# Operator playbook\n\nKeep spacing and author text exactly.  \n"
    operator_playbook = package / "docs/PLAYBOOK.md"
    operator_playbook.write_text(authored, encoding="utf-8")

    generator.synchronize(tmp_path, check=False, expected_count=1)
    generated = operator_playbook.read_text(encoding="utf-8")
    assert generated.startswith(authored)
    assert generated.count(generator.DOC_BLOCK_START) == 1

    authored_suffix = "\nAuthor-owned notes after the managed block.\n"
    stale = generated.replace("## Generated offline assessment", "stale generated text") + authored_suffix
    operator_playbook.write_text(stale, encoding="utf-8")
    assert generator.synchronize(tmp_path, check=True, expected_count=1) == [
        Path("plugins/vulnerability-management/example-workbench/docs/PLAYBOOK.md")
    ]
    generator.synchronize(tmp_path, check=False, expected_count=1)
    repaired = operator_playbook.read_text(encoding="utf-8")
    assert repaired == generated + authored_suffix
    assert repaired.startswith(authored)


@pytest.mark.parametrize(
    "content",
    [
        f"# Operator\n\n{generator.DOC_BLOCK_START}\n",
        f"# Operator\n\n{generator.DOC_BLOCK_END}\n",
        f"{generator.DOC_BLOCK_END}\n{generator.DOC_BLOCK_START}\n",
    ],
)
def test_operator_playbook_rejects_incomplete_or_out_of_order_managed_blocks(
    tmp_path: Path, content: str
) -> None:
    package = _fixture_repository(tmp_path)
    (package / "docs/PLAYBOOK.md").write_text(content, encoding="utf-8")

    with pytest.raises(generator.GenerationError, match="managed links block"):
        generator.render_repository(tmp_path, expected_count=1)


def test_authored_offline_assessment_is_preserved_and_normalized(tmp_path: Path) -> None:
    package = _fixture_repository(tmp_path)
    (package / "examples").mkdir()
    _write_json(package / "examples/input.json", {"kind": "input"})
    _write_json(package / "examples/correction-cases.json", {"cases": []})
    for script in ("assess.py", "report.py"):
        (package / f"scripts/{script}").write_text("raise SystemExit('must not execute')\n", encoding="utf-8")
    _write_json(
        package / "docs/offline-assessment.json",
        {
            "schema_version": "cops.offline-artifact-playbook/v1",
            "package_id": "example-workbench",
            "capability": "example_configuration",
            "readiness": "experimental",
            "entrypoints": {
                "assessment": "scripts/assess.py",
                "correction_playback": "scripts/demo.py",
                "native_report": "scripts/report.py",
                "package_check": "scripts/validate.py",
            },
            "inputs": ["examples/input.json", "examples/correction-cases.json"],
            "outputs": ["cops.artifact-assessment/v1", "cops.assessment-report/v1"],
            "permissions": {"filesystem": "read supplied files", "network": "none", "subprocess": "none"},
            "limitations": ["A content hash does not establish source authenticity."],
        },
    )
    (package / "docs/offline-assessment.md").write_text(
        """# Offline assessment walkthrough

Run `python3 scripts/demo.py` for corrected and insufficient cases.
Run `python3 scripts/assess.py --input examples/input.json` for assessment.
Run `python3 scripts/report.py --input examples/input.json --target fixture:example` for a report.
""",
        encoding="utf-8",
    )

    generator.synchronize(tmp_path, check=False, expected_count=1)
    playbook = json.loads((package / generator.PLAYBOOK_RELATIVE).read_text(encoding="utf-8"))
    preserved = playbook["authored_offline_assessment"]
    assert preserved["source_schema_version"] == "cops.offline-artifact-playbook/v1"
    assert preserved["inputs"] == ["examples/input.json", "examples/correction-cases.json"]
    assert preserved["outputs"] == ["cops.artifact-assessment/v1", "cops.assessment-report/v1"]
    authored = [entrypoint for entrypoint in playbook["entrypoints"] if entrypoint["id"].startswith("authored-")]
    assert len(authored) == 3
    assert all(entrypoint["working_directory"] == "plugins/vulnerability-management/example-workbench" for entrypoint in authored)
    assessment = next(entrypoint for entrypoint in authored if "assess.py" in entrypoint["argv"][1])
    assert assessment["effects"]["reads"] == [
        "plugins/vulnerability-management/example-workbench/scripts/assess.py",
        "plugins/vulnerability-management/example-workbench/examples/input.json",
    ]
    walkthrough = (package / generator.WALKTHROUGH_RELATIVE).read_text(encoding="utf-8")
    assert "vulnerable, corrected, insufficient, and benign" in walkthrough
    assert "../docs/offline-assessment.md" in walkthrough


def test_portable_export_policy_includes_generated_asset_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert {"playbooks", "walkthroughs"} <= portable.PORTABLE_ENTRIES
    source = tmp_path / "source"
    destination = tmp_path / "exported"
    playbook = source / "playbooks/offline-assessment.json"
    walkthrough = source / "walkthroughs/offline-assessment.md"
    _write_json(playbook, {"schema_version": "cops.plugin-playbook/v1"})
    walkthrough.parent.mkdir(parents=True)
    walkthrough.write_text("# Walkthrough\n", encoding="utf-8")
    monkeypatch.setattr(portable, "_tracked_files", lambda _source: [playbook.relative_to(source), walkthrough.relative_to(source)])
    monkeypatch.setattr(portable, "validate_portable_package", lambda _destination: None)

    portable.export_portable_package(source, destination)

    assert (destination / playbook.relative_to(source)).is_file()
    assert (destination / walkthrough.relative_to(source)).is_file()


def test_check_mode_never_repairs_stale_assets(tmp_path: Path) -> None:
    package = _fixture_repository(tmp_path)
    generator.synchronize(tmp_path, check=False, expected_count=1)
    playbook_path = package / generator.PLAYBOOK_RELATIVE
    playbook_path.write_text("stale\n", encoding="utf-8")

    assert generator.main(["--root", str(tmp_path), "--expected-count", "1", "--check"]) == 1
    assert playbook_path.read_text(encoding="utf-8") == "stale\n"


def test_generated_assets_use_only_repository_relative_paths(tmp_path: Path) -> None:
    _fixture_repository(tmp_path)
    assets = generator.render_repository(tmp_path, expected_count=1)
    for asset in assets:
        assert str(tmp_path) not in asset.content
        assert "/private/" not in asset.content
        assert "/Users/" not in asset.content


def test_output_destinations_are_resolved_against_the_declared_working_directory(
    tmp_path: Path,
) -> None:
    package = _fixture_repository(tmp_path)
    metadata_path = package / "package.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["demo"]["command"].extend(["--output-dir=build/evidence"])
    _write_json(metadata_path, metadata)

    generator.synchronize(tmp_path, check=False, expected_count=1)
    playbook = json.loads((package / generator.PLAYBOOK_RELATIVE).read_text(encoding="utf-8"))
    assert playbook["entrypoints"][0]["effects"]["writes"] == ["build/evidence"]
    assert playbook["entrypoints"][0]["expectations"]["outputs"]["durable_destinations"] == [
        "build/evidence"
    ]
