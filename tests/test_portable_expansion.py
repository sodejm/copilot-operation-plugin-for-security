"""Portable expansion asset and installed-runtime coverage."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cops.portable import export_portable_package

ROOT = Path(__file__).resolve().parents[1]
WEB_API_VENDOR = ROOT / "plugins/offensive-security/web-api-assessment-workbench/vendor"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runtime_manifest(vendor: Path) -> dict[str, object]:
    manifest_path = vendor / "runtime-provenance.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "cops.vendored-python-runtime/v1"
    records = {record["path"]: record for record in manifest["files"]}
    actual = {
        path.relative_to(vendor).as_posix()
        for path in vendor.rglob("*")
        if path.is_file() and path != manifest_path and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    assert set(records) == actual
    for relative, record in records.items():
        assert record["sha256"] == _sha256(vendor / relative)
        assert record["source"]
    return manifest


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("GIT_INDEX_FILE", None)
    return environment


def test_web_api_vendored_runtime_manifest_matches_files() -> None:
    _runtime_manifest(WEB_API_VENDOR)


def test_portable_export_preserves_expansion_assets_and_runs_installed_demo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    package = repository / "plugins/offensive-security/fixture-workbench"
    _write(
        package / "plugin.json",
        json.dumps(
            {
                "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
                "name": "fixture-plugin",
                "extensions": {"org.cops": {}},
            }
        ),
    )
    _write(
        package / "skills/fixture-skill/SKILL.md",
        "---\nname: fixture-skill\ndescription: Exercise portable expansion assets.\n---\n\n"
        "Run the installed demonstration.\n",
    )
    _write(
        package / "org.cops/prerequisites.json",
        '{"schema_version":"1.0","tools":[]}',
    )
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    package_relative = package.relative_to(repository)
    subprocess.run(
        ["git", "-C", str(repository), "add", "--", str(package_relative)],
        check=True,
    )
    baseline = subprocess.check_output(["git", "-C", str(repository), "ls-files"], text=True).splitlines()

    dataset = b'{"cases":[{"id":"offline-preview"}]}\n'
    dataset_digest = hashlib.sha256(dataset).hexdigest()
    assets: dict[str, str | bytes] = {
        "examples/openapi.json": '{"openapi":"3.0.0","paths":{}}\n',
        "playbooks/offline-preview.md": "# Offline preview\n\nRun the package demo.\n",
        "walkthroughs/installed-package.md": "# Installed package\n\nNo source checkout is required.\n",
        "datasets/cases.json": dataset,
        "provenance/cases.json": json.dumps(
            {
                "schema_version": "cops.dataset-provenance/v1",
                "artifacts": [{"path": "datasets/cases.json", "sha256": dataset_digest}],
            },
            sort_keys=True,
        )
        + "\n",
        "signatures/cases.sha256": f"{dataset_digest}  datasets/cases.json\n",
    }
    for relative, content in assets.items():
        _write(package / relative, content)
    shutil.copytree(
        WEB_API_VENDOR,
        package / "vendor",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    _write(
        package / "scripts/demo.py",
        '''#!/usr/bin/env python3
"""Run an offline replay using only this installed package."""

import json
from pathlib import Path
import sys


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "vendor"))

import cops
from cops.web_api.importer import import_openapi
from cops.web_api.models import ReplayBudget, ReplayRequest
from cops.web_api.replay import OfflineSyntheticReplayer, execute_replay_session


inventory = import_openapi(
    {
        "openapi": "3.0.0",
        "info": {"title": "Installed fixture", "version": "1"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
)
replayer = OfflineSyntheticReplayer()
report = execute_replay_session(
    [ReplayRequest("request-1", inventory.endpoints[0].endpoint_id, "GET", "https://api.example.test/health")],
    ["api.example.test"],
    budget=ReplayBudget(max_requests=1),
    replayer=replayer,
    session_id="installed-demo",
)
print(
    json.dumps(
        {
            "status": "passed",
            "runtime_root": str(Path(cops.__file__).resolve()),
            "endpoint_count": len(inventory.endpoints),
            "total_successful": report.total_successful,
            "synthetic_requests": len(replayer.requests_sent),
            "network_requests": 0,
        },
        sort_keys=True,
    )
)
''',
    )

    temporary_index = tmp_path / "temporary-index"
    shutil.copy2(repository / ".git/index", temporary_index)
    monkeypatch.setenv("GIT_INDEX_FILE", str(temporary_index))
    subprocess.run(
        ["git", "-C", str(repository), "add", "--", str(package_relative)],
        check=True,
    )
    destination = tmp_path / "portable-package"
    export_portable_package(package, destination)

    assert (
        subprocess.check_output(
            ["git", "-C", str(repository), "ls-files"],
            text=True,
            env=_git_environment(),
        ).splitlines()
        == baseline
    )
    for relative, expected in assets.items():
        expected_bytes = expected if isinstance(expected, bytes) else expected.encode()
        assert (destination / relative).read_bytes() == expected_bytes
    exported_manifest = _runtime_manifest(destination / "vendor")
    assert exported_manifest == _runtime_manifest(WEB_API_VENDOR)
    assert (
        (destination / "signatures/cases.sha256").read_text().startswith(_sha256(destination / "datasets/cases.json"))
    )

    environment = _git_environment()
    environment["PYTHONPATH"] = str(tmp_path / "source-tree-must-not-be-used")
    completed = subprocess.run(
        [sys.executable, "-I", str(destination / "scripts/demo.py")],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result == {
        "endpoint_count": 1,
        "network_requests": 0,
        "runtime_root": str((destination / "vendor/cops/__init__.py").resolve()),
        "status": "passed",
        "synthetic_requests": 1,
        "total_successful": 1,
    }
