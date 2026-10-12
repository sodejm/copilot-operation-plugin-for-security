"""Portable harness commands must not require the source-only COPS runtime."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cops.laboratory.agent_mcp import SOURCE_FILES
from cops.portable import export_portable_package

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins/offensive-security/foundry-agent-harness"


def test_exported_harness_keeps_offline_commands_and_explains_auth_dependency(tmp_path):
    exported = tmp_path / "portable" / "foundry-agent-harness"
    export_portable_package(PLUGIN, exported)
    demo = subprocess.run(
        [sys.executable, "-I", str(exported / "scripts/run_demo.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert demo.returncode == 0, demo.stderr
    assert "[OK] Evaluated" in demo.stdout

    result = subprocess.run(
        [
            sys.executable, "-I", str(exported / "foundryharness/cli.py"),
            "auth-plan", "--plan-id", "portable-check", "--engagement-id", "portable-check",
            "--created-at", "2026-10-12T00:00:00Z",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "require the COPS source runtime" in result.stderr
    assert "Traceback" not in result.stderr
    assert not result.stdout


def test_source_package_validator_does_not_require_repository_imports(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", str(PLUGIN / "scripts/validate_package.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def inject_execution_marker(source: Path, marker: Path):
    text = source.read_text()
    anchor = "from __future__ import annotations\n"
    assert anchor in text
    source.write_text(text.replace(
        anchor, anchor + f"\n__import__('pathlib').Path({str(marker)!r}).touch()\n", 1,
    ))


@pytest.mark.parametrize("name", SOURCE_FILES)
def test_package_gate_does_not_execute_authorization_sources(tmp_path, name):
    copied = tmp_path / "plugin"
    shutil.copytree(PLUGIN, copied, ignore=shutil.ignore_patterns("__pycache__"))
    marker = tmp_path / "executed"
    inject_execution_marker(copied / "foundryharness" / name, marker)
    result = subprocess.run(
        [sys.executable, "-I", str(copied / "scripts/validate_package.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not marker.exists(), f"package gate executed {name} before approval"


def test_normal_cops_check_keeps_package_sources_inert(tmp_path, capsys):
    from cops.cli import main

    copied = tmp_path / "repository"
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode().split("\0")
    for name in filter(None, tracked):
        source = ROOT / name
        if source.is_file():
            destination = copied / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    runtime = copied / PLUGIN.relative_to(ROOT) / "foundryharness"
    markers = []
    for name in (*SOURCE_FILES, "mcp_fixture_server.py"):
        marker = tmp_path / (name + ".executed")
        inject_execution_marker(runtime / name, marker)
        markers.append(marker)
    assert main(["check", "foundry-agent-harness"], root=copied) == 0, capsys.readouterr()
    assert not any(marker.exists() for marker in markers)


@pytest.mark.parametrize("directory", ["auth_cases", "lab_cases", "scenarios"])
def test_data_only_package_gate_rejects_invalid_case(tmp_path, directory):
    copied = tmp_path / "plugin"
    shutil.copytree(PLUGIN, copied, ignore=shutil.ignore_patterns("__pycache__"))
    case_path = next((copied / directory).glob("*.json"))
    data = json.loads(case_path.read_text())
    data["unrecognized_field"] = True
    case_path.write_text(json.dumps(data))
    result = subprocess.run(
        [sys.executable, "-I", str(copied / "scripts/validate_package.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0


@pytest.mark.parametrize("raw", [
    b'{"schema_version":"secret-a","schema_version":"secret-b"}',
    b'{"number":NaN}', b'{"number":Infinity}', b'{"number":1e999}',
    b'{"text":"\\ud800"}', b'{"text":"\xff"}',
    b'[' * 42 + b'0' + b']' * 42,
    b'[' + b'0,' * 10001 + b'0]',
    b' ' * (64 * 1024 + 1),
])
def test_data_only_package_gate_rejects_unbounded_or_ambiguous_json(tmp_path, raw):
    copied = tmp_path / "plugin"
    shutil.copytree(PLUGIN, copied, ignore=shutil.ignore_patterns("__pycache__"))
    next((copied / "auth_cases").glob("*.json")).write_bytes(raw)
    result = subprocess.run(
        [sys.executable, "-I", str(copied / "scripts/validate_package.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0
    assert "secret-a" not in result.stdout + result.stderr
    assert "secret-b" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("defect", [
    "boolean_integer", "missing_default_coverage", "symlink", "unbounded_pattern",
])
def test_data_only_package_gate_preserves_authorization_case_constraints(tmp_path, defect):
    copied = tmp_path / "plugin"
    shutil.copytree(PLUGIN, copied, ignore=shutil.ignore_patterns("__pycache__"))
    case_path = next(path for path in (copied / "auth_cases").glob("*.json")
                     if json.loads(path.read_text())["case_id"] == "delegated-control")
    data = json.loads(case_path.read_text())
    if defect == "boolean_integer":
        data["attempts"][0]["depth"] = True
        case_path.write_text(json.dumps(data))
    elif defect == "missing_default_coverage":
        # This remains schema-valid but removes the required positive control.
        data["attempts"][0]["tenant"] = "tenant-fabrikam-02"
        data["expected_decisions"] = ["denied"]
        data["expected_reasons"] = ["tenant_mismatch"]
        data["expected_effect_count"] = 0
        case_path.write_text(json.dumps(data))
    elif defect == "symlink":
        target = tmp_path / "outside.json"
        target.write_text(json.dumps(data))
        case_path.unlink()
        case_path.symlink_to(target)
    else:
        schema_path = copied / "schemas/auth-case.schema.json"
        schema = json.loads(schema_path.read_text())
        schema["properties"]["case_id"]["pattern"] = "(a+)+$"
        schema_path.write_text(json.dumps(schema))
    result = subprocess.run(
        [sys.executable, "-I", str(copied / "scripts/validate_package.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'{"secret":"first","secret":"second"}', "duplicate_key"),
        (b'{"nested":{"key":1,"key":2}}', "duplicate_key"),
        (b'{"number":NaN}', "invalid_json"),
        (b'{"number":Infinity}', "invalid_json"),
        (b'{"number":1e999}', "invalid_json"),
        (b'{"unicode":"\\ud800"}', "invalid_json"),
        (b'{"unicode":"\xff"}', "invalid_json"),
        (b'[[[[0]]]]', "payload_limit"),
    ],
)
def test_portable_fixture_decoder_rejects_hostile_json(raw, code, monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN))
    from foundryharness.bounded_json import JSONInputError, decode_json

    with pytest.raises(JSONInputError) as captured:
        decode_json(raw, max_depth=3)
    assert captured.value.code == code
    assert str(captured.value) == code


def test_portable_fixture_decoder_bounds_bytes_and_ignores_quoted_braces(monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN))
    from foundryharness.bounded_json import JSONInputError, decode_json

    raw = b'{"text":"[[[\\\"{{{","nested":[]}'
    assert decode_json(raw, max_depth=2) == {"text": '[[["{{{', "nested": []}
    with pytest.raises(JSONInputError, match="response_limit"):
        decode_json(raw, max_bytes=len(raw) - 1)
