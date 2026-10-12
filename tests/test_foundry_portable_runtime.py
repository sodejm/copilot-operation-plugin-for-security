"""Portable harness commands must not require the source-only COPS runtime."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

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
