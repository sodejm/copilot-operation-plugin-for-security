"""Verify pinned source packaging without executing third-party build code."""

import base64
import csv
import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def builder():
    path = Path(__file__).resolve().parents[1] / "laboratories/service-runtime/build_hexdump_wheel.py"
    spec = importlib.util.spec_from_file_location("build_hexdump_wheel", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(tmp_path, module=b"# Synthetic module; never imported\n"):
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as output:
        output.writestr("hexdump.py", module)
        output.writestr("setup.py", "raise RuntimeError('must not execute')")
        output.writestr("../escape.py", "raise RuntimeError('must not extract')")
    return source


def test_rejects_unreviewed_or_oversized_source_before_output(builder, tmp_path):
    source = archive(tmp_path)
    destination = tmp_path / "wheels"
    with pytest.raises(ValueError, match="reviewed release"):
        builder.build(source, destination)
    source.write_bytes(b"0" * 65_537)
    with pytest.raises(ValueError, match="reviewed release"):
        builder.build(source, destination)
    assert not destination.exists()


def test_deterministic_single_module_and_valid_record(builder, monkeypatch, tmp_path):
    source = archive(tmp_path)
    monkeypatch.setattr(builder, "SOURCE_SHA256", hashlib.sha256(source.read_bytes()).hexdigest())
    first = builder.build(source, tmp_path / "first").read_bytes()
    second = builder.build(source, tmp_path / "second").read_bytes()
    assert first == second
    with zipfile.ZipFile(io.BytesIO(first)) as wheel:
        assert set(wheel.namelist()) == {"hexdump.py", *(f"{builder.DIST}/{name}" for name in ("METADATA", "WHEEL", "RECORD"))}
        for item in wheel.infolist():
            assert item.date_time == (1980, 1, 1, 0, 0, 0)
        rows = csv.reader(io.StringIO(wheel.read(f"{builder.DIST}/RECORD").decode()))
        for name, digest, size in rows:
            if name.endswith("/RECORD"):
                assert (digest, size) == ("", "")
            else:
                data = wheel.read(name)
                expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                assert digest == f"sha256={expected}"
                assert int(size) == len(data)
    assert not (tmp_path / "escape.py").exists()


def test_rejects_expansion_beyond_module_bound(builder, monkeypatch, tmp_path):
    source = tmp_path / "large.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("hexdump.py", b"0" * 131_073)
    monkeypatch.setattr(builder, "SOURCE_SHA256", hashlib.sha256(source.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="size bound"):
        builder.build(source, tmp_path / "wheels")
