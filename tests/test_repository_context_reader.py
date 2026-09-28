"""Regression tests for repository-controlled file reads."""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile

import pytest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "plugins/logging-telemetry/security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py"
spec = importlib.util.spec_from_file_location("repository_context_scanner", SCRIPT)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def test_replaced_file_is_not_read_after_discovery(tmp_path, monkeypatch):
    target = tmp_path / "config.env"
    replacement = tmp_path / "replacement.env"
    target.write_text('db_password = "FixturePassword123!"\n')
    replacement.write_bytes(b'x' * (scanner.MAX_FILE_SIZE_BYTES + 1))
    opener = "open_windows_regular_file" if os.name == "nt" else "open"
    owner = scanner if os.name == "nt" else scanner.os
    real_open = getattr(owner, opener)

    def replace_then_open(path, *args, **kwargs):
        if path == str(target):
            replacement.replace(target)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(owner, opener, replace_then_open)
    result = scanner.scan_repository(tmp_path)

    assert {"file": "config.env", "reason": "changed"} in result["skipped_files"]
    assert result["secrets_findings"] == []



@pytest.mark.parametrize("restore_mtime", [False, pytest.param(True, marks=pytest.mark.skipif(os.name == "nt", reason="POSIX ctime mutation tracking"))])
def test_same_inode_rewrite_after_discovery_is_not_scanned(tmp_path, monkeypatch, restore_mtime):
    target = tmp_path / "config.env"
    target.write_text('password = "BeforeFixture123!"')
    discovered = target.lstat()
    opener = "open_windows_regular_file" if os.name == "nt" else "open"
    owner = scanner if os.name == "nt" else scanner.os
    real_open = getattr(owner, opener)

    def rewrite_then_open(path, *args, **kwargs):
        if path == str(target):
            target.write_text('password = "AfterFixture1234!"')
            mtime = discovered.st_mtime_ns if restore_mtime else discovered.st_mtime_ns + 1_000_000_000
            os.utime(target, ns=(discovered.st_atime_ns, mtime))
            assert target.lstat().st_ino == discovered.st_ino
            assert target.lstat().st_size == discovered.st_size
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(owner, opener, rewrite_then_open)
    result = scanner.scan_repository(tmp_path)

    assert {"file": "config.env", "reason": "changed"} in result["skipped_files"]
    assert result["secrets_findings"] == []


def test_file_enlarged_after_open_is_not_read_past_cap(tmp_path, monkeypatch):
    target = tmp_path / "config.env"
    target.write_text('db_password = "FixturePassword123!"\n')
    real_read = scanner.os.read
    requested = []
    returned = []
    grew = False

    def grow_then_read(fd, count):
        nonlocal grew
        requested.append(count)
        if not grew:
            grew = True
            with target.open("ab") as stream:
                stream.write(b'x' * (scanner.MAX_FILE_SIZE_BYTES + 1))
        chunk = real_read(fd, count)
        returned.append(len(chunk))
        return chunk

    monkeypatch.setattr(scanner.os, "read", grow_then_read)
    result = scanner.scan_repository(tmp_path)

    assert requested and sum(returned) == scanner.MAX_FILE_SIZE_BYTES + 1
    assert all(count <= 65536 for count in requested)
    assert {"file": "config.env", "reason": "too_large"} in result["skipped_files"]
    assert result["secrets_findings"] == []


def test_symlink_target_is_never_opened(tmp_path, monkeypatch):
    target = tmp_path / "target.txt"
    target.write_text('{"dependencies": {"express": "1"}}')
    link = tmp_path / "package.json"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable: {error}")
    real_open = scanner.os.open

    def reject_link_open(path, flags, *args, **kwargs):
        assert path != str(link)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", reject_link_open)
    result = scanner.scan_repository(tmp_path)

    assert {"file": "package.json", "reason": "symlink"} in result["skipped_files"]
    assert "Node.js Framework: express" not in result["frameworks_and_libraries"]


def test_skipped_special_files_count_toward_file_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILES_TO_SCAN", 3)
    for number in range(5):
        try:
            (tmp_path / f"link-{number}.json").symlink_to(tmp_path / "missing-target")
        except OSError as error:
            pytest.skip(f"Symlinks unavailable: {error}")

    result = scanner.scan_repository(tmp_path)

    assert result["scanned_files_count"] == 0
    assert len(result["skipped_files"]) == 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor flags")
@pytest.mark.parametrize("replacement_kind", ["symlink", "fifo"])
def test_non_regular_replacement_returns_without_blocking(tmp_path, replacement_kind):
    target = tmp_path / "config.env"
    target.write_text('password = "FixturePassword123!"')
    external = tmp_path / "external.txt"
    external.write_text('password = "OutsideFixture123!"')
    code = f"""
import importlib.util, json, os
spec = importlib.util.spec_from_file_location('scanner', {str(SCRIPT)!r})
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
original = os.open
def swap(path, flags, *args, **kwargs):
    if path == {str(target)!r}:
        os.unlink(path)
        if {replacement_kind!r} == 'fifo':
            os.mkfifo(path)
        else:
            os.symlink({str(external)!r}, path)
    return original(path, flags, *args, **kwargs)
scanner.os.open = swap
print(json.dumps(scanner.scan_repository({str(tmp_path)!r})))
"""
    run = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True, timeout=5)
    result = json.loads(run.stdout)
    reason = "changed" if replacement_kind == "symlink" else "non_regular"
    assert {"file": "config.env", "reason": reason} in result["skipped_files"]
    assert result["secrets_findings"] == []


@pytest.mark.parametrize("name", ["config.env", "main.tf", "package.json", "requirements.txt", "pom.xml"])
@pytest.mark.parametrize("extra", [0, 1])
def test_size_boundary_for_every_content_consumer(tmp_path, name, extra):
    target = tmp_path / name
    prefix = b'password = "FixturePassword123!"\n'
    target.write_bytes(prefix + b" " * (scanner.MAX_FILE_SIZE_BYTES + extra - len(prefix)))
    content, reason = scanner.read_bounded_regular_file(str(target), target.lstat())
    if extra:
        assert content is None and reason == "too_large"
    else:
        assert reason is None and len(content) == scanner.MAX_FILE_SIZE_BYTES


def test_ordinary_findings_and_universal_newlines_are_preserved(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"1","pg":"1","passport":"1"}}')
    (tmp_path / "main.tf").write_text('provider "aws" {}')
    (tmp_path / "requirements.txt").write_text('django\nstructlog\nboto3')
    (tmp_path / "pom.xml").write_text('spring-boot')
    value = "FixturePassword123!"
    (tmp_path / "config.env").write_bytes(f'first\r\nsecond\rthird\npassword = "{value}"'.encode())
    result = scanner.scan_repository(tmp_path)
    assert result["skipped_files"] == []
    assert {"Node.js Framework: express", "Python Framework: Django", "Java Framework: Spring Boot", "Logging Library: structlog"} <= set(result["frameworks_and_libraries"])
    assert "AWS" in result["iac_and_cloud"]
    assert "Node.js DB Client: pg" in result["databases"]
    assert "Node.js Auth: passport" in result["identity_and_auth"]
    assert result["secrets_findings"][0]["line"] == 4
    assert value not in json.dumps(result)


@pytest.mark.skipif(os.name == "nt", reason="POSIX sockets")
def test_socket_is_skipped():
    # Keep the pathname within the smaller AF_UNIX limit, even with long temp roots.
    with tempfile.TemporaryDirectory(dir="/tmp") as directory, socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(Path(directory) / "config.env"))
        result = scanner.scan_repository(directory)
    assert result["skipped_files"] == [{"file": "config.env", "reason": "non_regular"}]


def test_read_error_closes_descriptor(tmp_path, monkeypatch):
    target = tmp_path / "config.env"
    target.write_text("bounded")
    descriptors = []
    def fail_read(fd, count):
        descriptors.append(fd)
        raise OSError("fixture read error")
    monkeypatch.setattr(scanner.os, "read", fail_read)
    assert scanner.read_bounded_regular_file(str(target), target.lstat()) == (None, "unreadable")
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.skipif(os.name != "nt", reason="Windows device handle")
def test_windows_nul_is_rejected_before_read(tmp_path):
    target = tmp_path / "ordinary.env"
    target.write_text("bounded")
    assert scanner.read_bounded_regular_file("NUL", target.lstat()) == (None, "non_regular")
