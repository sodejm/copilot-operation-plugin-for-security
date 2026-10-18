"""Bounded immutable Git-object reads for report source anchors."""

from __future__ import annotations

import hashlib
import json
import subprocess
import threading
from pathlib import Path

import pytest

from cops.reporting.assessment import build_assessment_report
from cops.reports import ExportError, export_pr_markdown, exporters

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"
MAX_SOURCE_BLOB_BYTES = 1024 * 1024


def _report() -> dict:
    bundle = json.loads((FIXTURES / "valid_assessment_input.json").read_text(encoding="utf-8"))
    return build_assessment_report(bundle)


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        stderr=subprocess.DEVNULL,
        text=True,
    ).strip()


def _repository(tmp_path: Path, files: dict[str, bytes]) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    _git(repository, "config", "user.name", "COPS test")
    _git(repository, "config", "user.email", "cops@example.invalid")
    _git(repository, "config", "commit.gpgsign", "false")
    for relative_path, content in files.items():
        path = repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "-m", "test source anchors")
    return repository, _git(repository, "rev-parse", "HEAD")


def _anchor(path: str, *, start_line: int = 1, end_line: int | None = None) -> dict:
    anchor = {
        "finding_id": "find-open-port-http-80",
        "path": path,
        "start_line": start_line,
    }
    if end_line is not None:
        anchor["end_line"] = end_line
    return anchor


def test_source_anchor_accepts_blob_at_exact_byte_limit(tmp_path: Path) -> None:
    content = b"a" * MAX_SOURCE_BLOB_BYTES
    repository, revision = _repository(tmp_path, {"exact.txt": content})

    markdown = export_pr_markdown(
        _report(),
        repository_root=repository,
        revision=revision,
        source_anchors=[_anchor("exact.txt")],
    )

    assert hashlib.sha256(content).hexdigest() in markdown


def test_source_anchor_rejects_blob_one_byte_over_limit_without_content(tmp_path: Path) -> None:
    marker = b"private-anchor-content"
    content = b"a" * (MAX_SOURCE_BLOB_BYTES + 1 - len(marker)) + marker
    repository, revision = _repository(tmp_path, {"oversized.txt": content})

    with pytest.raises(ExportError, match="1 MiB") as raised:
        export_pr_markdown(
            _report(),
            repository_root=repository,
            revision=revision,
            source_anchors=[_anchor("oversized.txt")],
        )

    assert marker.decode("ascii") not in str(raised.value)


def test_oversized_metadata_is_rejected_before_blob_content_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, revision = _repository(
        tmp_path,
        {"oversized.txt": b"x" * (MAX_SOURCE_BLOB_BYTES + 1)},
    )

    def forbidden_read(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("oversized blob content must not be read")

    monkeypatch.setattr(exporters, "_read_git_blob", forbidden_read)

    with pytest.raises(ExportError, match="1 MiB"):
        export_pr_markdown(
            _report(),
            repository_root=repository,
            revision=revision,
            source_anchors=[_anchor("oversized.txt")],
        )


def test_blob_read_stays_bounded_when_metadata_understates_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = b"metadata-disagreement-content"
    content = b"z" * (MAX_SOURCE_BLOB_BYTES + 1 - len(marker)) + marker
    repository, revision = _repository(tmp_path, {"changed-size.txt": content})
    object_id = _git(repository, "rev-parse", f"{revision}:changed-size.txt")

    monkeypatch.setattr(
        exporters,
        "_git_blob_info",
        lambda *_args, **_kwargs: (object_id, "blob", 1),
    )

    with pytest.raises(ExportError, match="1 MiB") as raised:
        export_pr_markdown(
            _report(),
            repository_root=repository,
            revision=revision,
            source_anchors=[_anchor("changed-size.txt")],
        )

    assert marker.decode("ascii") not in str(raised.value)


def test_blob_reader_cleans_up_when_reader_start_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStdout:
        def __init__(self) -> None:
            self.closed = False

        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.args = ["git"]
            self.stdout = FakeStdout()
            self.killed = False

        def poll(self) -> int | None:
            return -9 if self.killed else None

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: int) -> int:
            return -9

    process = FakeProcess()
    monkeypatch.setattr(exporters.subprocess, "Popen", lambda *_args, **_kwargs: process)

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("reader start failed")

    monkeypatch.setattr(exporters.threading.Thread, "start", fail_start)

    with pytest.raises(ExportError, match="unable to verify"):
        exporters._read_git_blob(Path("."), "0" * 40)

    assert process.killed
    assert process.stdout.closed


def test_source_anchor_rejects_non_blob_path_without_content(tmp_path: Path) -> None:
    repository, revision = _repository(tmp_path, {"directory/file.txt": b"bounded\n"})

    with pytest.raises(ExportError, match="Git blob") as raised:
        export_pr_markdown(
            _report(),
            repository_root=repository,
            revision=revision,
            source_anchors=[_anchor("directory")],
        )

    assert "bounded" not in str(raised.value)


def test_source_anchor_reads_committed_blob_instead_of_dirty_worktree(tmp_path: Path) -> None:
    committed = "committed α\n".encode()
    repository, revision = _repository(tmp_path, {"source.txt": committed})
    (repository / "source.txt").write_text("dirty worktree content\n", encoding="utf-8")

    markdown = export_pr_markdown(
        _report(),
        repository_root=repository,
        revision=revision,
        source_anchors=[_anchor("source.txt")],
    )

    assert hashlib.sha256(committed).hexdigest() in markdown
    assert hashlib.sha256(b"dirty worktree content\n").hexdigest() not in markdown


def test_source_anchor_ignores_replacement_commit(tmp_path: Path) -> None:
    original = b"original committed content\n"
    replacement = b"replacement commit content\n"
    repository, revision = _repository(tmp_path, {"source.txt": original})
    (repository / "source.txt").write_bytes(replacement)
    _git(repository, "add", "source.txt")
    _git(repository, "commit", "--quiet", "-m", "replacement commit")
    replacement_revision = _git(repository, "rev-parse", "HEAD")
    _git(repository, "replace", revision, replacement_revision)

    markdown = export_pr_markdown(
        _report(),
        repository_root=repository,
        revision=revision,
        source_anchors=[_anchor("source.txt")],
    )

    assert hashlib.sha256(original).hexdigest() in markdown
    assert hashlib.sha256(replacement).hexdigest() not in markdown


def test_source_anchor_ignores_replacement_blob(tmp_path: Path) -> None:
    original = b"original blob content\n"
    replacement = b"replacement blob content\n"
    repository, revision = _repository(
        tmp_path,
        {"source.txt": original, "replacement.txt": replacement},
    )
    original_blob = _git(repository, "rev-parse", f"{revision}:source.txt")
    replacement_blob = _git(repository, "rev-parse", f"{revision}:replacement.txt")
    _git(repository, "replace", original_blob, replacement_blob)

    markdown = export_pr_markdown(
        _report(),
        repository_root=repository,
        revision=revision,
        source_anchors=[_anchor("source.txt")],
    )

    assert hashlib.sha256(original).hexdigest() in markdown
    assert hashlib.sha256(replacement).hexdigest() not in markdown


def test_source_anchor_hashes_valid_unicode_line_bytes(tmp_path: Path) -> None:
    content = "first α\nsecond 雪☃\nthird\n".encode()
    repository, revision = _repository(tmp_path, {"unicode.txt": content})

    markdown = export_pr_markdown(
        _report(),
        repository_root=repository,
        revision=revision,
        source_anchors=[_anchor("unicode.txt", start_line=2)],
    )

    assert hashlib.sha256("second 雪☃\n".encode()).hexdigest() in markdown
