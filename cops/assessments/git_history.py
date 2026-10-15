"""Bounded, read-only inspection of reachable Git history for synthetic secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = "cops.git-history-scan/v1"
_OID = re.compile(rb"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_TREE_HEADER = re.compile(rb"(\d{6}) (blob|tree|commit) ([0-9a-f]{40}(?:[0-9a-f]{24})?)")
_SYNTHETIC_PATTERNS = (
    ("cops-test-token-v1", re.compile(rb"COPS_TEST_TOKEN_[A-Za-z0-9_-]{16,128}")),
    ("cops-synthetic-secret-v1", re.compile(rb"COPS_SYNTHETIC_SECRET_[A-Za-z0-9_-]{16,128}")),
)
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_GIT_METADATA_ENTRIES = 250_000
_MAX_TREE_OUTPUT_BYTES = 16 * 1024 * 1024


class GitHistoryScanError(ValueError):
    """A content-free scanner failure safe to show to an operator."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ScanLimits:
    """Hard limits for a single scan."""

    max_commits: int = 100
    max_files: int = 5_000
    max_blob_bytes: int = 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_matches: int = 1_000
    timeout_seconds: int = 30

    def validated(self) -> "ScanLimits":
        ceilings = {
            "max_commits": 10_000,
            "max_files": 100_000,
            "max_blob_bytes": 8 * 1024 * 1024,
            "max_total_bytes": 64 * 1024 * 1024,
            "max_matches": 10_000,
            "timeout_seconds": 120,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if type(value) is not int or value < 1 or value > ceiling:
                raise GitHistoryScanError(f"invalid_{name}")
        return self


@dataclass(frozen=True)
class _GitResult:
    stdout: bytes
    returncode: int
    overflow: bool


def _safe_environment() -> dict[str, str]:
    permitted = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG")
    environment = {name: os.environ[name] for name in permitted if name in os.environ}
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_git(
    git: str,
    root: Path,
    git_dir: Path,
    arguments: Sequence[str],
    *,
    output_limit: int,
    deadline: float,
) -> _GitResult:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GitHistoryScanError("scan_timeout")
    command = [git, f"--git-dir={git_dir}", f"--work-tree={root}", *arguments]
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
    except OSError as error:
        raise GitHistoryScanError("git_execution_failed") from error

    output = bytearray()
    overflow = False

    def read_output() -> None:
        nonlocal overflow
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(min(65_536, output_limit + 1 - len(output)))
            if not chunk:
                return
            output.extend(chunk)
            if len(output) > output_limit:
                overflow = True
                process.kill()
                return

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        reader.join(timeout=1)
        raise GitHistoryScanError("scan_timeout") from error
    reader.join(timeout=1)
    if reader.is_alive():
        process.kill()
        process.wait()
        raise GitHistoryScanError("git_output_read_failed")
    return _GitResult(bytes(output[:output_limit]), returncode, overflow)


def _validate_git_metadata_tree(git_dir: Path) -> None:
    """Reject metadata paths that Git could follow outside the validated directory."""

    pending = [git_dir]
    entries_examined = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    entries_examined += 1
                    if entries_examined > _MAX_GIT_METADATA_ENTRIES:
                        raise GitHistoryScanError("git_metadata_entry_limit")
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise GitHistoryScanError("git_metadata_unreadable") from error
                    if stat.S_ISLNK(metadata.st_mode):
                        raise GitHistoryScanError("git_metadata_symlink")
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))
                    elif not stat.S_ISREG(metadata.st_mode):
                        raise GitHistoryScanError("unsupported_git_metadata_type")
        except GitHistoryScanError:
            raise
        except OSError as error:
            raise GitHistoryScanError("git_metadata_unreadable") from error


def _validate_repository_root(root: Path) -> tuple[Path, Path]:
    if not root.is_absolute():
        raise GitHistoryScanError("root_must_be_absolute")
    absolute = Path(os.path.abspath(root))
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise GitHistoryScanError("root_unavailable") from error
    if absolute != resolved or absolute.is_symlink() or not absolute.is_dir():
        raise GitHistoryScanError("root_symlink_or_not_directory")

    git_dir = absolute / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise GitHistoryScanError("unsupported_git_directory")
    _validate_git_metadata_tree(git_dir)
    if os.path.lexists(git_dir / "commondir"):
        raise GitHistoryScanError("linked_git_directory_unsupported")
    for relative in ("objects/info/alternates", "objects/info/http-alternates"):
        if os.path.lexists(git_dir / relative):
            raise GitHistoryScanError("alternate_object_store_unsupported")

    config = git_dir / "config"
    if config.exists():
        try:
            if config.stat().st_size > _MAX_CONFIG_BYTES:
                raise GitHistoryScanError("git_config_too_large")
            config_bytes = config.read_bytes()
        except OSError as error:
            raise GitHistoryScanError("git_config_unreadable") from error
        if re.search(rb"(?im)^\s*\[\s*include(?:if)?\b", config_bytes):
            raise GitHistoryScanError("git_config_include_unsupported")
    return absolute, git_dir


def _safe_path(path_bytes: bytes) -> tuple[str | None, bool]:
    if not path_bytes or len(path_bytes) > 4096 or b"\\" in path_bytes:
        return None, False
    try:
        path = path_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, False
    parts = path.split("/")
    if (
        path.startswith("/")
        or any(part in ("", ".", "..") for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        return None, False
    if any(pattern.search(path_bytes) for _, pattern in _SYNTHETIC_PATTERNS):
        digest = hashlib.sha256(path_bytes).hexdigest()
        return f"redacted-path/sha256-{digest}", True
    return path, False


def _repository_fingerprint(head: str | None, commits: list[str]) -> str:
    material = "\n".join([SCHEMA_VERSION, head or "empty", *commits]).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _fingerprint(value: bytes) -> str:
    return hashlib.sha256(b"cops.synthetic-credential/v1\0" + value).hexdigest()


def scan_git_history(root: str | os.PathLike[str], *, limits: ScanLimits | None = None) -> dict[str, Any]:
    """Inspect bounded reachable Git blobs without emitting matched values."""

    limits = (limits or ScanLimits()).validated()
    root_path, git_dir = _validate_repository_root(Path(root))
    git = shutil.which("git")
    if not git:
        raise GitHistoryScanError("git_unavailable")
    deadline = time.monotonic() + limits.timeout_seconds
    limitations = [
        "Only commits reachable from local refs and detached HEAD are inspected.",
        "Synthetic pattern inspection cannot prove provider-side revocation, rotation, or absence from unreachable Git objects.",
        "The repository must remain unchanged for the duration of this read-only scan.",
    ]
    truncated: set[str] = set()

    head_result = _run_git(
        git,
        root_path,
        git_dir,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        output_limit=128,
        deadline=deadline,
    )
    head: str | None = None
    if head_result.returncode == 0 and not head_result.overflow:
        candidate = head_result.stdout.strip()
        if _OID.fullmatch(candidate):
            head = candidate.decode("ascii")

    revision_arguments = ["rev-list", f"--max-count={limits.max_commits + 1}", "--all"]
    if head:
        revision_arguments.append("HEAD")
    revision_result = _run_git(
        git,
        root_path,
        git_dir,
        revision_arguments,
        output_limit=min((limits.max_commits + 1) * 66, 1024 * 1024),
        deadline=deadline,
    )
    if revision_result.returncode != 0:
        raise GitHistoryScanError("git_revision_enumeration_failed")
    if revision_result.overflow:
        truncated.add("commit_output")
    raw_commits = [line for line in revision_result.stdout.splitlines() if line]
    if any(not _OID.fullmatch(commit) for commit in raw_commits):
        raise GitHistoryScanError("invalid_git_revision_output")
    if len(raw_commits) > limits.max_commits:
        truncated.add("commits")
    commits = [commit.decode("ascii") for commit in raw_commits[: limits.max_commits]]
    repository_fingerprint = _repository_fingerprint(head, commits)

    occurrences: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    files_examined = 0
    blobs_examined = 0
    bytes_examined = 0
    stop = False

    for commit in commits:
        if stop:
            break
        tree_limit = min(_MAX_TREE_OUTPUT_BYTES, max(4096, (limits.max_files + 1) * 512))
        tree_result = _run_git(
            git,
            root_path,
            git_dir,
            ["ls-tree", "-rz", "--full-tree", commit],
            output_limit=tree_limit,
            deadline=deadline,
        )
        if tree_result.returncode != 0:
            truncated.add("tree_errors")
            continue
        if tree_result.overflow:
            truncated.add("tree_output")
        for record in tree_result.stdout.split(b"\0"):
            if not record:
                continue
            if files_examined >= limits.max_files:
                truncated.add("files")
                stop = True
                break
            files_examined += 1
            try:
                header, raw_path = record.split(b"\t", 1)
            except ValueError:
                truncated.add("invalid_tree_records")
                continue
            match = _TREE_HEADER.fullmatch(header)
            if not match:
                truncated.add("invalid_tree_records")
                continue
            mode, object_type, object_id = match.groups()
            if mode == b"120000":
                truncated.add("symlink_entries")
                continue
            if object_type != b"blob" or mode not in (b"100644", b"100755"):
                continue
            output_path, redacted_path = _safe_path(raw_path)
            if output_path is None:
                truncated.add("unsafe_paths")
                continue
            if redacted_path:
                truncated.add("redacted_paths")
            if bytes_examined >= limits.max_total_bytes:
                truncated.add("total_bytes")
                stop = True
                break
            remaining_bytes = limits.max_total_bytes - bytes_examined
            blob_limit = min(limits.max_blob_bytes, remaining_bytes)
            blob_result = _run_git(
                git,
                root_path,
                git_dir,
                ["cat-file", "blob", object_id.decode("ascii")],
                output_limit=blob_limit,
                deadline=deadline,
            )
            blobs_examined += 1
            bytes_examined += len(blob_result.stdout)
            if blob_result.overflow:
                truncated.add("blob_bytes")
            elif blob_result.returncode != 0:
                truncated.add("blob_errors")
                continue
            for pattern_id, pattern in _SYNTHETIC_PATTERNS:
                for secret_match in pattern.finditer(blob_result.stdout):
                    if len(occurrences) >= limits.max_matches:
                        truncated.add("matches")
                        stop = True
                        break
                    fingerprint = _fingerprint(secret_match.group(0))
                    key = (fingerprint, output_path, commit, pattern_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    occurrences.append(
                        {
                            "fingerprint": fingerprint,
                            "path": output_path,
                            "commit": commit,
                            "source": {
                                "kind": "git_blob",
                                "blob_oid": object_id.decode("ascii"),
                                "pattern_id": pattern_id,
                                "repository_fingerprint": repository_fingerprint,
                            },
                            "exposed": True,
                            "redacted": True,
                        }
                    )
                if stop:
                    break
            if stop:
                break

    if truncated:
        limitations.append("Coverage was limited by: " + ", ".join(sorted(truncated)) + ".")
    if not commits:
        status = "insufficient_evidence"
        limitations.append("No reachable commits were available for inspection.")
    elif occurrences:
        status = "exposure_observed"
    elif truncated:
        status = "insufficient_evidence"
    else:
        status = "no_synthetic_match_observed"

    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_id": f"git-history-{repository_fingerprint[:16]}",
        "kind": "git_history",
        "content": {
            "scanner_version": SCHEMA_VERSION,
            "source": {
                "kind": "git_repository",
                "repository_fingerprint": repository_fingerprint,
                "ref_scope": "all_reachable_local_refs_and_detached_head",
                "head_commit": head,
            },
            "occurrences": occurrences,
            "coverage": {
                "complete_within_configured_bounds": not truncated and bool(commits),
                "commits_examined": len(commits),
                "files_examined": files_examined,
                "blobs_examined": blobs_examined,
                "bytes_examined": bytes_examined,
                "matches_recorded": len(occurrences),
                "bounds": {
                    "max_commits": limits.max_commits,
                    "max_files": limits.max_files,
                    "max_blob_bytes": limits.max_blob_bytes,
                    "max_total_bytes": limits.max_total_bytes,
                    "max_matches": limits.max_matches,
                    "timeout_seconds": limits.timeout_seconds,
                },
            },
            "assessment_status": status,
            "containment_status": "unknown",
            "adapter_prerequisites": {
                "satisfied": [
                    {
                        "id": "registered-adapter:git-object-enumerator@1",
                        "implementation": SCHEMA_VERSION,
                        "tool": "git",
                    }
                ],
                "required": ["registered-adapter:provider-revocation-check@1"],
            },
            "limitations": limitations,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entrypoint with content-free errors."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="absolute path to an ordinary Git work tree")
    parser.add_argument("--max-commits", type=int, default=ScanLimits.max_commits)
    parser.add_argument("--max-files", type=int, default=ScanLimits.max_files)
    parser.add_argument("--max-blob-bytes", type=int, default=ScanLimits.max_blob_bytes)
    parser.add_argument("--max-total-bytes", type=int, default=ScanLimits.max_total_bytes)
    parser.add_argument("--max-matches", type=int, default=ScanLimits.max_matches)
    parser.add_argument("--timeout-seconds", type=int, default=ScanLimits.timeout_seconds)
    args = parser.parse_args(argv)
    try:
        result = scan_git_history(
            args.root,
            limits=ScanLimits(
                max_commits=args.max_commits,
                max_files=args.max_files,
                max_blob_bytes=args.max_blob_bytes,
                max_total_bytes=args.max_total_bytes,
                max_matches=args.max_matches,
                timeout_seconds=args.timeout_seconds,
            ),
        )
    except GitHistoryScanError as error:
        print(json.dumps({"error": error.code}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
