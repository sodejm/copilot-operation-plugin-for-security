"""Bounded, local-only collection of safe repository context descriptors."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

MAX_DESCRIPTOR_BYTES = 1_000_000

_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".terraform",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "target",
        "vendor",
    }
)
_DEPENDENCY_MANIFESTS = frozenset(
    {
        "cargo.lock",
        "cargo.toml",
        "composer.json",
        "composer.lock",
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)
_CI_NAMES = frozenset({".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile"})
_SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
    }
)
_SENSITIVE_DIRECTORIES = frozenset({".aws", ".gnupg", ".ssh", "credentials", "secrets"})


@dataclass(frozen=True)
class ContextArtifact:
    """A safe artifact descriptor. File contents are deliberately absent."""

    path: str
    category: Literal["dependency_manifest", "kubernetes_rendered", "terraform_plan", "ci_workflow"]
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "category": self.category, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class RepositoryContext:
    """Bounded local repository context for preview and planning."""

    version: str
    artifacts: tuple[ContextArtifact, ...]
    scanned_files: int
    truncated: bool
    network_collection: Literal["separate"] = "separate"

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "scanned_files": self.scanned_files,
            "truncated": self.truncated,
            "network_collection": self.network_collection,
        }


def _is_sensitive(path: Path) -> bool:
    name = path.name.lower()
    if name in _SENSITIVE_NAMES or name.startswith(".env."):
        return True
    if name.endswith((".key", ".pem", ".p12", ".pfx", ".tfstate", ".tfstate.backup")):
        return True
    return any(part.lower() in _SENSITIVE_DIRECTORIES for part in path.parts)


def _read_verified_regular_file(path: Path, limit: int = MAX_DESCRIPTOR_BYTES) -> bytes:
    """Read a bounded regular file while rejecting links, replacements, and special files."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise OSError("descriptor is not a bounded regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise OSError("descriptor changed before read")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) > limit or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OSError("descriptor changed during read or exceeded its bound")
        return data
    finally:
        os.close(descriptor)


def _ci_workflow(relative: Path) -> bool:
    lowered = tuple(part.lower() for part in relative.parts)
    return (
        relative.name.lower() in _CI_NAMES
        or (
            len(lowered) >= 3
            and lowered[0:2] == (".github", "workflows")
            and relative.suffix.lower() in {".yml", ".yaml"}
        )
        or (len(lowered) >= 2 and lowered[0:2] == (".circleci", "config.yml"))
    )


def _content_category(relative: Path, data: bytes) -> str | None:
    suffix = relative.suffix.lower()
    text = data.decode("utf-8", errors="replace")
    if suffix == ".json" and (relative.name.endswith(".tfplan.json") or relative.name == "plan.json"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            return None
        if (
            isinstance(document, dict)
            and "format_version" in document
            and ("planned_values" in document or "resource_changes" in document)
        ):
            return "terraform_plan"
    if suffix in {".yml", ".yaml"} and "apiVersion:" in text and "kind:" in text:
        if any(
            re.fullmatch(r"kind:\s*secret(?:\s*#.*)?", line.strip(), flags=re.IGNORECASE) for line in text.splitlines()
        ):
            return None
        rendered_path = any(part.lower() in {"rendered", "manifests", "output"} for part in relative.parts)
        if "# Source:" in text or rendered_path:
            return "kubernetes_rendered"
    return None


def collect_repository_context(
    root: str | Path,
    *,
    max_files: int = 10_000,
    max_artifacts: int = 1_000,
) -> RepositoryContext:
    """Collect safe local descriptors without network access or returned file content."""
    if max_files < 1 or max_artifacts < 1:
        raise ValueError("repository context limits must be positive")
    repository = Path(root).resolve(strict=True)
    if not repository.is_dir():
        raise ValueError(f"repository context root is not a directory: {repository}")
    artifacts: list[ContextArtifact] = []
    scanned = 0
    truncated = False

    for current, directories, files in os.walk(repository, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.lower() not in _IGNORED_DIRECTORIES
            and directory.lower() not in _SENSITIVE_DIRECTORIES
            and not (current_path / directory).is_symlink()
        )
        for filename in sorted(files):
            if scanned >= max_files or len(artifacts) >= max_artifacts:
                truncated = True
                break
            path = current_path / filename
            scanned += 1
            try:
                relative = path.relative_to(repository)
            except ValueError:
                continue
            if path.is_symlink() or _is_sensitive(relative):
                continue
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DESCRIPTOR_BYTES:
                continue
            category: str | None = None
            lower_name = filename.lower()
            if lower_name in _DEPENDENCY_MANIFESTS:
                category = "dependency_manifest"
            elif _ci_workflow(relative):
                category = "ci_workflow"
            elif path.suffix.lower() in {".json", ".yaml", ".yml"}:
                try:
                    category = _content_category(relative, _read_verified_regular_file(path))
                except OSError:
                    continue
            if category is None:
                continue
            artifacts.append(ContextArtifact(relative.as_posix(), category, metadata.st_size))
        if truncated:
            break

    return RepositoryContext(
        version="cops.repository-context/v1",
        artifacts=tuple(sorted(artifacts, key=lambda artifact: (artifact.category, artifact.path))),
        scanned_files=scanned,
        truncated=truncated,
    )
