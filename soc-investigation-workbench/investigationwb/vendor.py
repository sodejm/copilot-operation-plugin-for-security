"""Pinned, unmodified Sentinel dependency and fail-closed handoff boundary."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

from .engine import ContractError, Document, digest, next_steps, require, validate
from .files import read_regular

PACKAGE = Path(__file__).resolve().parent.parent
IGNORED = {"__pycache__", ".pytest_cache", ".git", ".DS_Store"}


def verify_hunt(root: Path, query: Document) -> None:
    try:
        hunt = json.loads(read_regular(root / "hunts" / (query["hunt_id"] + ".json"), nofollow=True))
        require(type(hunt) is dict and type(hunt.get("surface_support")) is dict,
                "Requested canonical hunt contract is malformed.")
        require(hunt["surface_support"].get(query["surface"]) == "supported",
                "Hunt surface is missing, unsupported, or unverified.")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ContractError("Requested canonical hunt contract is unavailable or unsupported.") from exc


def verify_requirements(root: Path) -> None:
    # The shipped case is the consumer contract; Sentinel owns the hunt catalog.
    case = validate(json.loads(read_regular(PACKAGE / "examples/case.json")))
    for step in case["steps"]:
        verify_hunt(root, step["query"])


def inventory(root: Path) -> dict[str, str]:
    require(root.is_dir() and not root.is_symlink(), "Vendor directory is unavailable or unsafe.")
    files = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORED for part in relative.parts) or path.suffix == ".pyc":
            continue
        require(not path.is_symlink(), "Vendor snapshots cannot contain symlinks.")
        if path.is_file():
            files[relative.as_posix()] = sha256(path.read_bytes()).hexdigest()
    return files


def verify(package: Path = PACKAGE, source: Path | None = None) -> Document:
    try:
        require(not (package / "vendor").is_symlink(), "Vendor destination cannot be a symlink.")
        lock = json.loads(read_regular(package / "vendor-lock.json", nofollow=True))
        require(type(lock) is dict and type(lock["schema_version"]) is int
                and lock["schema_version"] == 1, "Unsupported vendor lock schema.")
        require(lock["files"] == inventory(package / "vendor" / "sentinel-hunt-workbench"),
                "Vendored Sentinel files have drifted; refresh from canonical source.")
        require(digest(lock["files"]) == lock["snapshot_hash"], "Vendor snapshot digest is invalid.")
        expected_skills = sorted(name for name in lock["files"]
                                 if name.startswith("skills/") and name.endswith("/SKILL.md"))
        require(bool(expected_skills) and lock["skills"] == expected_skills,
                "Canonical Sentinel skill inventory is incomplete or invalid.")
        require("scripts/huntwb.py" in lock["files"] and "hunts/H01.json" in lock["files"]
                and "LICENSE" in lock["files"], "Canonical Sentinel package is incomplete.")
        for skill in lock["skills"]:
            require(type(skill) is str and skill.startswith("skills/") and skill.endswith("/SKILL.md")
                    and ".." not in Path(skill).parts and skill in lock["files"],
                    "Vendor skill entry is invalid.")
        verify_requirements(package / "vendor" / "sentinel-hunt-workbench")
        if source is not None:
            current = inventory(source)
            # LICENSE is inherited from the upstream repository when absent in its package.
            if "LICENSE" not in current:
                current["LICENSE"] = sha256(read_regular(source.parent / "LICENSE", nofollow=True)).hexdigest()
            require(current == lock["files"], "Canonical Sentinel source has changed since vendoring.")
        return {"status": "verified", "snapshot_hash": lock["snapshot_hash"],
                "skills": lock["skills"], "source_state": lock["source_state"]}
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ContractError("Sentinel dependency or vendor lock is missing or malformed.") from exc


def sync(source: Path, package: Path = PACKAGE) -> Document:
    """Explicit maintainer operation; never performed implicitly during a case."""
    require(source.name == "sentinel-hunt-workbench", "Expected the canonical Sentinel package directory.")
    before = inventory(source)
    skills = sorted(name for name in before if name.startswith("skills/") and name.endswith("/SKILL.md"))
    require(bool(skills) and "scripts/huntwb.py" in before and "hunts/H01.json" in before,
            "Canonical Sentinel skills and catalog must exist before vendoring.")
    verify_requirements(source)
    inherited_license = (read_regular(source.parent / "LICENSE", nofollow=True)
                         if "LICENSE" not in before else None)
    lock_path = package / "vendor-lock.json"
    require(not lock_path.is_symlink(), "Vendor lock cannot be a symlink.")
    try:
        commit = subprocess.run(["git", "-C", str(source.parent), "rev-parse", "HEAD"],
                                check=True, capture_output=True, text=True).stdout.strip()
        provenance_paths = [source.name] + (["LICENSE"] if "LICENSE" not in before else [])
        dirty = subprocess.run(["git", "-C", str(source.parent), "status", "--porcelain", "--", *provenance_paths],
                               check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError("Cannot establish canonical repository provenance.") from exc
    require(len(commit) == 40 and all(c in "0123456789abcdef" for c in commit),
            "Canonical repository revision is invalid.")
    vendor_parent = package / "vendor"
    require(not vendor_parent.is_symlink(), "Vendor destination cannot be a symlink.")
    vendor_parent.mkdir(exist_ok=True)
    target = vendor_parent / source.name
    require(not target.is_symlink(), "Vendor destination cannot be a symlink.")
    with tempfile.TemporaryDirectory(dir=vendor_parent) as temporary:
        staged = Path(temporary) / source.name
        staged.mkdir()
        for name in before:
            destination = staged / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, destination)
        if inherited_license is not None:
            (staged / "LICENSE").write_bytes(inherited_license)
            require(read_regular(source.parent / "LICENSE", nofollow=True) == inherited_license,
                    "Inherited license changed during vendoring; retry from a stable snapshot.")
        require(inventory(source) == before, "Canonical source changed during vendoring; retry from a stable snapshot.")
        files = inventory(staged)
        require(all(files.get(name) == value for name, value in before.items()),
                "Copied dependency differs from its canonical source.")
        verify_requirements(staged)
        lock: dict[str, Any] = {
            "schema_version": 1,
            "upstream": "https://github.com/sodejm/copilot-operations-plugin-for-security",
            "source_subdirectory": source.name, "base_commit": commit,
            "source_state": "working_tree_snapshot" if dirty else "committed",
            "snapshot_hash": digest(files), "skills": skills, "files": files,
            "policy": "Exact upstream bytes. Update from source; never patch vendored flows.",
        }
        if target.exists():
            shutil.rmtree(target)
        shutil.move(str(staged), target)
        # Replacing the directory entry never follows a link introduced after the
        # initial check; the temporary file is created exclusively and privately.
        with tempfile.NamedTemporaryFile(mode="w", dir=package, delete=False, encoding="utf-8") as stream:
            temporary_lock = Path(stream.name)
            try:
                stream.write(json.dumps(lock, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
                require(not lock_path.is_symlink(), "Vendor lock cannot be a symlink.")
                os.replace(temporary_lock, lock_path)
            finally:
                temporary_lock.unlink(missing_ok=True)
    return verify(package, source)


def handoff(case: Document, step_id: str, package: Path = PACKAGE) -> Document:
    validate(case)
    require(step_id in {s["step_id"] for s in next_steps(case)["candidates"]},
            "Handoff requires a currently selected, budgeted step.")
    dependency = verify(package)
    step = next(s for s in case["steps"] if s["id"] == step_id)
    root = package / "vendor" / "sentinel-hunt-workbench"
    verify_hunt(root, step["query"])
    return {"step_id": step_id, "snapshot_hash": dependency["snapshot_hash"],
            "canonical_skills": [str(root / skill) for skill in dependency["skills"]],
            "sentinel_cli": str(root / "scripts" / "huntwb.py"),
            "request": {"scope": case["scope"], **step["query"]},
            "boundary": "Read the relevant canonical skill. Resolve aliases in authorized tools; use Sentinel to validate and render. This handoff executes no query."}
