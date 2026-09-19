"""Pinned, unmodified Sentinel dependency and fail-closed handoff boundary."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from .engine import ContractError, Document, HASH, digest, fields, next_steps, require, validate
from .files import open_regular, read_regular

PACKAGE = Path(__file__).resolve().parent.parent
IGNORED = {"__pycache__", ".pytest_cache", ".git", ".DS_Store"}
UPSTREAM = "https://github.com/sodejm/copilot-operations-plugin-for-security"
ORIGINS = {UPSTREAM, UPSTREAM + ".git",
           "git@github.com:sodejm/copilot-operations-plugin-for-security.git",
           "ssh://git@github.com/sodejm/copilot-operations-plugin-for-security.git"}
SOURCE_SUBDIRECTORY = "sentinel-hunt-workbench"
POLICY = "Exact upstream bytes. Update from source; never patch vendored flows."
DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    prefix + suffix for prefix in ("COM", "LPT") for suffix in "123456789¹²³"}


def validate_paths(names) -> None:
    entries = {}
    for name in names:
        require(type(name) is str and bool(name) and name != "."
                and not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
                and PurePosixPath(name).as_posix() == name, "Vendor inventory path is invalid.")
        parts = PurePosixPath(name).parts
        for index, part in enumerate(parts):
            require(not any(ord(char) < 32 or char in '<>:"\\|?*' for char in part)
                    and not part.endswith((".", " ")) and part.split(".")[0].upper() not in DEVICES,
                    "Vendor inventory path is incompatible with Windows.")
            prefix = "/".join(parts[:index + 1])
            entry = (prefix, index == len(parts) - 1)
            require(entries.setdefault(prefix.casefold(), entry) == entry,
                    "Vendor inventory paths have a case or file/directory collision.")


def git_inspect(source: Path, *args: str) -> bytes:
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(source.parent)]
    try:
        if args[0] == "status":
            # Refreshing tracked files can invoke configured clean/process filters.
            filters = subprocess.run([*command, "config", "--null", "--name-only", "--get-regexp",
                                      r"^filter\..*\.(clean|smudge|process|required)$"], capture_output=True)
            require(filters.returncode in (0, 1), "Cannot inspect repository filter configuration.")
            for key in filters.stdout.split(b"\0"):
                if key:
                    name = os.fsdecode(key)
                    command += ["-c", name + ("=false" if name.endswith(".required") else "=")]
        return subprocess.run([*command, *args], check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError("Cannot establish canonical repository provenance.") from exc


def source_revision(source: Path) -> str:
    require(source.name == SOURCE_SUBDIRECTORY, "Expected the canonical Sentinel package directory.")
    root = Path(os.fsdecode(git_inspect(source, "rev-parse", "--show-toplevel").rstrip(b"\r\n")))
    require(root.resolve() == source.parent.resolve(), "Canonical package must be at the repository root.")
    origins = git_inspect(source, "config", "--local", "--get-all", "remote.origin.url").splitlines()
    require(len(origins) == 1 and origins[0] in {url.encode() for url in ORIGINS},
            "Repository origin must identify the allowlisted canonical source.")
    commit = git_inspect(source, "rev-parse", "HEAD").strip()
    require(re.fullmatch(b"[0-9a-f]{40}", commit), "Canonical repository revision is invalid.")
    return commit.decode("ascii")


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


def reject_redirect(path: Path) -> None:
    try:
        entry = path.lstat()
    except FileNotFoundError:
        return
    # is_symlink() misses Windows junctions on supported Python 3.11 hosts.
    require(not stat.S_ISLNK(entry.st_mode)
            and not getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
            "Vendor entries cannot be symlinks or Windows reparse points.")


def inventory(root: Path, *, installed: bool = False) -> dict[str, str]:
    reject_redirect(root)
    require(root.is_dir(), "Vendor directory is unavailable or unsafe.")
    files = {}
    directories = [root]
    while directories:
        directory = directories.pop()
        reject_redirect(directory)
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root)
            if path.name in IGNORED or path.suffix == ".pyc":
                require(not installed, "Installed dependency contains untracked cache or metadata entries.")
                continue
            reject_redirect(path)
            require(path.is_file() or path.is_dir(), "Vendor entries must be regular files or directories.")
            if path.is_dir():
                directories.append(path)
                continue
            checksum = sha256()
            with open_regular(path, nofollow=True) as stream:
                for chunk in iter(lambda: stream.read(64 * 1024), b""):
                    checksum.update(chunk)
            files[relative.as_posix()] = checksum.hexdigest()
    validate_paths(files)
    return dict(sorted(files.items()))


def validate_lock(lock: Document) -> None:
    fields(lock, "schema_version upstream source_subdirectory base_commit source_state snapshot_hash skills files policy")
    require(type(lock["schema_version"]) is int and lock["schema_version"] == 1,
            "Unsupported vendor lock schema.")
    require(lock["upstream"] == UPSTREAM and lock["source_subdirectory"] == SOURCE_SUBDIRECTORY
            and lock["policy"] == POLICY, "Vendor provenance does not match the canonical source policy.")
    require(type(lock["base_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", lock["base_commit"]),
            "Vendor source revision is invalid.")
    require(lock["source_state"] in ("committed", "working_tree_snapshot"),
            "Vendor source state is invalid.")
    require(type(lock["snapshot_hash"]) is str and HASH.fullmatch(lock["snapshot_hash"]),
            "Vendor snapshot digest is invalid.")
    require(type(lock["files"]) is dict and type(lock["skills"]) is list,
            "Vendor inventory shape is invalid.")
    validate_paths(lock["files"])
    for checksum in lock["files"].values():
        require(type(checksum) is str and HASH.fullmatch(checksum), "Vendor file digest is invalid.")


def verify(package: Path = PACKAGE, source: Path | None = None) -> Document:
    try:
        reject_redirect(package / "vendor")
        lock = json.loads(read_regular(package / "vendor-lock.json", nofollow=True))
        validate_lock(lock)
        require(lock["files"] == inventory(package / "vendor" / SOURCE_SUBDIRECTORY, installed=True),
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
            source_revision(source)
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
    commit = source_revision(source)
    before = inventory(source)
    skills = sorted(name for name in before if name.startswith("skills/") and name.endswith("/SKILL.md"))
    require(bool(skills) and "scripts/huntwb.py" in before and "hunts/H01.json" in before,
            "Canonical Sentinel skills and catalog must exist before vendoring.")
    verify_requirements(source)
    inherited_license = (read_regular(source.parent / "LICENSE", nofollow=True)
                         if "LICENSE" not in before else None)
    lock_path = package / "vendor-lock.json"
    reject_redirect(lock_path)
    provenance_paths = [source.name] + (["LICENSE"] if "LICENSE" not in before else [])
    dirty = git_inspect(source, "status", "--porcelain", "--untracked-files=all", "--", *provenance_paths).strip()
    ignored = git_inspect(source, "ls-files", "--others", "--ignored", "--exclude-standard", "-z",
                          "--", *provenance_paths).split(b"\0")
    # NUL-delimited bytes preserve unusual filenames; excluded caches are not copy candidates.
    candidates = {os.fsencode(f"{source.name}/{name}") for name in before}
    if inherited_license is not None:
        candidates.add(b"LICENSE")
    require(not candidates.intersection(ignored),
            "Canonical source contains Git-ignored files; remove them before vendoring.")
    vendor_parent = package / "vendor"
    reject_redirect(vendor_parent)
    vendor_parent.mkdir(exist_ok=True)
    target = vendor_parent / source.name
    reject_redirect(target)
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
        files = inventory(staged, installed=True)
        require(all(files.get(name) == value for name, value in before.items()),
                "Copied dependency differs from its canonical source.")
        verify_requirements(staged)
        lock: dict[str, Any] = {
            "schema_version": 1,
            "upstream": UPSTREAM,
            "source_subdirectory": SOURCE_SUBDIRECTORY, "base_commit": commit,
            "source_state": "working_tree_snapshot" if dirty else "committed",
            "snapshot_hash": digest(files), "skills": skills, "files": files,
            "policy": POLICY,
        }
        validate_lock(lock)
        reject_redirect(vendor_parent)
        reject_redirect(target)
        reject_redirect(lock_path)
        if target.exists():
            shutil.rmtree(target)
        shutil.move(str(staged), target)
        # Replacing the directory entry never follows a link introduced after the
        # initial check; the temporary file is created exclusively and privately.
        temporary_lock = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=package, delete=False, encoding="utf-8") as stream:
                temporary_lock = Path(stream.name)
                stream.write(json.dumps(lock, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            reject_redirect(lock_path)
            os.replace(temporary_lock, lock_path)
        finally:
            if temporary_lock is not None:
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
    relative_root = PurePosixPath("vendor") / SOURCE_SUBDIRECTORY
    return {"step_id": step_id, "snapshot_hash": dependency["snapshot_hash"],
            "canonical_skills": [(relative_root / skill).as_posix() for skill in dependency["skills"]],
            "sentinel_cli": (relative_root / "scripts" / "huntwb.py").as_posix(),
            "request": {"scope": case["scope"], **step["query"]},
            "boundary": "Read the relevant canonical skill. Resolve aliases in authorized tools; use Sentinel to validate and render. This handoff executes no query."}
