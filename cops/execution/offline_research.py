"""Versioned, Linux-only profile for reading pinned local research fixtures."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cops.adapters.registry import ToolAdapter
from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest, timestamp

from .cleanup import SideEffectLedger
from .filesystem import SecureDirectoryError, open_directory_no_symlinks
from .sandbox import LinuxBubblewrapSandbox


class OfflineResearchError(ValueError):
    """An offline profile or its independently observed boundary is invalid."""


_LOCAL_TARGET = re.compile(r"local:[a-z0-9_-]{1,64}\Z")
_MAX_CORPUS_BYTES = 1024 * 1024
_MAX_ATTESTATION_AGE = timedelta(minutes=5)


def validate_offline_cat_adapter(adapter: ToolAdapter, *, expected_pin: str) -> None:
    """Bind the complete executable probe and argv template to the offline profile."""
    if type(adapter) is not ToolAdapter:
        raise OfflineResearchError("offline research cat adapter definition differs from the approved profile")
    verification = adapter.executable_verification
    action = adapter.actions.get("read_local_corpus")
    parameter = action.parameters.get("filename") if action is not None else None
    if not (
        adapter.tool == "cat"
        and adapter.version == "coreutils-9.4"
        and adapter.binary == "cat"
        and adapter.provenance == {
            "source": "https://www.gnu.org/software/coreutils/",
            "license": "GPL-3.0",
            "pinned_revision": "9.4",
        }
        and adapter.supported_environments == ["linux"]
        and set(adapter.actions) == {"read_local_corpus"}
        and action is not None
        and action.action == "read_local_corpus"
        and action.base_args == ["--"]
        and set(action.parameters) == {"filename"}
        and parameter is not None
        and parameter.name == "filename"
        and parameter.param_type == "string"
        and parameter.flag is None
        and parameter.required is True
        and parameter.default is None
        and parameter.allowed_values == []
        and parameter.regex_pattern == r"^corpus-[a-z0-9_-]{1,48}$"
        and verification is not None
        and verification.sha256 == expected_pin
        and verification.version_args == ("--version",)
        and verification.version_pattern == r"cat \(GNU coreutils\) (?P<version>[0-9.]+)"
        and verification.max_size_bytes == 268_435_456
    ):
        raise OfflineResearchError("offline research cat adapter definition differs from the approved profile")


def validate_offline_request(
    plan: ActionPlan,
    *,
    worker_identity: str,
    worker_inventory: Mapping[str, Any],
    cat_executable_sha256: str | None,
    sandbox: object,
    workspace_dir: Path | None,
    scope_guard: object,
    credential_resolver: object,
    egress_identity_verifier: object,
) -> Mapping[str, Any] | None:
    """Reject profile violations before a one-use approval is consumed."""
    profile = plan.offline_research
    if profile is None:
        return None
    if type(sandbox) is not LinuxBubblewrapSandbox:
        raise OfflineResearchError("offline research requires the production Linux sandbox")
    if profile["worker_identity"] != worker_identity:
        raise OfflineResearchError("offline research worker identity mismatch")
    if profile["worker_inventory_sha256"] != digest(dict(worker_inventory)):
        raise OfflineResearchError("offline research worker inventory digest mismatch")
    if workspace_dir is not None:
        raise OfflineResearchError("offline research requires an ephemeral private workspace")
    if scope_guard is not None or credential_resolver is not None or egress_identity_verifier is not None:
        raise OfflineResearchError("offline research cannot use external scope, credentials, or egress mediation")
    if plan.credential_references or plan.limits.get("egress_allowed") is not False:
        raise OfflineResearchError("offline research cannot resolve credentials or allow egress")
    if _LOCAL_TARGET.fullmatch(plan.target) is None:
        raise OfflineResearchError("offline research target must be a local profile identifier")

    names = [corpus["name"] for corpus in profile["corpora"]]
    if len(names) != len(set(names)):
        raise OfflineResearchError("offline research corpus names must be unique")
    allowed_files = {f"corpus-{name}" for name in names}
    has_cat = any(operation["tool"] == "cat" for operation in plan.operations)
    if has_cat and (
        cat_executable_sha256 is None
        or profile.get("cat_executable_sha256") != cat_executable_sha256
    ):
        raise OfflineResearchError("offline research cat executable pin mismatch")
    if not has_cat and "cat_executable_sha256" in profile:
        raise OfflineResearchError("offline research cannot claim an unused cat executable")
    for operation in plan.operations:
        if "egress_policy" in operation or "cleanup" in operation or operation.get("side_effects"):
            raise OfflineResearchError("offline research cannot request egress or side effects")
        if operation["tool"] == "inert":
            if operation["action"] != "print_status" or operation["arguments"] not in ({}, []):
                raise OfflineResearchError("offline inert fixtures cannot carry destinations")
            continue
        if (
            operation["tool"] != "cat"
            or operation["action"] != "read_local_corpus"
            or operation["tool_version"] != "coreutils-9.4"
            or not isinstance(operation["arguments"], Mapping)
            or set(operation["arguments"]) != {"filename"}
            or operation["arguments"]["filename"] not in allowed_files
        ):
            raise OfflineResearchError("offline research operation is outside the approved adapter profile")

    attestation = profile["isolation_attestation"]
    try:
        observed_at = timestamp(attestation["observed_at"])
    except (KeyError, ValueError) as err:
        raise OfflineResearchError("offline research isolation observation timestamp is invalid") from err
    age = datetime.now(UTC) - observed_at
    if age < timedelta(0) or age > _MAX_ATTESTATION_AGE:
        raise OfflineResearchError("offline research isolation observation is stale or future dated")
    return profile


def stage_corpora(
    profile: Mapping[str, Any], *, workspace: Path, workspace_fd: int, ledger: SideEffectLedger
) -> list[dict[str, str]]:
    """Copy bounded regular files by held directory descriptors and verify their approved digests."""
    staged: list[dict[str, str]] = []
    for corpus in profile["corpora"]:
        source = Path(corpus["path"])
        if not source.is_absolute() or ".." in source.parts:
            raise OfflineResearchError("offline corpus path must be absolute and traversal free")
        parent_fd = source_fd = destination_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(source.parent)
            source_fd = os.open(
                source.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
            source_info = os.fstat(source_fd)
            if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > _MAX_CORPUS_BYTES:
                raise OfflineResearchError("offline corpus must be a bounded regular file")
            destination = workspace / f"corpus-{corpus['name']}"
            effect = ledger.record_effect(
                step_id=f"offline-corpus-{corpus['name']}",
                resource_type="file",
                target=str(destination),
                cleanup_action="delete",
                metadata={"purpose": "offline_research_corpus"},
            )
            destination_fd = os.open(
                f"corpus-{corpus['name']}",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=workspace_fd,
            )
            ledger.record_created_identity(effect, creation_fd=destination_fd)
            hasher = hashlib.sha256()
            copied = 0
            while chunk := os.read(source_fd, 65_536):
                copied += len(chunk)
                if copied > _MAX_CORPUS_BYTES:
                    raise OfflineResearchError("offline corpus exceeds the profile size limit")
                hasher.update(chunk)
                pending = memoryview(chunk)
                while pending:
                    written = os.write(destination_fd, pending)
                    if written <= 0:
                        raise OfflineResearchError("offline corpus staging made no progress")
                    pending = pending[written:]
            after = os.fstat(source_fd)
            if (
                copied != source_info.st_size
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (source_info.st_dev, source_info.st_ino, source_info.st_size, source_info.st_mtime_ns)
                or hasher.hexdigest() != corpus["sha256"]
            ):
                raise OfflineResearchError("offline corpus changed or failed its approved digest")
            os.fsync(destination_fd)
            staged.append({"name": corpus["name"], "sha256": corpus["sha256"]})
        except (OSError, SecureDirectoryError) as err:
            raise OfflineResearchError("offline corpus could not be safely staged") from err
        finally:
            for descriptor in (destination_fd, source_fd, parent_fd):
                if descriptor >= 0:
                    os.close(descriptor)
    return staged


def verify_isolation_observation(
    profile: Mapping[str, Any], *, sandbox: LinuxBubblewrapSandbox,
    workspace: Path, workspace_fd: int,
) -> dict[str, Any]:
    """Measure a fresh sandbox and compare it with the approval-bound observation."""
    observation = sandbox.observe_offline_isolation(cwd=workspace, expected_workspace_fd=workspace_fd)
    if observation["digest"] != profile["isolation_attestation"]["digest"]:
        raise OfflineResearchError("offline isolation observation does not match the approved attestation")
    return observation
