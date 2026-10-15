"""Fail-closed Docker launcher for synthetic service acceptance only."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .acceptance_cases import ACCEPTANCE_CASE_IDS
from .source_snapshot import CONTRACT_SCHEMAS, MAX_BYTES, MAX_FILES, allowed_source, bounded_read, manifest_digest

SCHEMA_VERSION = "cops.laboratory-acceptance-gate/v1"
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
_CONTAINER = re.compile(r"[0-9a-f]{64}")
_OUTPUT_BYTES = 1024 * 1024
_OWNER_LABEL = "org.cops.acceptance-nonce"


def _snapshot(repository: Path, destination: Path) -> str:
    """Copy only the acceptance runtime and fixtures; omit Git and host secrets."""
    repository = repository.resolve(strict=True)
    source_root = repository / "cops"
    paths = sorted(path for path in source_root.rglob("*") if allowed_source(path.relative_to(repository).as_posix()))
    paths.extend(repository / relative for relative in sorted(CONTRACT_SCHEMAS) if (repository / relative).exists())
    paths.append(repository / "scripts" / "check_laboratory.py")
    manifest: list[dict[str, str]] = []
    total = 0
    destination.chmod(0o755)
    if len(paths) > MAX_FILES:
        raise ValueError("acceptance source snapshot exceeds its file budget")
    for path in paths:
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(repository)
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if repository in parent.parents):
            raise ValueError("acceptance snapshot rejects symbolic links")
        if not path.is_file():
            continue
        raw = bounded_read(path)
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError("acceptance source snapshot exceeds its byte budget")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        for directory in target.parents:
            if directory == destination:
                break
            directory.chmod(0o755)
        target.write_bytes(raw)
        target.chmod(0o644)
        manifest.append({"path": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()})
    digest = manifest_digest(manifest)
    (destination / "source-manifest.json").write_text(json.dumps({"sha256": digest, "files": manifest}, sort_keys=True))
    (destination / "source-manifest.json").chmod(0o644)
    return digest


def _inspect_configuration(value: dict[str, Any], *, image: str, snapshot: Path, nonce: str, digest: str) -> None:
    """Reject any deviation before starting the container."""
    host = value["HostConfig"]
    config = value["Config"]
    mounts = value["Mounts"]
    required_environment = {
        f"COPS_LABORATORY_CONTAINER_NONCE={nonce}",
        f"COPS_LABORATORY_SOURCE_DIGEST={digest}",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONPATH=/opt/cops-src",
    }
    checks = (
        value["Image"] == image,
        host["NetworkMode"] == "none",
        host["ReadonlyRootfs"] is True,
        host["Privileged"] is False,
        host.get("PublishAllPorts", False) is False,
        not host.get("PortBindings"),
        not host.get("Devices"),
        not host.get("DeviceRequests"),
        not host.get("CapAdd"),
        "ALL" in host.get("CapDrop", []),
        any(option in {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"} for option in host.get("SecurityOpt", [])),
        host.get("PidMode", "") == "",
        host.get("IpcMode", "") == "private",
        host.get("PidsLimit") == 128,
        host.get("Memory") == 512 * 1024 * 1024,
        host.get("NanoCpus") == 1_000_000_000,
        host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,size=128m,mode=1777"},
        config.get("Labels", {}).get(_OWNER_LABEL) == nonce,
        config["User"] == "65532:65532",
        config["WorkingDir"] == "/opt/cops-src",
        config["Entrypoint"] == ["python"],
        config["Cmd"] == ["scripts/check_laboratory.py", "--container-child"],
        required_environment <= set(config.get("Env", [])),
        len(mounts) == 1,
    )
    if not all(checks):
        raise ValueError("container inspection rejected isolation, resource, or command configuration")
    mount = mounts[0]
    if not (
        mount["Type"] == "bind"
        and Path(mount["Source"]).resolve() == snapshot.resolve()
        and mount["Destination"] == "/opt/cops-src"
        and mount["RW"] is False
    ):
        raise ValueError("container inspection rejected source mount")


def _docker_command(docker: str, arguments: list[str], *, seconds: int = 15) -> subprocess.CompletedProcess[str]:
    """Bound both streams while retaining a deadline, including daemon errors."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen([docker, *arguments], stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + seconds
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired("docker acceptance command", seconds)
                if stdout.tell() > _OUTPUT_BYTES or stderr.tell() > _OUTPUT_BYTES:
                    raise ValueError("Docker acceptance output exceeds its budget")
                time.sleep(0.02)
            if stdout.tell() > _OUTPUT_BYTES or stderr.tell() > _OUTPUT_BYTES:
                raise ValueError("Docker acceptance output exceeds its budget")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(arguments, process.returncode, stdout.read(_OUTPUT_BYTES).decode("utf-8", "replace"), stderr.read(_OUTPUT_BYTES).decode("utf-8", "replace"))


def run_container_acceptance(repository: Path, *, image: str, timeout: int = 240) -> tuple[int, dict[str, Any]]:
    """Use a preinstalled immutable image; never pull, install, or inherit sockets."""
    if not _IMAGE.fullmatch(image):
        raise ValueError("laboratory image must be an immutable local sha256 image ID")
    if not 30 <= timeout <= 600:
        raise ValueError("laboratory timeout must be between 30 and 600 seconds")
    docker = shutil.which("docker")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "status": "blocked", "cases": [], "failures": [],
        "blockers": [], "isolation": {"verified": False, "mechanism": "docker-network-none"},
        "summary": {"cases_passed": 0, "cases_total": len(ACCEPTANCE_CASE_IDS), "functional_evidence_only": True},
    }
    if docker is None:
        result["blockers"] = ["Docker CLI is unavailable; provision the isolated acceptance runtime"]
        return 2, result

    def command(arguments: list[str], *, seconds: int = 15) -> subprocess.CompletedProcess[str]:
        return _docker_command(docker, arguments, seconds=seconds)

    # Fail before copying source or creating a container when prerequisites are absent.
    try:
        ready = command(["info", "--format", "{{.ServerVersion}}"], seconds=5)
        if ready.returncode:
            result["blockers"] = ["Docker daemon is unavailable; isolated acceptance did not run"]
            return 2, result
        installed = command(["image", "inspect", image, "--format", "{{.Id}}"])
        if installed.returncode or installed.stdout.strip() != image:
            result["blockers"] = ["pinned laboratory image is not installed; no image was pulled"]
            return 2, result
    except (OSError, subprocess.SubprocessError, ValueError):
        result["blockers"] = ["Docker readiness probe failed or exceeded its deadline"]
        return 2, result

    container_id: str | None = None
    cleanup_verified = False
    with tempfile.TemporaryDirectory(prefix="cops-isolated-source-") as temporary:
        snapshot = Path(temporary)
        nonce = uuid.uuid4().hex
        container_name = f"cops-acceptance-{nonce}"
        create_attempted = False
        stage = "source-snapshot"
        try:
            digest = _snapshot(repository, snapshot)
            result["launcher"] = {"image_id": image, "source_digest": digest, "nonce": nonce}
            create_attempted = True
            stage = "container-create"
            created = command([
                "create", "--name", container_name, "--label", f"{_OWNER_LABEL}={nonce}",
                "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", "65532:65532", "--pids-limit", "128",
                "--memory", "512m", "--cpus", "1", "--ipc", "private", "--no-healthcheck",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,mode=1777", "--entrypoint", "python",
                "--mount", f"type=bind,src={snapshot},dst=/opt/cops-src,readonly",
                "--workdir", "/opt/cops-src", "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--env", "PYTHONPATH=/opt/cops-src", "--env", f"COPS_LABORATORY_CONTAINER_NONCE={nonce}",
                "--env", f"COPS_LABORATORY_SOURCE_DIGEST={digest}", image,
                "scripts/check_laboratory.py", "--container-child",
            ])
            candidate = created.stdout.strip()
            if created.returncode or not _CONTAINER.fullmatch(candidate):
                raise ValueError("Docker could not create the restricted acceptance container")
            container_id = candidate
            stage = "configuration-inspection"
            inspected = command(["inspect", container_id])
            if inspected.returncode:
                raise ValueError("Docker container inspection failed before execution")
            _inspect_configuration(json.loads(inspected.stdout)[0], image=image, snapshot=snapshot, nonce=nonce, digest=digest)
            stage = "acceptance-execution"
            executed = command(["start", "--attach", container_id], seconds=timeout)
            if len(executed.stdout) > 1024 * 1024:
                raise ValueError("acceptance report exceeds its output budget")
            report = json.loads(executed.stdout)
            stage = "exit-verification"
            state = command(["inspect", container_id, "--format", "{{json .State}}"])
            final_state = json.loads(state.stdout) if state.returncode == 0 else {}
            if final_state.get("Running") is not False or final_state.get("ExitCode") != 0:
                raise ValueError("acceptance container did not exit successfully")
            evidence = report.get("isolation", {}).get("evidence", [])
            cases = report.get("cases", [])
            expected_cases = set(ACCEPTANCE_CASE_IDS)
            stage = "report-verification"
            if not (
                executed.returncode == 0 and report.get("schema_version") == SCHEMA_VERSION
                and report.get("status") == "passed" and report.get("isolation", {}).get("verified") is True
                and report.get("summary", {}).get("cases_passed") == len(expected_cases)
                and report.get("summary", {}).get("cases_total") == len(expected_cases)
                and report.get("summary", {}).get("functional_evidence_only") is False
                and f"launcher_nonce={nonce}" in evidence and f"source_sha256={digest}" in evidence
                and not report.get("failures") and not report.get("blockers")
                and isinstance(cases, list) and len(cases) == len(expected_cases)
                and all(isinstance(case, dict) and case.get("passed") is True and not case.get("failures") for case in cases)
                and {case.get("name") for case in cases} == expected_cases
                and report.get("strict_preflight", {}).get("passed") is True
            ):
                raise ValueError("container report failed source, correlation, or acceptance verification")
            report["launcher"] = result["launcher"]
            report["launcher"]["configuration_inspected"] = True
            result = report
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError) as exc:
            result["status"] = "failed"
            result["failures"] = [f"isolated acceptance failed at {stage} ({type(exc).__name__}); raw runtime output withheld"]
        finally:
            if create_attempted:
                try:
                    # Recover a timed-out create by its unique name, then verify ownership.
                    owned = command(["inspect", container_id or container_name])
                    value = json.loads(owned.stdout)[0] if owned.returncode == 0 else {}
                    owned_id = value.get("Id", "")
                    if value.get("Config", {}).get("Labels", {}).get(_OWNER_LABEL) == nonce and _CONTAINER.fullmatch(owned_id):
                        removed = command(["rm", "--force", "--volumes", owned_id])
                        remaining = command(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", f"id={owned_id}"])
                        cleanup_verified = removed.returncode == 0 and remaining.returncode == 0 and not remaining.stdout.strip()
                    elif owned.returncode != 0 and container_id is None:
                        # A rejected create may leave no object. Verify absence through
                        # a second daemon operation rather than trusting error text.
                        remaining = command(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", f"name=^/{container_name}$"])
                        cleanup_verified = remaining.returncode == 0 and not remaining.stdout.strip()
                except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError):
                    cleanup_verified = False
                result.setdefault("launcher", {})["container_removed"] = cleanup_verified
                if not cleanup_verified:
                    result["status"] = "failed"
                    result["failures"].append("acceptance container cleanup could not be verified")
    if result["status"] != "passed":
        result["isolation"]["verified"] = False
    return (0 if result["status"] == "passed" else 1), result
