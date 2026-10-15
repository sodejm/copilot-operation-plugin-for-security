"""The acceptance launcher must fail closed before executing lab services."""

from __future__ import annotations

import copy
import errno
import json
import subprocess
from pathlib import Path

import pytest

from cops.laboratory import container_runtime as runtime
from cops.laboratory import network_boundary as boundary
from cops.laboratory import source_snapshot as snapshot

IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64
NONCE = "c" * 32
DIGEST = "d" * 64


def source_tree(root):
    for relative, data in {
        "cops/__init__.py": b"",
        "cops/laboratory/example.py": b"VALUE = 1\n",
        "cops/laboratory/service_fixtures/example.json": b"{}",
        "scripts/check_laboratory.py": b"pass\n",
        "catalog/schemas/action-plan.schema.json": b"{}",
        "catalog/schemas/unregistered.schema.json": b"{}",
        "catalog/private.json": b"synthetic-secret",
        ".env": b"synthetic-secret",
        "cops/private.pem": b"synthetic-secret",
        "tests/example.py": b"pass\n",
    }.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


def configuration(source, nonce=NONCE, digest=DIGEST):
    return {
        "Id": CONTAINER, "Image": IMAGE,
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "IpcMode": "private", "PidsLimit": 128, "Memory": 512 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=128m,mode=1777"},
        },
        "Config": {
            "Labels": {runtime._OWNER_LABEL: nonce}, "User": "65532:65532",
            "WorkingDir": "/opt/cops-src", "Entrypoint": ["python"],
            "Cmd": ["scripts/check_laboratory.py", "--container-child"],
            "Env": [f"COPS_LABORATORY_CONTAINER_NONCE={nonce}",
                    f"COPS_LABORATORY_SOURCE_DIGEST={digest}",
                    "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH=/opt/cops-src"],
        },
        "Mounts": [{"Type": "bind", "Source": str(source),
                    "Destination": "/opt/cops-src", "RW": False}],
    }


def test_snapshot_is_allowlisted_hashed_and_world_readable(tmp_path):
    repository = source_tree(tmp_path / "repository")
    target = tmp_path / "snapshot"
    target.mkdir()
    digest = runtime._snapshot(repository, target)
    snapshot.verify_source_snapshot(target, digest)
    copied = {path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()}
    assert copied == {"source-manifest.json", "cops/__init__.py", "cops/laboratory/example.py",
                      "cops/laboratory/service_fixtures/example.json", "scripts/check_laboratory.py",
                      "catalog/schemas/action-plan.schema.json"}
    assert all(path.stat().st_mode & 0o777 == (0o755 if path.is_dir() else 0o644)
               for path in (target, *target.rglob("*")))


@pytest.mark.parametrize("attack", ["modified", "schema-modified", "unbound", "symlink", "oversized", "total-budget"])
def test_snapshot_rejects_modified_or_unbounded_sources(tmp_path, monkeypatch, attack):
    repository = source_tree(tmp_path / "repository")
    target = tmp_path / "snapshot"
    target.mkdir()
    digest = runtime._snapshot(repository, target)
    file = target / "cops/laboratory/example.py"
    if attack == "modified":
        file.write_text("VALUE = 2\n")
    elif attack == "schema-modified":
        (target / "catalog/schemas/action-plan.schema.json").write_text('{"additionalProperties": true}')
    elif attack == "unbound":
        (target / "unbound.txt").write_text("unexpected")
    elif attack == "symlink":
        file.unlink()
        file.symlink_to(repository / "cops/laboratory/example.py")
    elif attack == "oversized":
        file.write_bytes(b"x" * (snapshot.MAX_FILE_BYTES + 1))
    else:
        monkeypatch.setattr(snapshot, "MAX_BYTES", 1)
    with pytest.raises(ValueError):
        snapshot.verify_source_snapshot(target, digest)


@pytest.mark.parametrize("relative", ["../cops/x.py", "/cops/x.py", "cops//x.py", "cops/../x.py",
                                      "cops\\x.py", "cops/__pycache__/x.py", ".env", "terraform.tfstate"])
def test_snapshot_path_validation(relative):
    assert not snapshot.allowed_source(relative)


@pytest.mark.parametrize("prerequisite", ["cli", "daemon", "image"])
def test_missing_prerequisites_never_copy_or_create(tmp_path, monkeypatch, prerequisite):
    calls = []
    monkeypatch.setattr(runtime.shutil, "which", lambda _: None if prerequisite == "cli" else "docker")

    def command(_, args, **kwargs):
        calls.append(args)
        code = 1 if args[0] == ("info" if prerequisite == "daemon" else "image") else 0
        return subprocess.CompletedProcess(args, code, "", "")

    monkeypatch.setattr(runtime, "_docker_command", command)
    monkeypatch.setattr(runtime, "_snapshot", lambda *args: pytest.fail("source copied before prerequisites"))
    code, report = runtime.run_container_acceptance(tmp_path, image=IMAGE)
    assert code == 2 and report["status"] == "blocked" and not report["isolation"]["verified"]
    assert not any(call[0] == "create" for call in calls)


@pytest.mark.parametrize("section,key,value", [
    ("HostConfig", "NetworkMode", "bridge"), ("HostConfig", "ReadonlyRootfs", False),
    ("HostConfig", "Privileged", True), ("HostConfig", "CapAdd", ["NET_ADMIN"]),
    ("HostConfig", "SecurityOpt", ["no-new-privileges:false"]),
    ("HostConfig", "Memory", 0), ("HostConfig", "PortBindings", {"80/tcp": [{}]}),
    ("Config", "User", "root"), ("Config", "Env", []), ("Config", "Entrypoint", ["sh"]),
])
def test_configuration_rejects_unsafe_settings(tmp_path, section, key, value):
    config = configuration(tmp_path)
    runtime._inspect_configuration(config, image=IMAGE, snapshot=tmp_path, nonce=NONCE, digest=DIGEST)
    config[section][key] = value
    with pytest.raises(ValueError):
        runtime._inspect_configuration(config, image=IMAGE, snapshot=tmp_path, nonce=NONCE, digest=DIGEST)


@pytest.mark.parametrize("attack", ["image", "writable", "extra-mount", "wrong-source"])
def test_configuration_rejects_image_and_mount_changes(tmp_path, attack):
    config = configuration(tmp_path)
    if attack == "image":
        config["Image"] = "sha256:" + "e" * 64
    elif attack == "writable":
        config["Mounts"][0]["RW"] = True
    elif attack == "extra-mount":
        config["Mounts"].append(copy.deepcopy(config["Mounts"][0]))
    else:
        config["Mounts"][0]["Source"] = str(tmp_path / "elsewhere")
    with pytest.raises(ValueError):
        runtime._inspect_configuration(config, image=IMAGE, snapshot=tmp_path, nonce=NONCE, digest=DIGEST)


def docker_double(monkeypatch, *, create_timeout=False, create_failure=False, wrong_owner=False, cleanup_failure=False,
                  unsafe_config=False, invalid_report=False):
    calls = []
    state = {}
    monkeypatch.setattr(runtime.shutil, "which", lambda _: "docker")

    def command(_, args, **kwargs):
        calls.append(args)
        output, code = "", 0
        if args[0] == "image":
            output = IMAGE
        elif args[0] == "create":
            if create_failure:
                return subprocess.CompletedProcess(args, 1, "", "bind source is unavailable")
            state["nonce"] = args[args.index("--label") + 1].split("=", 1)[1]
            source = args[args.index("--mount") + 1].split("src=", 1)[1].split(",", 1)[0]
            manifest = json.loads((Path(source) / "source-manifest.json").read_text())
            state["config"] = configuration(Path(source), state["nonce"], manifest["sha256"])
            if unsafe_config:
                state["config"]["HostConfig"]["NetworkMode"] = "bridge"
            if wrong_owner:
                state["config"]["Config"]["Labels"][runtime._OWNER_LABEL] = "another-owner"
            if create_timeout:
                raise subprocess.TimeoutExpired("docker create", 15)
            output = CONTAINER
        elif args[0] == "inspect":
            if create_failure:
                return subprocess.CompletedProcess(args, 1, "", "no such container")
            output = json.dumps({"Running": False, "ExitCode": 0} if "--format" in args else [state["config"]])
        elif args[0] == "start":
            digest = state["config"]["Config"]["Env"][1].split("=", 1)[1]
            cases = runtime.ACCEPTANCE_CASE_IDS
            report = {
                "schema_version": runtime.SCHEMA_VERSION, "status": "passed", "failures": [], "blockers": [],
                "isolation": {"verified": True, "evidence": [f"launcher_nonce={state['nonce']}", f"source_sha256={digest}"]},
                "summary": {"cases_passed": len(cases), "cases_total": len(cases), "functional_evidence_only": False},
                "strict_preflight": {"passed": True},
                "cases": [{"name": name, "passed": True, "failures": []} for name in cases],
            }
            if invalid_report:
                report["cases"][0]["passed"] = False
            output = json.dumps(report)
        elif args[0] == "rm":
            code = int(cleanup_failure)
        elif args[0] == "container":
            output = CONTAINER if cleanup_failure else ""
        return subprocess.CompletedProcess(args, code, output, "")

    monkeypatch.setattr(runtime, "_docker_command", command)
    return calls


def test_launcher_checks_configuration_correlates_report_and_removes_container(tmp_path, monkeypatch):
    calls = docker_double(monkeypatch)
    code, report = runtime.run_container_acceptance(source_tree(tmp_path), image=IMAGE)
    assert code == 0 and report["status"] == "passed"
    assert report["launcher"]["configuration_inspected"] and report["launcher"]["container_removed"]
    assert [call[0] for call in calls] == ["info", "image", "create", "inspect", "start", "inspect", "inspect", "rm", "container"]
    create = calls[2]
    assert create[create.index("--pull") + 1] == "never"


def test_rejected_create_reports_stage_and_verifies_no_container_remains(tmp_path, monkeypatch):
    calls = docker_double(monkeypatch, create_failure=True)
    code, report = runtime.run_container_acceptance(source_tree(tmp_path), image=IMAGE)
    assert code == 1 and report["status"] == "failed"
    assert "container-create" in report["failures"][0]
    assert report["launcher"]["container_removed"] is True
    assert len(report["failures"]) == 1
    assert not any(call[0] in {"start", "rm"} for call in calls)
    assert calls[-1][-1].startswith("name=^/cops-acceptance-")


@pytest.mark.parametrize("scenario", ["create-timeout", "wrong-owner", "cleanup-failure", "unsafe-config", "invalid-report"])
def test_launcher_failure_cleanup_is_owned_and_verified(tmp_path, monkeypatch, scenario):
    calls = docker_double(monkeypatch, **{scenario.replace("-", "_"): True})
    code, report = runtime.run_container_acceptance(source_tree(tmp_path), image=IMAGE)
    assert code == 1 and report["status"] == "failed" and not report["isolation"]["verified"]
    removed = [call for call in calls if call[0] == "rm"]
    assert bool(removed) == (scenario != "wrong-owner")
    if scenario in {"unsafe-config", "wrong-owner", "create-timeout"}:
        assert not any(call[0] == "start" for call in calls)
    if scenario == "create-timeout":
        recovered = next(call for call in calls if call[0] == "inspect")
        assert recovered[1].startswith("cops-acceptance-")


def test_environment_markers_alone_cannot_prove_isolation(monkeypatch):
    monkeypatch.setenv("COPS_LABORATORY_CONTAINER_NONCE", NONCE)
    monkeypatch.setenv("COPS_LABORATORY_SOURCE_DIGEST", DIGEST)
    monkeypatch.setattr(boundary.platform, "system", lambda: "Linux")
    monkeypatch.setattr(boundary, "verify_source_snapshot", lambda *args: (_ for _ in ()).throw(ValueError("missing manifest")))
    verified, _, blocker = boundary.inspect_acceptance_boundary()
    assert not verified and blocker


@pytest.mark.parametrize("egress", [errno.ENETUNREACH, errno.ETIMEDOUT, 0])
def test_boundary_requires_loopback_routes_and_definite_egress_denial(monkeypatch, egress):
    monkeypatch.setenv("COPS_LABORATORY_CONTAINER_NONCE", NONCE)
    monkeypatch.setenv("COPS_LABORATORY_SOURCE_DIGEST", DIGEST)
    monkeypatch.setattr(boundary.platform, "system", lambda: "Linux")
    monkeypatch.setattr(boundary, "verify_source_snapshot", lambda *args: None)
    monkeypatch.setattr(Path, "iterdir", lambda _: iter([Path("lo")]))
    monkeypatch.setattr(Path, "read_text", lambda path: "Iface Destination\n" if str(path).endswith("/route") else "0000 lo\n")

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            assert value == 1

        def connect_ex(self, destination):
            return egress

    monkeypatch.setattr(boundary.socket, "socket", lambda *args: Connection())
    verified, evidence, blocker = boundary.inspect_acceptance_boundary()
    assert verified == (egress == errno.ENETUNREACH)
    assert (blocker is None) == verified
    assert "kernel_routes=loopback-only" in evidence
