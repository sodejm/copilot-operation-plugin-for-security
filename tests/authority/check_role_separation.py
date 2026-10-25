"""Disposable Linux acceptance probe; provisioning runs as root, never as the worker.

Invoke with ``python -m tests.authority.check_role_separation --help``. This is
test infrastructure, not an installed approval supervisor or account installer.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

from cops.contracts.models import ActionPlan
from cops.execution.authorization import (
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
)
from cops.execution.control import (
    ApprovalAuthority,
    ApprovalAuthorityServer,
    ApprovalControlClient,
    ApprovalControlError,
)
from cops.execution.store import ApprovalStore
from tests.auth_testkit import make_test_authorization_context

IDENTITY = "issue327-disposable-worker"
MODULE = "tests.authority.check_role_separation"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict, mode: int = 0o600) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
    path.chmod(mode)


def wait_file(path: Path, process: subprocess.Popen | None = None) -> None:
    deadline = time.monotonic() + 30
    while not path.exists():
        if process is not None and process.poll() is not None:
            raise RuntimeError("fixture process exited before readiness")
        if time.monotonic() >= deadline:
            raise TimeoutError("fixture readiness deadline exceeded")
        time.sleep(0.05)


def rejected(operation) -> None:
    try:
        operation()
    except ApprovalControlError:
        return
    raise AssertionError("authority accepted an invalid request")


def denied(operation) -> None:
    try:
        operation()
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            return
        raise
    raise AssertionError("worker accessed protected authority state")


def authority(base: Path) -> None:
    settings = read_json(base / "settings.json")
    assert os.geteuid() == settings["authority_uid"]
    plan = ActionPlan.from_dict(read_json(Path("cops/contracts/fixtures/valid_action_plan.json")))
    signer, _, engagement = make_test_authorization_context(plan)
    private = base / "private"
    key = private / "key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    signer = replace(signer, secret=key.read_bytes())
    trust = AuthorizationTrustStore(
        [
            TrustedAuthorizationKey(
                signer.key_id,
                signer.operator,
                signer.secret,
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2030-01-01T00:00:00Z",
            )
        ]
    )
    authorization = create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity=IDENTITY,
        valid_hours=1,
    )
    store = ApprovalStore(private / "approvals.sqlite3")
    store.store_authorization(authorization)
    verifier = ApprovalAuthority(
        store,
        trust,
        engagement,
        IDENTITY,
        settings["worker_uid"],
        settings["worker_gid"],
        settings["worker_pid"],
        settings["authority_uid"],
    )
    server = ApprovalAuthorityServer(base / "control" / "authority.sock", verifier)
    with server.listener() as listener:
        assert not listener.get_inheritable()
        assert stat.S_IMODE(os.lstat(server.socket_path).st_mode) == 0o660
        write_json(
            base / "control" / "public.json",
            {
                "plan": plan.to_dict(),
                "authorization_id": authorization.authorization_id,
                "authority_uid": settings["authority_uid"],
            },
            0o640,
        )
        listener.settimeout(30)
        for _ in range(5):
            connection, _ = listener.accept()
            assert not connection.get_inheritable()
            server._serve_accepted_connection(connection)
    assert not server.socket_path.exists()
    assert store.get_authorization(authorization.authorization_id).status == "consumed"
    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute("SELECT count(*) FROM approval_consumptions").fetchone()[0] == 1
    write_json(
        private / "result.json",
        {
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "requests": 5,
            "consumptions": 1,
            "socket_noninheritable": True,
            "socket_removed": True,
        },
    )


def worker(base: Path, worker_dir: Path, *, child: bool = False) -> None:
    if not child:
        write_json(worker_dir / "pid.json", {"pid": os.getpid()})
        wait_file(base / "control" / "public.json")
    public = read_json(base / "control" / "public.json")
    plan = ActionPlan.from_dict(public["plan"])
    client = ApprovalControlClient(base / "control" / "authority.sock", public["authority_uid"])

    def consume():
        return client.consume_authorization(public["authorization_id"], plan, IDENTITY)

    if child:
        rejected(consume)  # Same UID/GID, different PID must fail before consumption.
        return
    assert os.geteuid() != public["authority_uid"]
    status = Path("/proc/self/status").read_text(encoding="utf-8")
    assert "NoNewPrivs:\t1" in status
    denied(lambda: (base / "private").iterdir().__next__())
    for name in ("key", "approvals.sqlite3"):
        denied(lambda name=name: (base / "private" / name).read_bytes())
    denied(lambda: (base / "private" / "worker-created").touch())
    denied(lambda: (base / "control").iterdir().__next__())
    denied(lambda: (base / "control" / "worker-created").touch())
    sgid = worker_dir / "sgid-attempt"
    sgid.mkdir()
    denied(lambda: sgid.chmod(0o2710))
    assert not stat.S_IMODE(sgid.stat().st_mode) & stat.S_ISGID
    subprocess.run(
        [sys.executable, "-m", MODULE, "--role", "child", "--base", str(base), "--worker-dir", str(worker_dir)],
        check=True,
        timeout=15,
    )
    snapshot = plan.approved_snapshot()
    changed = ActionPlan.create(
        plan_id="plan-issue327-wrong",
        engagement_id=plan.engagement_id,
        scenario_id=plan.scenario_id,
        target=plan.target,
        specialist_id=plan.specialist_id,
        operations=snapshot["operations"],
        limits=snapshot["limits"],
        credential_references=snapshot["credential_references"],
        created_at=plan.created_at,
        platform_prerequisites=snapshot["platform_prerequisites"],
        batch=snapshot["batch"],
    )
    rejected(lambda: client.consume_authorization(public["authorization_id"], changed, IDENTITY))
    rejected(lambda: client.consume_authorization(public["authorization_id"], plan, "wrong-worker"))
    receipt = consume()
    assert receipt.plan_digest == plan.plan_digest and receipt.worker_identity == IDENTITY
    client.validate_receipt_provenance(receipt)
    rejected(consume)  # A new request cannot consume the same approval twice.
    write_json(
        worker_dir / "result.json",
        {
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "pid": os.getpid(),
            "no_new_privileges": True,
            "sgid_denied": True,
            "authority_state_denied": True,
            "control_mutation_denied": True,
            "wrong_pid_denied": True,
            "wrong_plan_denied": True,
            "wrong_identity_denied": True,
            "valid_consumption": True,
            "replay_denied": True,
        },
    )


def provision(args) -> None:
    import pwd

    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise RuntimeError("run provisioning as root in a disposable systemd Linux VM")
    worker_account = pwd.getpwnam(args.worker_user)
    authority_account = pwd.getpwnam(args.authority_user)
    assert worker_account.pw_uid > 0 and authority_account.pw_uid > 0
    assert worker_account.pw_uid != authority_account.pw_uid
    assert worker_account.pw_gid != authority_account.pw_gid
    worker_home = Path(worker_account.pw_dir)
    assert worker_home.is_dir() and not worker_home.is_symlink()
    base = Path(tempfile.mkdtemp(prefix="cops-327-", dir="/run"))
    base.chmod(0o755)
    worker_dir = Path(tempfile.mkdtemp(prefix="role-fixture-", dir=worker_home))
    os.chown(worker_dir, worker_account.pw_uid, worker_account.pw_gid)
    processes = []
    unit = "cops-327-" + uuid.uuid4().hex
    try:
        for name, mode, group in (
            ("private", 0o700, authority_account.pw_gid),
            ("control", 0o2710, worker_account.pw_gid),
        ):
            path = base / name
            path.mkdir()
            os.chown(path, authority_account.pw_uid, group)
            path.chmod(mode)  # Provisioning role only; the worker must never do this.
        properties = {
            "User": args.worker_user,
            "Group": str(worker_account.pw_gid),
            "WorkingDirectory": str(Path.cwd()),
            "InaccessiblePaths": "/Users /mnt /media -/run/docker.sock",
            "ProtectHome": "yes",
            "ProtectSystem": "strict",
            "ReadWritePaths": str(worker_home),
            "PrivateTmp": "yes",
            "NoNewPrivileges": "yes",
            "RestrictSUIDSGID": "yes",
            "UMask": "0077",
        }
        command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit", unit]
        command += [f"--property={key}={value}" for key, value in properties.items()]
        environment = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(Path.cwd())}
        invocation = [sys.executable, "-m", MODULE]
        running_worker = subprocess.Popen(
            command
            + [
                "/usr/bin/env",
                "-i",
                *[f"{k}={v}" for k, v in environment.items()],
                *invocation,
                "--role",
                "worker",
                "--base",
                str(base),
                "--worker-dir",
                str(worker_dir),
            ]
        )
        processes.append(running_worker)
        wait_file(worker_dir / "pid.json", running_worker)
        measured_properties = (
            subprocess.check_output(
                [
                    "systemctl",
                    "show",
                    unit,
                    "--property=Id",
                    "--property=InvocationID",
                    "--property=MainPID",
                    *[f"--property={key}" for key in properties],
                ],
                text=True,
            )
            .strip()
            .splitlines()
        )
        write_json(
            base / "settings.json",
            {
                "authority_uid": authority_account.pw_uid,
                "worker_uid": worker_account.pw_uid,
                "worker_gid": worker_account.pw_gid,
                "worker_pid": read_json(worker_dir / "pid.json")["pid"],
            },
            0o644,
        )
        running_authority = subprocess.Popen(
            invocation + ["--role", "authority", "--base", str(base), "--worker-dir", str(worker_dir)],
            env=environment,
            user=authority_account.pw_uid,
            group=authority_account.pw_gid,
            extra_groups=[],
            umask=0o077,
        )
        processes.append(running_authority)
        assert running_worker.wait(timeout=60) == 0
        assert running_authority.wait(timeout=35) == 0
        result = {
            "worker": read_json(worker_dir / "result.json"),
            "authority": read_json(base / "private" / "result.json"),
            "worker_properties": measured_properties,
        }
    finally:
        subprocess.run(["systemctl", "stop", unit], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        shutil.rmtree(base)
        shutil.rmtree(worker_dir)
    assert not base.exists() and not worker_dir.exists()
    result["fixture_cleanup_verified"] = True
    print(json.dumps(result, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-user", default="cops-worker")
    parser.add_argument("--authority-user", default="cops-approval")
    parser.add_argument("--role", choices=("provision", "authority", "worker", "child"), default="provision")
    parser.add_argument("--base", type=Path)
    parser.add_argument("--worker-dir", type=Path)
    args = parser.parse_args()
    if args.role == "provision":
        provision(args)
    elif args.role == "authority":
        authority(args.base)
    else:
        worker(args.base, args.worker_dir, child=args.role == "child")


if __name__ == "__main__":
    main()
