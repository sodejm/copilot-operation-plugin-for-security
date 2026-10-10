"""Test fixtures for the bounded SSH remote-worker transport."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

from cops.execution.ssh_transport import SSHRemoteEndpoint, SSHRemoteTransport, SSHTransportLimits


def make_fake_ssh(root: Path) -> tuple[Path, Path]:
    """Create a fake OpenSSH client that speaks the transport envelope."""
    marker = root / "fake-ssh-invoked"
    executable = root / "fake-ssh"
    executable.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import os
            import stat
            from pathlib import Path
            import sys
            import time

            MARKER = Path({os.fspath(marker)!r})
            MARKER.write_text("invoked", encoding="utf-8")
            request = json.load(sys.stdin)
            mode = request["payload"].get("mode", "success")

            if mode == "timeout":
                os.write(sys.stdout.fileno(), b'{{"credential":"part')
                time.sleep(10)
                raise SystemExit(0)
            if mode == "response-overflow":
                os.write(sys.stdout.fileno(), b'{{"credential":"' + (b"x" * 10000))
                raise SystemExit(0)
            if mode == "diagnostic-overflow":
                os.write(sys.stderr.fileno(), b"secret=" + (b"x" * 10000))
                time.sleep(10)
                raise SystemExit(0)
            if mode == "nonzero":
                os.write(sys.stderr.fileno(), b"secret=do-not-return\\n")
                raise SystemExit(23)
            if mode == "malformed":
                os.write(sys.stdout.fileno(), b"{{")
                raise SystemExit(0)

            argv = sys.argv[1:]
            options = {{}}
            for index, argument in enumerate(argv):
                if argument == "-o":
                    name, value = argv[index + 1].split("=", 1)
                    options[name] = value
            pin_path = Path(options["UserKnownHostsFile"])
            response = {{
                "protocol": request["protocol"],
                "request_id": request["request_id"],
                "host": request["expected_host"],
                "worker_id": request["expected_worker_id"],
                "payload": {{
                    "argv": argv,
                    "pin": pin_path.read_text(encoding="ascii"),
                    "pin_mode": stat.S_IMODE(pin_path.stat().st_mode),
                    "request": request,
                    "result": "accepted",
                }},
            }}
            if mode == "protocol-mismatch":
                response["protocol"] = "cops.remote-worker/v999"
            elif mode == "request-mismatch":
                response["request_id"] = "request-substituted"
            elif mode == "host-mismatch":
                response["host"] = "substitute.example.test"
            elif mode == "worker-mismatch":
                response["worker_id"] = "worker-substituted"
            elif mode == "extra-field":
                response["unexpected"] = True
            json.dump(response, sys.stdout, separators=(",", ":"), sort_keys=True)
            """
        ),
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable, marker


def make_transport(
    root: Path,
    *,
    limits: SSHTransportLimits | None = None,
    worker_id: str = "worker-lab-01",
    pin_host: str = "worker.example.test",
) -> tuple[SSHRemoteTransport, Path, Path]:
    """Build a transport pointed at the fake SSH executable."""
    executable, marker = make_fake_ssh(root)
    known_hosts = root / "known_hosts"
    known_hosts.write_text(f"{pin_host} ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n", encoding="ascii")
    known_hosts.chmod(0o600)
    endpoint = SSHRemoteEndpoint(
        host="worker.example.test",
        port=22,
        username="cops-worker",
        worker_id=worker_id,
        known_hosts_path=known_hosts,
        remote_command=("python3", "-m", "cops.remote_worker"),
    )
    return SSHRemoteTransport(endpoint, limits=limits, ssh_executable=executable), marker, known_hosts
