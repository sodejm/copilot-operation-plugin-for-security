"""Offline installation and execution of two reviewed synthetic dependency wheels."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.metadata
import inspect
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

from cops.assessments.artifacts import assess

from .service_boundaries import _corrected_query, _vulnerable_query, query_component

ADAPTER_ID = "synthetic-wheel-installation@1"
ADAPTERS = {ADAPTER_ID: {
    "version": 1, "platforms": ["linux", "darwin"],
    "prerequisites": {"linux": "pip==26.1.2", "darwin": "pip==26.2.1"},
    "scope": "registered-synthetic-wheel-in-disposable-laboratory",
    "profiles": ["vulnerable", "corrected"],
}}
_PIP_VERSIONS = {"linux": "26.1.2", "darwin": "26.2.1"}
_TIMEOUT = 20
_OUTPUT_LIMIT = 64 * 1024

# Fixed worker source, never assembled from supplied code, package names, or URLs.
_RUNTIME = r'''
import http.client
import json
import sqlite3
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, sys.argv[1])
from cops_synthetic_query import query

requests = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        value = urllib.parse.parse_qs(parsed.query).get("id", [""])[0]
        with sqlite3.connect(":memory:") as connection:
            connection.execute("CREATE TABLE objects(id TEXT, owner TEXT)")
            connection.executemany("INSERT INTO objects VALUES (?, ?)",
                                  [("owner-object", "owner"), ("other-object", "other")])
            objects = [row[0] for row in query(connection, value)]
        payload = json.dumps(objects).encode()
        requests.append({"sequence": len(requests) + 1, "objects": objects})
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

server = HTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
results = []
try:
    for value in ("owner-object", "' OR 1=1 --"):
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            client.request("GET", "/objects?id=" + urllib.parse.quote(value, safe=""))
            response = client.getresponse()
            if response.status != 200:
                raise RuntimeError("synthetic service rejected request")
            results.append(json.loads(response.read(4096)))
        finally:
            client.close()
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
print(json.dumps({"execution_id": sys.argv[2], "actual_requests": len(requests),
                  "service_stopped": not thread.is_alive(),
                  "benign_objects": results[0], "injection_objects": results[1]}))
'''


def prerequisite_status() -> dict[str, Any]:
    """Report availability without installing or selecting a substitute tool."""
    try:
        version = importlib.metadata.version("pip")
    except importlib.metadata.PackageNotFoundError:
        version = None
    available = sys.platform in _PIP_VERSIONS and version == _PIP_VERSIONS[sys.platform]
    return {
        "available": available, "adapter_id": ADAPTER_ID, "platform": sys.platform,
        "installer": "pip", "version": version,
        "required_version": _PIP_VERSIONS.get(sys.platform),
        "limitation": None if available else "Registered offline installer or supported platform unavailable.",
    }


def _build_wheel(root: Path, profile: str) -> tuple[Path, dict[str, str]]:
    component = query_component(profile)
    query = _vulnerable_query if profile == "vulnerable" else _corrected_query
    source = textwrap.dedent(inspect.getsource(query))
    module = ("import sqlite3\n\n" + source + "\nquery = " + query.__name__ + "\n").encode()
    version = component["version"]
    dist = f"cops_synthetic_query-{version}.dist-info"
    files = {
        "cops_synthetic_query/__init__.py": module,
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: cops-synthetic-query\nVersion: {version}\n\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: cops-synthetic-wheel-v1\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    records = []
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        records.append(f"{name},sha256={digest},{len(content)}\n")
    files[f"{dist}/RECORD"] = ("".join(records) + f"{dist}/RECORD,,\n").encode()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"cops_synthetic_query-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as wheel:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            wheel.writestr(info, content)
    return path, {
        **component, "wheel_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "module_sha256": hashlib.sha256(module).hexdigest(),
    }


def _install_arguments(target: Path, lock: Path) -> list[str]:
    return [sys.executable, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
            "--no-input", "--no-cache-dir", "install", "--target", str(target), "--no-index",
            "--no-deps", "--require-hashes", "--only-binary", ":all:", "--no-compile", "-r", str(lock)]


def _run(arguments: list[str], root: Path, label: str) -> tuple[int, str]:
    """Run a fixed adapter with bounded output and kill its process group on error."""
    environment = {"PATH": os.defpath, "HOME": str(root), "TMPDIR": str(root), "LANG": "C.UTF-8"}
    with subprocess.Popen(
        arguments, cwd=root, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
    ) as process:
        output = bytearray()
        deadline = time.monotonic() + _TIMEOUT
        try:
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(label, _TIMEOUT)
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fd, min(8192, _OUTPUT_LIMIT + 1 - len(output)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output.extend(chunk)
                        if len(output) > _OUTPUT_LIMIT:
                            raise ValueError("synthetic installer output limit exceeded")
            return process.wait(timeout=max(0.01, deadline - time.monotonic())), output.decode("utf-8", errors="replace")
        finally:
            # The adapter never starts unrelated children. Reap the whole group even
            # if a parent exited while a descendant retained its stdout pipe.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def _runtime_result(raw: str, execution_id: str) -> dict[str, Any]:
    try:
        result = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid supply-chain runtime output") from exc
    if (not isinstance(result, dict) or result.get("execution_id") != execution_id
            or type(result.get("actual_requests")) is not int or result["actual_requests"] != 2
            or result.get("service_stopped") is not True):
        raise ValueError("incomplete supply-chain runtime evidence")
    for field in ("benign_objects", "injection_objects"):
        values = result.get(field)
        if (not isinstance(values, list) or len(values) > 2
                or any(type(value) is not str or value not in {"owner-object", "other-object"} for value in values)
                or len(values) != len(set(values))):
            raise ValueError("invalid supply-chain runtime object evidence")
    return result


def _artifact_assessments(metadata: dict[str, str]) -> tuple[str, str]:
    artifacts = [
        {"artifact_id": "installed-lock", "kind": "requirements_lock", "content":
         f"cops-synthetic-query=={metadata['version']} --hash=sha256:{metadata['wheel_sha256']}\n"},
        {"artifact_id": "synthetic-advisory", "kind": "advisory_fixture", "content": {"advisories": [
            {"ecosystem": "pypi", "package": "cops-synthetic-query", "version": "1.0.0"}]}},
    ]
    report = assess("supply_chain", artifacts, as_of="2026-10-15T12:00:00Z")
    missing = assess("supply_chain", [{"artifact_id": "missing-components", "kind": "cyclonedx",
                                      "content": {"components": []}}], as_of="2026-10-15T12:00:00Z")
    unknown = any(finding["classification"] == "unresolved" and finding["verification"] == "unverified"
                  and finding["confidence"] == "unknown" for finding in missing["findings"])
    return ("matched" if "pinned_advisory_match" in report["finding_codes"].values() else "clear",
            "unknown" if unknown else "unexpected_assessment")


def run_supply_chain_acceptance(profile: str) -> dict[str, Any]:
    """Install and exercise only a registered fixture; no caller-supplied wheels."""
    if profile not in {"vulnerable", "corrected"}:
        raise ValueError("unsupported supply-chain profile")
    prerequisite = prerequisite_status()
    if prerequisite["available"] is not True:
        return {"status": "unsupported", "profile": profile, "prerequisite": prerequisite}
    execution_id = "supply-chain-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="cops-synthetic-wheel-") as temporary:
        root = Path(temporary)
        wheel, metadata = _build_wheel(root, profile)
        lock = root / "requirements.txt"
        lock.write_text(f"./{wheel.name} --hash=sha256:{metadata['wheel_sha256']}\n", encoding="utf-8")
        installed = root / "installed"
        install_exit, _ = _run(_install_arguments(installed, lock), root, "synthetic-wheel-install")
        if install_exit != 0:
            raise RuntimeError("registered synthetic wheel installation failed")
        module = installed / "cops_synthetic_query" / "__init__.py"
        if module.is_symlink() or hashlib.sha256(module.read_bytes()).hexdigest() != metadata["module_sha256"]:
            raise ValueError("installed synthetic source differs from reviewed source")
        runtime_exit, raw = _run([sys.executable, "-I", "-c", _RUNTIME, str(installed), execution_id], root, "synthetic-wheel-runtime")
        if runtime_exit != 0:
            raise RuntimeError("installed synthetic dependency runtime failed")
        runtime = _runtime_result(raw, execution_id)
        # Appended bytes leave ZIP structure readable but invalidate the pinned hash.
        with wheel.open("ab") as stream:
            stream.write(b"synthetic-tampering")
        rejected = root / "rejected"
        reject_exit, rejection = _run(_install_arguments(rejected, lock), root, "synthetic-wheel-hash-rejection")
        hash_rejected = reject_exit != 0 and "DO NOT MATCH THE HASHES" in rejection
        advisory, insufficient = _artifact_assessments(metadata)
        result = {
            "status": "complete", "profile": profile, "adapter_id": ADAPTER_ID,
            "prerequisite": prerequisite, "component": metadata,
            "install_exit_code": install_exit, "installed_source_verified": True,
            "runtime": runtime, "advisory_assessment": advisory,
            "insufficient_evidence_status": insufficient,
            "hash_mismatch_rejected": hash_rejected,
            "tampered_install_absent": not (rejected / "cops_synthetic_query").exists(),
        }
    result["disposable_root_removed"] = not root.exists()
    return result
