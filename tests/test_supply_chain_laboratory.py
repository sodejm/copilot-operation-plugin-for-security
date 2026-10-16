from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from cops.laboratory import service_supply_chain as supply
from cops.laboratory.service_boundaries import query_component


@pytest.mark.parametrize("profile", ["vulnerable", "corrected"])
def test_synthetic_wheel_is_reproducible_and_bound_to_reviewed_source(tmp_path: Path, profile: str) -> None:
    first, metadata = supply._build_wheel(tmp_path / "first", profile)
    second, other = supply._build_wheel(tmp_path / "second", profile)
    assert first.read_bytes() == second.read_bytes()
    assert metadata == other
    assert metadata["wheel_sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    assert metadata["source_sha256"] == query_component(profile)["source_sha256"]
    with zipfile.ZipFile(first) as wheel:
        assert len(wheel.namelist()) == 4
        assert all(not name.startswith("/") and ".." not in name.split("/") for name in wheel.namelist())
        assert b"Root-Is-Purelib: true" in wheel.read(next(name for name in wheel.namelist() if name.endswith("/WHEEL")))


def test_arbitrary_profile_is_rejected_before_prerequisite_or_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supply, "prerequisite_status", lambda: pytest.fail("must validate profile first"))
    with pytest.raises(ValueError, match="profile"):
        supply.run_supply_chain_acceptance("../untrusted")


def test_missing_installer_is_explicitly_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supply, "prerequisite_status", lambda: {"available": False, "limitation": "pinned installer unavailable"})
    monkeypatch.setattr(supply, "_run", lambda *_args: pytest.fail("unsupported prerequisite must not execute"))
    assert supply.run_supply_chain_acceptance("corrected")["status"] == "unsupported"


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired("fixed-installer", 20), RuntimeError("installer failed"), KeyboardInterrupt()])
def test_failure_and_cancellation_remove_partial_installation(monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    roots: list[Path] = []
    monkeypatch.setattr(supply, "prerequisite_status", lambda: {"available": True})

    def fail(_arguments: list[str], root: Path, _label: str) -> tuple[int, str]:
        roots.append(root)
        (root / "partial-install").write_text("synthetic", encoding="utf-8")
        raise failure

    monkeypatch.setattr(supply, "_run", fail)
    with pytest.raises(type(failure)):
        supply.run_supply_chain_acceptance("corrected")
    assert roots and all(not root.exists() for root in roots)


def test_installer_arguments_forbid_network_dependencies_and_source_builds(tmp_path: Path) -> None:
    arguments = supply._install_arguments(tmp_path / "installed", tmp_path / "requirements.txt")
    assert arguments[:3] == [sys.executable, "-I", "-m"]
    assert {"--isolated", "--no-index", "--no-deps", "--require-hashes", "--no-cache-dir", "--no-input", "--no-compile"}.issubset(arguments)
    assert arguments[arguments.index("--only-binary") + 1] == ":all:"


def test_unregistered_installer_and_platform_are_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supply.importlib.metadata, "version", lambda _name: "999.0")
    assert supply.prerequisite_status()["available"] is False
    monkeypatch.setattr(supply.sys, "platform", "unsupported-platform")
    assert supply.prerequisite_status()["available"] is False


@pytest.mark.parametrize("field,value", [("execution_id", "another-run"), ("actual_requests", True), ("actual_requests", 1), ("service_stopped", False)])
def test_runtime_output_requires_this_execution_and_observed_activity(field: str, value: object) -> None:
    result = {"execution_id": "this-run", "actual_requests": 2, "service_stopped": True,
              "benign_objects": ["owner-object"], "injection_objects": []}
    result[field] = value
    with pytest.raises(ValueError, match="runtime"):
        supply._runtime_result(json.dumps(result), "this-run")


@pytest.mark.skipif(sys.platform not in {"linux", "darwin"}, reason="registered POSIX subprocess adapter")
@pytest.mark.parametrize("mode", ["timeout", "output", "cancellation"])
def test_adapter_reaps_actual_worker_after_timeout_output_limit_or_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    workers: list[subprocess.Popen[bytes]] = []
    popen = subprocess.Popen

    def start(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        worker = popen(*args, **kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(supply.subprocess, "Popen", start)
    script = "import time; time.sleep(30)"
    error: type[BaseException] = subprocess.TimeoutExpired
    if mode == "timeout":
        monkeypatch.setattr(supply, "_TIMEOUT", 0.2)
    elif mode == "output":
        monkeypatch.setattr(supply, "_OUTPUT_LIMIT", 128)
        script = "import sys, time; sys.stdout.write('x' * 4096); sys.stdout.flush(); time.sleep(30)"
        error = ValueError
    else:
        def cancel(*_args: object) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr(supply.selectors.DefaultSelector, "select", cancel)
        error = KeyboardInterrupt
    with pytest.raises(error):
        supply._run([sys.executable, "-I", "-c", script], tmp_path, "fixed-fixture-worker")
    assert len(workers) == 1
    assert workers[0].returncode is not None and workers[0].returncode < 0
