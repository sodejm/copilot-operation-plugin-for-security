from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cops.operations import bundle as bundle_module
from cops.operations.bundle import build_bundle
from cops.operations.catalog import declarations
from cops.operations.metadata import generated_files, synchronize, validate_installed_metadata
from cops.operations.service import OperationService

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "plugins/detection-hunting/soc-investigation-workbench"


def test_metadata_covers_all_catalog_packages_without_completion_claims():
    report = validate_installed_metadata()
    assert report["operations"] == 28
    records = json.loads((ROOT / "catalog/plugins.json").read_text())["plugins"]
    files = generated_files()
    assert len(files) == len(records) + 4
    for record in records:
        metadata = files[Path(record["path"]) / "org.cops/operations.json"]
        assert metadata["package_feature_complete"] is False
        assert sum(row["kind"] == "operation" for row in metadata["features"]) == len(metadata["operations"])
        assert all((ROOT / path).is_file() for path in metadata["skill_references"])
    assert synchronize(check=True) == []


def test_bundle_runs_real_soc_and_assessment_outside_repository(tmp_path):
    bundle = tmp_path / "installed tools"
    hashes = build_bundle(bundle)
    manifest = json.loads((bundle / "bundle-manifest.json").read_text())
    assert manifest["files"] == hashes
    assert not any(
        name.startswith(("cops/execution/", "cops/laboratory/", "cops/web_api/", "cops/remote_")) for name in hashes
    )
    assert all(hashlib.sha256((bundle / name).read_bytes()).hexdigest() == digest for name, digest in hashes.items())
    environment = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
    case = json.loads((SOC / "examples/case.json").read_text())
    request = {
        "schema_version": "cops.operation-request/v1",
        "operation_id": "cops.soc.next",
        "arguments": {"case": case},
    }
    process = subprocess.run(
        [sys.executable, "-S", "-B", str(bundle / "cops_headless.py"), "tools", "invoke"],
        cwd=tmp_path,
        env=environment,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout) == OperationService().invoke(request)
    fixture = json.loads((ROOT / "tests/fixtures/artifact_assessment_cases_v1.json").read_text())
    sample = fixture["cases"][0]
    request["operation_id"] = "cops.assess." + sample["capability"]
    request["arguments"] = {"artifacts": sample["artifacts"], "as_of": fixture["as_of"]}
    process = subprocess.run(
        [sys.executable, "-S", "-B", str(bundle / "cops_headless.py"), "tools", "invoke"],
        cwd=tmp_path,
        env=environment,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout) == OperationService().invoke(request)
    with pytest.raises(ValueError, match="destination_exists"):
        build_bundle(bundle)


def test_distribution_missing_dependency_is_reported_not_replaced(tmp_path):
    bundle = tmp_path / "bundle"
    build_bundle(bundle)
    # Test recovery without deleting anything: configure an empty install root.
    result = OperationService(soc_root=tmp_path / "missing").invoke(
        {
            "schema_version": "cops.operation-request/v1",
            "operation_id": "cops.soc.validate",
            "arguments": {"case": {}},
        }
    )
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "missing_prerequisite"


def test_declared_bindings_never_accept_host_destinations():
    forbidden = {"path", "output", "command", "module", "url", "destination", "executable"}
    for declaration in declarations():
        assert not forbidden.intersection(declaration["input_schema"]["properties"])


@pytest.mark.skipif(os.name != "posix", reason="private durable state requires POSIX")
def test_exported_runtime_recovers_across_cli_processes(tmp_path):
    bundle = tmp_path / "installed"
    build_bundle(bundle)
    config = tmp_path / "runtime.json"
    state = tmp_path / "state"
    config.write_text(json.dumps({"schema_version": "cops.operation-runtime/v1", "state_directory": str(state)}))
    config.chmod(0o600)
    environment = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
    environment["COPS_RUNTIME_CONFIG"] = str(config)

    def invoke(operation, arguments):
        request = {"schema_version": "cops.operation-request/v1", "operation_id": operation, "arguments": arguments}
        process = subprocess.run(
            [sys.executable, "-S", "-B", str(bundle / "cops_headless.py"), "tools", "invoke"],
            cwd=tmp_path,
            env=environment,
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert process.returncode == 0, process.stdout + process.stderr
        return json.loads(process.stdout)

    created = invoke(
        "cops.run.create",
        {
            "request": {
                "schema_version": "cops.operation-request/v1",
                "operation_id": "cops.work.request",
                "arguments": {"task": "sample"},
            }
        },
    )
    run_id = created["result"]["run_id"]
    assert invoke("cops.run.resume", {"run_id": run_id})["result"]["state"] == "succeeded"
    assert invoke("cops.run.status", {"run_id": run_id})["result"]["attempt"] == 1


def test_bundle_excludes_unreviewed_files_and_rejects_indexed_symlinks(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "cops/operations").mkdir(parents=True)
    (source / "cops/operations/reviewed.py").write_text("# reviewed runtime\n")
    (source / "cops/private.local.json").write_text('{"private":"must-not-export"}')
    monkeypatch.setattr(bundle_module, "_tracked_files", lambda root: [Path("cops/operations/reviewed.py")])
    destination = tmp_path / "export"
    build_bundle(destination, root=source)
    assert (destination / "cops/operations/reviewed.py").is_file()
    assert not (destination / "cops/private.local.json").exists()
    (source / "cops/operations/link.py").symlink_to(source / "cops/operations/reviewed.py")
    monkeypatch.setattr(bundle_module, "_tracked_files", lambda root: [Path("cops/operations/link.py")])
    with pytest.raises(ValueError, match="source_symlink"):
        build_bundle(tmp_path / "rejected", root=source)
