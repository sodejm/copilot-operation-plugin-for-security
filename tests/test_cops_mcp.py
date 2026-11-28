"""Actual SDK client/server exchanges; no live model or service is involved."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from cops.operations.bundle import build_bundle

ROOT = Path(__file__).resolve().parents[1]


def test_sdk_exchange_from_foreign_directory(tmp_path):
    anyio = pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def exchange():
        environment = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        parameters = StdioServerParameters(
            command=sys.executable, args=["-B", "-m", "cops.mcp"], cwd=str(tmp_path), env=environment
        )
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams, read_timeout_seconds=timedelta(seconds=15)) as client:
                initialized = await client.initialize()
                assert initialized.serverInfo.name == "cops"
                inventory = await client.list_tools()
                assert len(inventory.tools) == 28
                assert all(tool.outputSchema for tool in inventory.tools)
                resume = next(tool for tool in inventory.tools if tool.name == "cops_run_resume")
                assert not resume.annotations.openWorldHint
                assert "authorization_id" not in resume.inputSchema["properties"]
                assert all(not tool.name.startswith("cops_controlled_") for tool in inventory.tools)
                assert all(tool.name != "cops_run_reconcile" for tool in inventory.tools)
                assert not resume.annotations.readOnlyHint
                for name in ("cops_run_create", "cops_run_resume", "cops_delegate_prepare"):
                    tool = next(tool for tool in inventory.tools if tool.name == name)
                    assert not tool.annotations.idempotentHint
                pure = next(tool for tool in inventory.tools if tool.name == "cops_work_request")
                assert pure.annotations.idempotentHint
                result = await client.call_tool("cops_work_request", {"task": "inspect a sample"})
                assert result.structuredContent["status"] == "succeeded"
                assert result.structuredContent["result"]["execution_authorized"] is False
                result = await client.call_tool("cops_work_request", {})
                assert result.structuredContent["status"] == "needs_input"
                result = await client.call_tool("cops_work_request", {"task": "x", "command": "private_marker"})
                assert result.isError
                assert "private_marker" not in result.model_dump_json()
                result = await client.call_tool("cops_s0_unknown", {})
                assert result.isError

    anyio.run(exchange)


@pytest.mark.parametrize(
    "payload", [b'{"jsonrpc":"2.0","id":1,"id":2}\n', b" " * (8 * 1024 * 1024 + 1)], ids=["duplicate-key", "oversized"]
)
def test_bad_frames_fail_closed_without_echo(payload):
    pytest.importorskip("mcp")
    process = subprocess.run(
        [sys.executable, "-B", "-m", "cops.mcp"], cwd=ROOT, input=payload, capture_output=True, timeout=15
    )
    assert process.returncode != 0
    assert b"Traceback" not in process.stderr
    assert len(process.stdout + process.stderr) < 1024


def test_optional_sdk_is_not_needed_for_discovery():
    # -S deliberately hides all site packages, including the optional SDK.
    process = subprocess.run(
        [sys.executable, "-S", "-B", "-m", "cops.operations", "tools", "list"],
        cwd=ROOT,
        capture_output=True,
        timeout=15,
    )
    assert process.returncode == 0
    assert len(json.loads(process.stdout)["operations"]) == 28


def test_sdk_discovery_is_inert_and_lifecycle_persists(tmp_path):
    if os.name != "posix":
        pytest.skip("private durable state requires POSIX")
    anyio = pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    state = tmp_path / "private"
    config = tmp_path / "runtime.json"
    config.write_text(json.dumps({"schema_version": "cops.operation-runtime/v1", "state_directory": str(state)}))
    config.chmod(0o600)

    async def exchange():
        environment = dict(
            os.environ, PYTHONPATH=str(ROOT), COPS_RUNTIME_CONFIG=str(config), PYTHONDONTWRITEBYTECODE="1"
        )
        parameters = StdioServerParameters(
            command=sys.executable, args=["-B", "-m", "cops.mcp"], cwd=str(tmp_path), env=environment
        )
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams, read_timeout_seconds=timedelta(seconds=15)) as client:
                await client.initialize()
                await client.list_tools()
                assert not state.exists()
                created = await client.call_tool(
                    "cops_run_create",
                    {
                        "request": {
                            "schema_version": "cops.operation-request/v1",
                            "operation_id": "cops.work.request",
                            "arguments": {"task": "Inspect sample without executing it"},
                        }
                    },
                )
                run_id = created.structuredContent["result"]["run_id"]
                result = await client.call_tool("cops_run_resume", {"run_id": run_id})
                assert result.structuredContent["result"]["state"] == "succeeded"
                return run_id

    run_id = anyio.run(exchange)
    from cops.operations.runs import RunStore

    assert RunStore(state).get(run_id)["state"] == "succeeded"


def test_exported_mcp_has_no_source_checkout_dependency(tmp_path):
    anyio = pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    destination = tmp_path / "installed bundle"
    build_bundle(destination)

    async def exchange():
        environment = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-B", str(destination / "cops_headless.py"), "mcp"],
            cwd=str(tmp_path),
            env=environment,
        )
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams, read_timeout_seconds=timedelta(seconds=15)) as client:
                await client.initialize()
                assert len((await client.list_tools()).tools) == 28
                case = json.loads(
                    (
                        destination / "plugins/detection-hunting/soc-investigation-workbench/examples/case.json"
                    ).read_text()
                )
                result = await client.call_tool("cops_soc_handoff", {"case": case, "step_id": "signin"})
                assert result.structuredContent["status"] == "succeeded"
                assert result.structuredContent["result"]["canonical_skills"]

    anyio.run(exchange)
