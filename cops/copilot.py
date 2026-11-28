"""Local MCP entry point for the bundled Detection Quality review in Copilot."""

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

from cops.catalog import ROOT
from cops.workflows.detection_quality import SELECTION, clarification, prepare_review, review_package, run_review

VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
TOOL = {
    "name": "request",
    "description": (
        "Submit the user's original request for both packaged Detection Quality suites. "
        "On accepted, immediately call this tool with the returned run_id. "
        "To resume, use the run_id from the same chat."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "request": {"type": "string", "description": "The user's original ask for a new review.", "maxLength": 600},
            "run_id": {
                "type": "string",
                "description": "The accepted review to continue.",
                "pattern": "^[0-9a-f]{32}$",
            },
        },
        "additionalProperties": False,
    },
}


def run_store() -> Path:
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    if not state.is_absolute():
        raise ValueError("State directory must be absolute.")
    checkout = hashlib.sha256(os.fsencode(ROOT)).hexdigest()[:24]
    return state / "cops" / "copilot" / checkout


def request(arguments: dict) -> dict:
    if set(arguments) == {"request"} and isinstance(arguments["request"], str):
        package = review_package(ROOT, arguments["request"])
        if package is None:
            return clarification()
        run_id = uuid.uuid4().hex
        store = run_store()
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
        prepare_review(package, store / run_id)
        return {
            "status": "accepted",
            "run_id": run_id,
            **SELECTION,
            "message": "Call request with this run_id now to complete the review.",
        }
    if set(arguments) == {"run_id"} and isinstance(arguments["run_id"], str):
        run_id = arguments["run_id"]
        if re.fullmatch(r"[0-9a-f]{32}", run_id):
            directory = run_store() / run_id
            if directory.is_dir() and not directory.is_symlink():
                package = review_package(ROOT, None)
                result = run_review(package, directory, resume=True, announce=False)
                del result["run_dir"]
                return {**result, "run_id": run_id}
            return {"status": "failed", "message": "No saved review with this run ID in this checkout."}
    return {"status": "failed", "message": "Supply the original request or one valid run ID."}


def reply(message: object) -> dict | None:
    def error(code: int, detail: str) -> dict:
        return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": detail}}

    identifier = message.get("id") if isinstance(message, dict) else None
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return error(-32600, "Invalid request")
    if "id" not in message:
        return None
    method, params = message["method"], message.get("params", {})
    if not isinstance(params, dict):
        return error(-32602, "Expected an object for params")
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {
            "protocolVersion": version if version in VERSIONS else VERSIONS[0],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "cops", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "ping":
        result = {}
    elif method == "tools/call":
        if params.get("name") != TOOL["name"] or not isinstance(params.get("arguments", {}), dict):
            return error(-32602, "Unknown tool or invalid arguments")
        try:
            report = request(params.get("arguments", {}))
        except ValueError, KeyError, OSError, sqlite3.Error, subprocess.SubprocessError:
            report = {"status": "failed", "message": "COPS could not open or verify this local fixture review."}
        result = {"content": [{"type": "text", "text": json.dumps(report)}], "isError": report["status"] == "failed"}
    else:
        return error(-32601, "Method not found")
    return {"jsonrpc": "2.0", "id": identifier, "result": result}


def main() -> None:
    for line in sys.stdin.buffer:
        try:
            response = reply(json.loads(line))
        except ValueError, RecursionError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
