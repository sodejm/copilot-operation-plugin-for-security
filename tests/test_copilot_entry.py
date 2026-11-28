"""Run the configured Copilot tool over its public stdio transport."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cops.catalog import ROOT
from cops.workflows.detection_quality import STAGES

ASK = "Check whether our Sentinel and Splunk detections catch the bundled cases."
# The crash happens before the second evaluation. Both evaluator invocations
# use the real implementation and are counted outside the coordinator process.
TRACE = """
import os, runpy
from pathlib import Path
from cops.workflows import detection_quality as pilot
original = pilot.evaluate
def traced(package, stage):
    if os.getenv('STOP_BEFORE') == stage:
        os._exit(75)
    with Path(os.environ['CALL_LOG']).open('a') as log:
        print(stage, file=log)
    return original(package, stage)
pilot.evaluate = traced
runpy.run_module('cops.copilot', run_name='__main__')
"""


class CopilotClient:
    def __init__(self, state, *, stop=False, trace=False):
        config = json.loads((ROOT / ".mcp.json").read_text())["mcpServers"]["cops"]
        args = config["args"] if not trace else ["-c", TRACE]
        self.process = subprocess.Popen(
            [config["command"], *args],
            cwd=ROOT / config["cwd"],
            env={
                **os.environ,
                "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                "XDG_STATE_HOME": str(state),
                "CALL_LOG": str(state / "calls"),
                "STOP_BEFORE": STAGES[1] if stop else "",
            },
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.serial = 0

    def send(self, method, params, *, notification=False):
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            self.serial += 1
            msg["id"] = self.serial
        self.process.stdin.write(json.dumps(msg) + "\n")
        self.process.stdin.flush()
        if not notification:
            line = self.process.stdout.readline()
            if not line:
                raise EOFError(self.process.wait(timeout=5))
            reply = json.loads(line)
            assert reply["id"] == msg["id"]
            return reply["result"]

    def __enter__(self):
        result = self.send(
            "initialize",
            {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test-chat", "version": "1"}},
        )
        assert result["protocolVersion"] == "2025-11-25"
        self.send("notifications/initialized", {}, notification=True)
        return self

    def __exit__(self, *exc):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        finally:
            self.process.kill()
            self.process.stdout.close()

    def call(self, **arguments):
        reply = self.send("tools/call", {"name": "request", "arguments": arguments})
        return json.loads(reply["content"][0]["text"])


class CopilotTests(unittest.TestCase):
    def test_one_chat_request(self):
        with tempfile.TemporaryDirectory() as raw, CopilotClient(Path(raw)) as chat:
            tools = chat.send("tools/list", {})["tools"]
            self.assertEqual([tool["name"] for tool in tools], ["request"])
            ticket = chat.call(request=ASK)
            self.assertEqual(ticket["status"], "accepted")
            report = chat.call(run_id=ticket["run_id"])
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["specialist"], "cops-detection-engineer")
            self.assertEqual(report["workbench"], "detection-quality-workbench")
            self.assertEqual(report["skill"], "detection-quality-review")
            self.assertEqual(report["totals"]["evaluated_cases"], 15)
            self.assertEqual(report["totals"]["total_cases"], 18)
            self.assertEqual([s["missing_fields"] for s in report["suites"]], [["IPAddress"], ["ScriptBlockText"]])
            self.assertEqual(
                [[case["case_id"] for case in suite["gaps"]] for suite in report["suites"]],
                [["CASE-BND-MISSING-FIELD", "CASE-BND-NULL-IP"], ["CASE-SPL-BND-MISSING"]],
            )
            self.assertNotIn(raw, json.dumps([ticket, report]))

    def test_workspace_registration(self):
        for adapter in (
            ".github/agents/cops.agent.md",
            ".github/agents/squad.agent.md",
            ".github/copilot-instructions.md",
        ):
            self.assertIn("cops/request", (ROOT / adapter).read_text())
        config = json.loads((ROOT / ".mcp.json").read_text())["mcpServers"]["cops"]
        self.assertEqual(config["tools"], ["request"])
        default_agent = json.loads((ROOT / ".vscode/settings.json").read_text())["chat.newSession.defaultMode"]
        agent_file = ROOT / ".github/agents" / (default_agent.lower() + ".agent.md")
        self.assertIn("cops/request", agent_file.read_text())
        with tempfile.TemporaryDirectory() as raw, CopilotClient(Path(raw)) as chat:
            self.assertEqual([tool["name"] for tool in chat.send("tools/list", {})["tools"]], config["tools"])

    def test_interrupted_chat_resumes(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            with CopilotClient(state, stop=True, trace=True) as first:
                ticket = first.call(request=ASK)
                run_id = ticket["run_id"]
                self.assertFalse((state / "calls").exists())
                with self.assertRaisesRegex(EOFError, "75"):
                    first.call(run_id=run_id)
            self.assertEqual((state / "calls").read_text().splitlines(), list(STAGES[:1]))
            with CopilotClient(state, trace=True) as reopened:
                result = reopened.call(run_id=run_id)
                self.assertEqual([s["disposition"] for s in result["suites"]], ["reused", "evaluated"])
                replay = reopened.call(run_id=run_id)
                self.assertEqual([s["disposition"] for s in replay["suites"]], ["reused", "reused"])
                self.assertEqual(
                    [s["receipt_digest"] for s in result["suites"]], [s["receipt_digest"] for s in replay["suites"]]
                )
            self.assertEqual((state / "calls").read_text().splitlines(), list(STAGES))

    def test_chat_boundaries(self):
        with tempfile.TemporaryDirectory() as raw, CopilotClient(Path(raw)) as chat:
            for request in ("Do not " + ASK, ASK + " Also deploy them.", "Resume my review."):
                self.assertEqual(chat.call(request=request)["status"], "clarification_required")
            for args in ({"run_id": "../another-run"}, {"run_id": "0" * 32}, {"request": ASK, "run_id": "0" * 32}, {}):
                self.assertEqual(chat.call(**args)["status"], "failed")
            self.assertEqual(list(Path(raw).rglob("checkpoint.sqlite3")), [])
            one, two = chat.call(request=ASK), chat.call(request=ASK)
            self.assertNotEqual(one["run_id"], two["run_id"])
            self.assertEqual(chat.call(run_id=one["run_id"])["run_id"], one["run_id"])
