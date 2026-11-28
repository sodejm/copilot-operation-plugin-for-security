"""Public CLI acceptance for the two-suite offline detection review."""

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from cops.catalog import ROOT
from cops.routing.detection_quality import route_bundled_review
from cops.workflows import detection_quality as pilot

ASK = "Check the bundled Sentinel and Splunk rules against their labeled fixtures and explain the coverage gaps."
PACKAGE = ROOT / "plugins/detection-hunting/detection-quality-workbench"


def ask(*args, instrument=None):
    command = [sys.executable, "-m", "cops"]
    if instrument:
        command = [sys.executable, "-c", INSTRUMENT, *map(str, instrument)]
    return subprocess.run(
        [*command, "ask", *map(str, args), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


# Exercise the real CLI and evaluator in a separate process. Only the test
# harness records invocations and can terminate a coordinator mid-transaction.
INSTRUMENT = """
import os, sys
from pathlib import Path
from cops.cli import main
from cops.workflows import detection_quality as pilot
log = Path(sys.argv.pop(1))
stop = sys.argv.pop(1) == 'interrupt'
evaluate = pilot.evaluate
def traced(package, stage):
    if stop and stage == pilot.STAGES[1]:
        os._exit(75)
    with log.open('a') as stream:
        print(stage, file=stream)
    return evaluate(package, stage)
pilot.evaluate = traced
raise SystemExit(main())
"""


class PilotTests(unittest.TestCase):
    def test_route_bundled_review(self):
        for query in (
            ASK,
            "Run the Detection Quality pilot.",
            "Please run both Detection Quality fixture sets and report the gaps.",
            "Evaluate the packaged KQL and SPL rules against their labelled fixtures.",
            "Run the Detection Quality workbench on both fixture sets.",
            "Can you run both fixture sets for Detection Quality and tell me what's missing?",
            "Review the Splunk and Sentinel fixture suites, then list any telemetry gaps.",
            "Run the Detection Quality pilot on both bundled fixture sets.",
        ):
            with self.subTest(query=query):
                decision = route_bundled_review(query)
                self.assertEqual(decision.status, "routed")
                self.assertEqual(decision.primary_profile.primary_plugin, pilot.WORKBENCH)
                self.assertEqual(decision.recommended_skills, (pilot.SKILL,))
                self.assertIn("bundled", decision.match_reasons[0].lower())

    def test_advisory_route_agrees_with_ask(self):
        result = subprocess.run(
            [sys.executable, "-m", "cops", "route", ASK, "--json"], cwd=ROOT, capture_output=True, text=True, check=True
        )
        preview = json.loads(result.stdout)
        self.assertEqual(preview["primary_profile"]["id"], pilot.SPECIALIST)
        self.assertEqual(preview["recommended_skills"], [pilot.SKILL])

    def test_reject_invented_missing_fields(self):
        report = pilot.evaluate(PACKAGE, pilot.STAGES[0])
        report["static_checks"]["missing_fields"] = ["InventedField"]
        with self.assertRaisesRegex(ValueError, "missing fields"):
            pilot.verify(PACKAGE, pilot.STAGES[0], report)

    def test_ask_refuses_unmatched_requests(self):
        for query in (
            "Do not " + ASK,
            "Explain how to " + ASK,
            "Check the bundled Sentinel rules against their labeled fixtures.",
            ASK + " Also deploy the results.",
            "Evaluate detection coverage.",
            "Run both Detection Quality fixture sets against my tenant.",
            "cops-detection-engineer",
            "Which skill would run both Detection Quality fixture sets?",
            "Run both Detection Quality fixture sets except Splunk.",
            "Run both fixture sets for Detection Quality using my downloaded fixtures.",
        ):
            with self.subTest(query=query), tempfile.TemporaryDirectory() as raw:
                dest = Path(raw) / "absent"
                result = ask(query, "--run-dir", dest)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "clarification_required")
                self.assertFalse(dest.exists())

    def test_one_ask_reports_verified_gaps(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "run"
            result = ask(ASK, "--run-dir", dest)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "verified")
            self.assertEqual(report["run_dir"], str(dest))
            for key, value in pilot.SELECTION.items():
                self.assertEqual(report[key], value)
            self.assertEqual(
                report["totals"],
                dict(total_cases=18, evaluated_cases=15, schema_error_cases=3, false_positives=0, false_negatives=0),
            )
            sentinel, splunk = report["suites"]
            for suite, expected_field, case_ids in (
                (sentinel, "IPAddress", ["CASE-BND-MISSING-FIELD", "CASE-BND-NULL-IP"]),
                (splunk, "ScriptBlockText", ["CASE-SPL-BND-MISSING"]),
            ):
                self.assertEqual(suite["disposition"], "evaluated")
                self.assertEqual(suite["missing_fields"], [expected_field])
                self.assertEqual([c["case_id"] for c in suite["gaps"]], case_ids)
                self.assertIsNone(suite["metrics"]["precision_on_labeled_fixtures"])
                self.assertIsNone(suite["metrics"]["recall_on_labeled_fixtures"])

    def test_interrupted_resume_skips_accepted_work(self):
        with tempfile.TemporaryDirectory() as raw:
            dest, log = Path(raw) / "run", Path(raw) / "calls"
            crash = ask(ASK, "--run-dir", dest, instrument=(log, "interrupt"))
            self.assertEqual(crash.returncode, 75, crash.stderr)
            with closing(sqlite3.connect(dest / "checkpoint.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT stage FROM accepted").fetchall(), [(pilot.STAGES[0],)])
            self.assertEqual(log.read_text().splitlines(), list(pilot.STAGES[:1]))

            def resume():
                result = ask("--resume", dest, instrument=(log, "resume"))
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                return json.loads(result.stdout)

            with ThreadPoolExecutor(max_workers=2) as pool:
                resumes = [pool.submit(resume) for _ in range(2)]
                reports = [future.result() for future in resumes]
            dispositions = [[s["disposition"] for s in r["suites"]] for r in reports]
            self.assertCountEqual(dispositions, [["reused", "evaluated"], ["reused", "reused"]])
            final = resume()
            self.assertEqual([s["disposition"] for s in final["suites"]], ["reused", "reused"])
            self.assertEqual(final["totals"]["total_cases"], 18)
            with closing(sqlite3.connect(dest / "checkpoint.sqlite3")) as db:
                receipts = dict(db.execute("SELECT stage, receipt FROM accepted"))
            for report in [*reports, final]:
                self.assertEqual({s["rule_id"]: s["receipt_digest"] for s in report["suites"]}, receipts)
            self.assertEqual(log.read_text().splitlines(), list(pilot.STAGES))

    def test_damaged_receipt_fails_resume(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "run"
            self.assertEqual(ask(ASK, "--run-dir", dest).returncode, 0)
            with closing(sqlite3.connect(dest / "checkpoint.sqlite3")) as db, db:
                db.execute("UPDATE accepted SET receipt = 'damaged' WHERE stage = ?", (pilot.STAGES[0],))
            resumed = ask("--resume", dest)
            self.assertEqual(resumed.returncode, 2)
            self.assertIn("receipt", json.loads(resumed.stdout)["message"])

    def test_changed_fixture_fails_resume(self):
        with tempfile.TemporaryDirectory() as raw:
            dest, package = Path(raw) / "run", Path(raw) / "package"
            shutil.copytree(PACKAGE, package)
            pilot.run_review(package, dest, False)
            fixture = package / "fixtures" / f"{pilot.STAGES[0]}.json"
            with fixture.open("a") as stream:
                stream.write("\n")
            with self.assertRaisesRegex(ValueError, "input revision"):
                pilot.run_review(package, dest, True)
