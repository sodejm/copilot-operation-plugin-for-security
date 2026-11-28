"""Opt-in pytest hooks for the COPS benchmark."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _pytest.subtests import SubtestReport


def pytest_addoption(parser):
    parser.addoption("--cops-profile", type=Path)


def pytest_configure(config):
    output = config.getoption("--cops-profile")
    if output and not hasattr(config, "workerinput"):
        config.pluginmanager.register(Profile(output))


@pytest.hookimpl(wrapper=True)
def pytest_report_to_serializable(config, report):
    payload = yield
    if config.getoption("--cops-profile") and isinstance(report, SubtestReport):
        # Preserve the label before pytest reconstructs the worker's report.
        payload["cops_subtest_label"] = report.head_line
    return payload


class Profile:
    def __init__(self, output):
        self.output = output
        self.collections = {}
        self.reports = []

    def pytest_collection_finish(self, session):
        self.collections["serial"] = [item.nodeid for item in session.items]

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids):
        self.collections[node.gateway.id] = list(ids)

    def pytest_runtest_logreport(self, report):
        skip_reason = None
        if report.skipped and isinstance(report.longrepr, tuple):
            skip_reason = report.longrepr[2]
        entry = {
            "nodeid": report.nodeid,
            "phase": report.when,
            "outcome": report.outcome,
            "skip_reason": skip_reason,
            "xfail_reason": getattr(report, "wasxfail", None),
            "seconds": round(report.duration, 6),
        }
        if isinstance(report, SubtestReport):
            entry["subtest"] = getattr(report, "cops_subtest_label", report.head_line)
        self.reports.append(entry)

    def pytest_sessionfinish(self, session, exitstatus):
        self.output.write_text(
            json.dumps({"exit_code": int(exitstatus), "collections": self.collections, "reports": self.reports}),
            encoding="utf-8",
        )
