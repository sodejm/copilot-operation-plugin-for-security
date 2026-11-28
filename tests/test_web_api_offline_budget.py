"""Offline replay batch-budget regressions without network transport."""

from __future__ import annotations

from copy import deepcopy

import pytest

import cops.web_api.replay as replay_module
from cops.web_api.models import ReplayBudget, ReplayRequest, ReplayResponse
from cops.web_api.replay import (
    OfflineSyntheticReplayer,
    ReplayAuthorizationError,
    ReplayBudgetExceededError,
    Replayer,
    execute_replay_session,
)


def _requests(count: int, *, denied_index: int | None = None) -> list[ReplayRequest]:
    requests = []
    for index in range(count):
        host = "denied.example.test" if index == denied_index else "api.example.test"
        requests.append(
            ReplayRequest(
                request_id=f"request-{index}",
                endpoint_id=f"endpoint-{index}",
                method="GET",
                url=f"https://{host}/resource/{index}",
                headers={"X-Test": f"value-{index}"},
            )
        )
    return requests


class RecordingOfflineReplayer(OfflineSyntheticReplayer):
    def __init__(self) -> None:
        super().__init__()
        self.budgets_seen: list[ReplayBudget] = []

    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        self.budgets_seen.append(budget)
        return super().send(req, budget)


class NetworkReplayer(Replayer):
    def __init__(self) -> None:
        self.requests_sent: list[ReplayRequest] = []

    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        self.requests_sent.append(req)
        raise AssertionError("network replayer dispatched")


@pytest.mark.parametrize(
    ("requests", "budget"),
    [
        (_requests(3), ReplayBudget(max_requests=2)),
        (_requests(ReplayBudget().max_requests + 1), None),
    ],
    ids=["small-limit", "default-limit"],
)
def test_oversized_offline_batch_fails_before_send_or_report(monkeypatch, requests, budget):
    replayer = RecordingOfflineReplayer()
    report_calls = []
    original_report = replay_module._report

    def report_spy(**kwargs):
        report_calls.append(kwargs)
        return original_report(**kwargs)

    monkeypatch.setattr(replay_module, "_report", report_spy)

    with pytest.raises(ReplayBudgetExceededError, match=r"^request count exceeds max_requests$"):
        execute_replay_session(requests, ["api.example.test"], budget, replayer)

    assert replayer.requests_sent == []
    assert replayer.budgets_seen == []
    assert report_calls == []


def test_exact_limit_preserves_batch_order_coverage_and_callers():
    requests = _requests(3, denied_index=1)
    destinations = ["api.example.test", "unused.example.test"]
    budget = ReplayBudget(max_requests=3, rate_limit_rps=0)
    original_requests = deepcopy(requests)
    original_destinations = list(destinations)
    original_budget = deepcopy(budget)
    replayer = RecordingOfflineReplayer()

    report = execute_replay_session(requests, destinations, budget, replayer)

    expected_ids = ["request-0", "request-1", "request-2"]
    assert [item.request_id for item in report.requests] == expected_ids
    assert [item.request_id for item in report.responses] == expected_ids
    assert [item.request_id for item in replayer.requests_sent] == ["request-0", "request-2"]
    assert report.total_dispatched == 3
    assert report.total_successful == 2
    assert report.total_failed == 1
    assert report.destination_violations == 1
    assert all(seen is not budget for seen in replayer.budgets_seen)
    assert requests == original_requests
    assert destinations == original_destinations
    assert budget == original_budget


def test_empty_batch_returns_an_empty_report_without_send():
    replayer = RecordingOfflineReplayer()

    report = execute_replay_session([], ["api.example.test"], replayer=replayer)

    assert report.requests == []
    assert report.responses == []
    assert report.total_dispatched == 0
    assert report.total_successful == 0
    assert report.total_failed == 0
    assert report.destination_violations == 0
    assert replayer.requests_sent == []
    assert replayer.budgets_seen == []


@pytest.mark.parametrize(
    ("budget", "message"),
    [
        (ReplayBudget(max_requests=0), "max_requests must be an integer between 1 and 1000"),
        (ReplayBudget(max_requests=True), "max_requests must be an integer between 1 and 1000"),
        (ReplayBudget(timeout_seconds=float("inf")), "timeout_seconds must be a finite number"),
    ],
)
def test_invalid_budget_still_fails_before_send_or_report(monkeypatch, budget, message):
    replayer = RecordingOfflineReplayer()
    report_calls = []
    monkeypatch.setattr(replay_module, "_report", lambda **kwargs: report_calls.append(kwargs))

    with pytest.raises(ReplayBudgetExceededError, match=f"^{message}$"):
        execute_replay_session(_requests(1), ["api.example.test"], budget, replayer)

    assert replayer.requests_sent == []
    assert report_calls == []


def test_network_replayer_remains_rejected_without_dispatch():
    replayer = NetworkReplayer()

    with pytest.raises(
        ReplayAuthorizationError,
        match=r"^live replay requires execute_authorized_replay_session$",
    ):
        execute_replay_session(_requests(1), ["api.example.test"], replayer=replayer)

    assert replayer.requests_sent == []
