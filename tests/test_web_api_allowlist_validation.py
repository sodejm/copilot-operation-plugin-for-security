"""Destination allowlist grammar and fail-closed entry-point regressions."""

from __future__ import annotations

import traceback
from copy import deepcopy

import pytest

from cops.web_api.models import ReplayBudget, ReplayRequest
from cops.web_api.replay import (
    DestinationGuard,
    DestinationViolationError,
    OfflineSyntheticReplayer,
    build_replay_action_plan,
    execute_authorized_replay_session,
    execute_replay_session,
    preview_replay_session,
)

_ERROR = "destination allowlist contains an invalid entry"
_OVERSIZED_PORT = "9" * 5_000


def _request(url: str = "https://api.example.test/resource") -> ReplayRequest:
    return ReplayRequest(
        request_id="request-one",
        endpoint_id="endpoint-one",
        method="GET",
        url=url,
    )


def _trace(error: BaseException) -> str:
    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


@pytest.mark.parametrize(
    ("allowed", "url", "expected"),
    [
        ("api.example.test", "https://API.EXAMPLE.TEST/resource", True),
        ("API.EXAMPLE.TEST", "https://api.example.test:9443/resource", True),
        ("api.example.test:8443", "https://api.example.test:8443/resource", True),
        ("api.example.test:8443", "https://api.example.test/resource", False),
        ("127.0.0.1", "http://127.0.0.1/resource", True),
        ("127.0.0.1:8080", "http://127.0.0.1:8080/resource", True),
        ("127.0.0.1:8080", "http://127.0.0.1:8081/resource", False),
        ("[2001:db8::1]", "https://[2001:db8::1]/resource", True),
        ("[2001:db8::1]", "https://[2001:0DB8:0:0:0:0:0:1]/resource", False),
        ("[2001:db8::1]:8443", "https://[2001:db8::1]:8443/resource", True),
        ("[2001:db8::1]:8443", "https://[2001:db8::1]/resource", False),
        ("*.example.test", "https://example.test/resource", True),
        ("*.EXAMPLE.TEST", "https://a.b.example.test/resource", True),
        ("*.example.test", "https://notexample.test/resource", False),
    ],
)
def test_supported_allowlist_grammar_matches_without_broadening(allowed, url, expected):
    assert DestinationGuard([allowed]).is_destination_allowed(url) is expected


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        None,
        7,
        " api.example.test",
        "api.example.test ",
        "api. example.test",
        "api.example.test\n",
        "api.example.test\x7f",
        "alice:password@other.test",
        "https://api.example.test",
        "api.example.test/path",
        "api.example.test?query=secret",
        "api.example.test#fragment",
        "%61pi.example.test",
        "api\\example.test",
        "*",
        "example.*.test",
        "**.example.test",
        "*.example.test:443",
        "*.127.0.0.1",
        ".example.test",
        "example..test",
        "-example.test",
        "example-.test",
        "example_test",
        "tést.example",
        "999.0.0.1",
        "::1",
        "[::1",
        "[::1]suffix",
        "[127.0.0.1]",
        "[private-token]",
        "api.example.test:",
        "api.example.test:zero",
        "api.example.test:0",
        "api.example.test:080",
        "api.example.test:65536",
        "2130706433",
        "0x7f000001",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "127.1",
        f"api.example.test:{_OVERSIZED_PORT}",
        f"127.0.0.1:{_OVERSIZED_PORT}",
        "[::1]:0",
        "[::1]:080",
        "[::1]:65536",
        f"[::1]:{_OVERSIZED_PORT}",
    ],
)
def test_malformed_allowlist_items_have_one_content_free_error(invalid):
    with pytest.raises(DestinationViolationError) as raised:
        DestinationGuard([invalid])

    assert str(raised.value) == _ERROR
    if isinstance(invalid, str) and invalid:
        assert invalid not in _trace(raised.value)


class _ApprovalProbe:
    def __init__(self) -> None:
        self.ready_calls = []
        self.consume_calls = []

    def assert_ready(self, worker_identity):
        self.ready_calls.append(worker_identity)

    def consume_authorization(self, *args):
        self.consume_calls.append(args)
        raise AssertionError("invalid allowlist reached approval consumption")


class _ScopeProbe:
    def __init__(self) -> None:
        self.calls = []

    def check_destination(self, destination):
        self.calls.append(destination)
        raise AssertionError("invalid allowlist reached scope resolution")


class _DeepcopyBomb:
    marker = "deepcopy-secret-value"

    def __init__(self) -> None:
        self.deepcopy_calls = 0

    def __deepcopy__(self, memo):
        self.deepcopy_calls += 1
        raise RuntimeError(self.marker)


def _plan(requests, destinations, budget):
    return build_replay_action_plan(
        plan_id="plan-allowlist-validation",
        engagement_id="eng-allowlist-validation",
        scenario_id="scen-allowlist-validation",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        allowed_destinations=destinations,
        budget=budget,
        created_at="2026-10-18T00:00:00Z",
    )


def _invoke(entry_point, requests, destinations, budget, replayer, plan, approval, scope):
    if entry_point == "preview":
        return preview_replay_session(requests, destinations, budget)
    if entry_point == "plan":
        return _plan(requests, destinations, budget)
    if entry_point == "offline":
        return execute_replay_session(requests, destinations, budget, replayer)
    return execute_authorized_replay_session(
        requests=requests,
        sessions=[],
        allowed_destinations=destinations,
        scope_guard=scope,
        budget=budget,
        action_plan=plan,
        authorization_id="auth-allowlist-validation",
        approval_control=approval,
        worker_identity="worker-allowlist-validation",
    )


@pytest.mark.parametrize("entry_point", ["preview", "plan", "offline", "authorized"])
@pytest.mark.parametrize("placement", ["used", "unused"])
@pytest.mark.parametrize(
    ("factory", "matching_url", "secret"),
    [
        (
            lambda: "alice:password@other.test",
            "https://other.test/resource",
            "alice:password@other.test",
        ),
        (lambda: "[private-token]", "https://[private-token]/resource", "private-token"),
        (lambda: "2130706433", "http://2130706433/resource", "2130706433"),
        (lambda: memoryview(b"memory-secret.test"), "https://memory-secret.test/resource", "memory-secret"),
        (_DeepcopyBomb, "https://deepcopy-secret.test/resource", _DeepcopyBomb.marker),
    ],
    ids=["userinfo", "malformed-ipv6", "legacy-ipv4", "memoryview", "deepcopy-bomb"],
)
def test_every_entry_point_rejects_used_and_unused_values_without_side_effects(
    entry_point, placement, factory, matching_url, secret
):
    invalid = factory()
    request_url = matching_url if placement == "used" else "https://api.example.test/resource"
    destinations = [invalid] if placement == "used" else ["api.example.test", invalid]
    requests = [_request(request_url)]
    budget = ReplayBudget(max_requests=1)
    replayer = OfflineSyntheticReplayer()
    approval = _ApprovalProbe()
    scope = _ScopeProbe()
    plan = _plan([_request()], ["api.example.test"], budget)
    original_requests = deepcopy(requests)
    original_budget = deepcopy(budget)
    original_container = list(destinations)
    original_element_ids = [id(item) for item in destinations]

    with pytest.raises(DestinationViolationError) as raised:
        _invoke(entry_point, requests, destinations, budget, replayer, plan, approval, scope)

    assert str(raised.value) == _ERROR
    assert secret not in _trace(raised.value)
    assert requests == original_requests
    assert budget == original_budget
    assert destinations == original_container
    assert [id(item) for item in destinations] == original_element_ids
    if isinstance(invalid, _DeepcopyBomb):
        assert invalid.deepcopy_calls == 0
    assert replayer.requests_sent == []
    assert scope.calls == []
    assert approval.ready_calls == []
    assert approval.consume_calls == []


def test_valid_snapshot_preserves_spelling_order_and_is_independent_of_container():
    destinations = ["API.Example.TEST", "unused.example.test:8443"]
    report = preview_replay_session([_request()], destinations)

    destinations[0] = "changed.example.test"
    assert report.allowed_destinations == ["API.Example.TEST", "unused.example.test:8443"]
