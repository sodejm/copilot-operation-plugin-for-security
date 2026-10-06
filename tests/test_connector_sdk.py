"""Fault-injection tests for the common acquisition runner (no tenant access)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cops.connectors import Checkpoint, GraphUsers, Limits, ResourceGraph, Response, collect, preview
from cops.evidence import EvidenceError, validate_receipt

TENANT = "00000000-0000-0000-0000-000000000001"
SUB = "00000000-0000-0000-0000-000000000002"
USER1 = "00000000-0000-0000-0000-000000000003"
USER2 = "00000000-0000-0000-0000-000000000004"
CANARY = "CANARY_AUTH_OR_UNREVIEWED_DATA"


def fixture(adapter="graph"):
    if adapter == "graph":
        return GraphUsers(TENANT), [
            {
                "value": [{"id": USER1, "userType": "Member", "displayName": CANARY}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=opaque",
            },
            {"value": [{"id": USER2, "userType": "Guest"}]},
        ]
    return ResourceGraph(TENANT, [SUB]), [
        {
            "data": [
                {
                    "id": f"/subscriptions/{SUB}/resourceGroups/demo/providers/microsoft.compute/virtualMachines/a",
                    "type": "microsoft.compute/virtualmachines",
                    "location": "eastus",
                    "tags": {"secret": CANARY},
                }
            ],
            "count": 1,
            "totalRecords": 2,
            "resultTruncated": "true",
            "$skipToken": "opaque",
        },
        {
            "data": [
                {
                    "id": f"/subscriptions/{SUB}/resourceGroups/demo/providers/microsoft.compute/virtualMachines/b",
                    "type": "microsoft.compute/virtualmachines",
                    "location": "eastus",
                }
            ],
            "count": 1,
            "totalRecords": 2,
            "resultTruncated": "false",
        },
    ]


class Credentials:
    def __init__(self):
        self.refreshes = []

    def headers(self, *, refresh=False):
        self.refreshes.append(refresh)
        return {"Authorization": "Bearer " + CANARY}


class Transport:
    def __init__(self, pages):
        self.pages, self.requests = list(pages), []

    def send(self, request, headers, *, timeout, max_bytes):
        self.requests.append(request)
        page = self.pages.pop(0)
        if isinstance(page, BaseException):
            raise page
        if isinstance(page, Response):
            return page
        return Response(200, json.dumps(page).encode())


class Crash(BaseException):
    pass


def run(tmp_path, pages, adapter=None, limits=None, **kw):
    with Checkpoint(tmp_path / "private") as checkpoint:
        return collect(
            adapter or fixture()[0], checkpoint, Credentials(), Transport(pages), limits=limits or Limits(), **kw
        )


@pytest.mark.parametrize("name", ["graph", "arg"])
def test_resume_after_page_commit(tmp_path, name):
    adapter, pages = fixture(name)
    with pytest.raises(Crash):
        run(
            tmp_path,
            pages,
            adapter,
            fault=lambda phase: (_ for _ in ()).throw(Crash()) if phase == "after_commit" else None,
        )
    result = run(tmp_path, [pages[1]], adapter)
    assert len(result.records) == 2
    assert result.receipt["status"] == "complete"
    validate_receipt(result.receipt)
    assert CANARY not in json.dumps(result.records)
    assert result.records[0]["observed"]["at"] is None


def test_limits_stop_and_preserve_accepted_records(tmp_path):
    adapter, pages = fixture()
    result = run(tmp_path, pages, adapter, Limits(records=1))
    assert len(result.records) == 1
    assert result.receipt["reasons"] == ["record_limit"]
    assert result.receipt["status"] == "partial"


@pytest.mark.parametrize("partial", [False, True])
def test_terminal_resume_preserves_collection_interval(tmp_path, partial):
    adapter, pages = fixture()
    limits = Limits(records=1) if partial else Limits()
    first = run(tmp_path, pages, adapter, limits, now=lambda: "2026-09-28T00:00:00Z")
    credentials, transport = Credentials(), Transport([])
    with Checkpoint(tmp_path / "private") as checkpoint:
        resumed = collect(
            adapter, checkpoint, credentials, transport, limits=limits, now=lambda: "2026-09-29T00:00:00Z"
        )
    assert resumed.receipt["finished_at"] == first.receipt["finished_at"]
    assert resumed.receipt["started_at"] == first.receipt["started_at"]
    assert resumed.receipt["status"] == ("partial" if partial else "complete")
    assert resumed.receipt["generation"] == 2
    assert credentials.refreshes == transport.requests == []


def test_terminal_commit_persists_finish_before_interruption(tmp_path):
    adapter, pages = fixture()
    with pytest.raises(Crash):
        run(
            tmp_path,
            [pages[1]],
            adapter,
            now=lambda: "2026-09-28T00:00:00Z",
            fault=lambda phase: (_ for _ in ()).throw(Crash()) if phase == "after_commit" else None,
        )
    resumed = run(tmp_path, [], adapter, now=lambda: "2026-09-29T00:00:00Z")
    assert resumed.receipt["finished_at"] == "2026-09-28T00:00:00Z"


@pytest.mark.parametrize("name", ["graph", "arg"])
def test_duplicate_processing_stops_at_active_time_limit(tmp_path, monkeypatch, name):
    import cops.connectors.runner as runner

    adapter, pages = fixture(name)
    key = "value" if name == "graph" else "data"
    pages[0][key] *= 100
    if name == "arg":
        pages[0]["count"] = pages[0]["totalRecords"] = 100
    current, calls = [0.0], []
    original = runner.build_envelope

    def processing_cost(**kwargs):
        calls.append(kwargs["identity"])
        current[0] += 0.4
        return original(**kwargs)

    monkeypatch.setattr(runner, "build_envelope", processing_cost)
    result = run(tmp_path, pages, adapter, Limits(active_seconds=1, request_seconds=1), clock=lambda: current[0])
    assert len(calls) <= 3
    assert len(result.records) == 1
    assert result.receipt["reasons"] == ["time_limit"]
    assert result.receipt["consumed"]["active_seconds"] == 1


@pytest.mark.parametrize("name", ["graph", "arg"])
def test_adapter_projection_stops_at_active_time_limit(tmp_path, monkeypatch, name):
    import cops.connectors.adapters.microsoft as microsoft

    adapter, pages = fixture(name)
    key = "value" if name == "graph" else "data"
    pages[0][key] *= 100
    if name == "arg":
        pages[0]["count"] = pages[0]["totalRecords"] = 100
    current, projections = [0.0], []
    if name == "graph":
        original = microsoft.UUID

        def match(value):
            projections.append(value)
            current[0] += 0.4
            return original.fullmatch(value)

        from types import SimpleNamespace

        monkeypatch.setattr(microsoft, "UUID", SimpleNamespace(fullmatch=match))
    else:
        original = microsoft.re.fullmatch

        def match(pattern, value, *args, **kwargs):
            if pattern.startswith("/subscriptions/"):
                projections.append(value)
                current[0] += 0.4
            return original(pattern, value, *args, **kwargs)

        monkeypatch.setattr(microsoft.re, "fullmatch", match)
    result = run(tmp_path, pages, adapter, Limits(active_seconds=1, request_seconds=1), clock=lambda: current[0])
    assert len(projections) <= 3
    assert len(result.records) == 1
    assert result.receipt["reasons"] == ["time_limit"]


def test_auth_throttle_duplicates_and_secret_boundary(tmp_path, capsys):
    adapter, pages = fixture()
    pages[1]["value"].insert(0, pages[0]["value"][0])
    credentials = Credentials()
    transport = Transport([pages[0], Response(401, CANARY.encode()), Response(429, CANARY.encode(), "0"), pages[1]])
    with Checkpoint(tmp_path / "private") as cp:
        result = collect(adapter, cp, credentials, transport, sleep=lambda seconds: None)
    assert result.receipt["status"] == "complete"
    assert result.receipt["consumed"]["duplicates"] == 1
    assert credentials.refreshes.count(True) == 1
    assert result.receipt["consumed"]["attempts"] == 4
    assert CANARY not in repr(result) + json.dumps(result.receipt) + str(capsys.readouterr())


@pytest.mark.parametrize(
    "failure,code",
    [
        ({"unexpected": []}, "schema_drift"),
        (Response(401, CANARY.encode()), "authentication"),
        (ValueError(CANARY), "transport"),
    ],
)
def test_partial_errors_are_safe(tmp_path, failure, code):
    _, pages = fixture()
    result = run(tmp_path, [pages[0], failure, failure])
    assert result.receipt["status"] == "partial"
    assert code in result.receipt["reasons"]
    assert len(result.records) == 1
    assert CANARY not in json.dumps(result.receipt)


@pytest.mark.parametrize(
    "link",
    [
        "http://graph.microsoft.com/v1.0/users",
        "https://evil.invalid/v1.0/users",
        "https://graph.microsoft.com:444/v1.0/users",
        "https://graph.microsoft.com/v1.0/users?access_token=secret",
        "https://graph.microsoft.com/v1.0/users/../../me",
        "https://graph.microsoft.com/v1.0/users#$skiptoken=x",
    ],
)
def test_hostile_continuation_never_gets_credentials(tmp_path, link):
    adapter, pages = fixture()
    pages[0]["@odata.nextLink"] = link
    credentials, transport = Credentials(), Transport(pages)
    with Checkpoint(tmp_path / "private") as cp:
        result = collect(adapter, cp, credentials, transport)
    assert result.receipt["reasons"] == ["unsafe_destination"]
    assert len(credentials.refreshes) == 1
    assert len(transport.requests) == 1


def test_preview_has_no_effects():
    plan = preview(fixture()[0])
    assert plan["method"] == "GET"
    assert "Authorization" not in json.dumps(plan)


def test_crash_reservation_and_resume_binding(tmp_path):
    adapter, pages = fixture()
    with pytest.raises(Crash):
        run(
            tmp_path,
            pages,
            adapter,
            fault=lambda phase: (_ for _ in ()).throw(Crash()) if phase == "after_reserve" else None,
        )
    with pytest.raises(EvidenceError, match="resume_mismatch"):
        run(tmp_path, pages, GraphUsers(SUB))
    with pytest.raises(EvidenceError, match="resume_limits"):
        run(tmp_path, pages, adapter, Limits(pages=101))
    result = run(tmp_path, pages, adapter)
    assert result.receipt["consumed"]["attempts"] == 3
    assert result.receipt["consumed"]["bytes"] >= Limits().response_bytes


def test_private_checkpoint_rejects_symlink_and_permissions(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(EvidenceError, match="private_storage"):
        Checkpoint(link)
    target.chmod(0o755)
    with pytest.raises(EvidenceError, match="private_storage"):
        Checkpoint(target)


@pytest.mark.parametrize(
    "limits,reason",
    [
        (Limits(pages=1), "page_limit"),
        (Limits(attempts=1), "attempt_limit"),
        (Limits(total_bytes=1), "response_limit"),
        (Limits(response_bytes=1), "response_limit"),
        (Limits(storage_bytes=1), "storage_limit"),
        (Limits(record_bytes=1), "projection_failed"),
    ],
)
def test_budgets_are_enforced(tmp_path, limits, reason):
    result = run(tmp_path, fixture()[1], limits=limits)
    assert result.receipt["status"] == "partial"
    assert result.receipt["reasons"] == [reason]
    validate_receipt(result.receipt)


@pytest.mark.parametrize(
    "failure,reason",
    [
        (Response(200, b"{broken"), "invalid_json"),
        (Response(410, b"PRIVATE"), "cursor_expired"),
        (Response(302, b"PRIVATE"), "transport"),
        (Response(429, b"", "invalid"), "throttled"),
    ],
)
def test_later_failure_keeps_first_page(tmp_path, failure, reason):
    result = run(tmp_path, [fixture()[1][0], failure])
    assert result.receipt["reasons"] == [reason]
    assert len(result.records) == 1


def test_cycles_and_retry_continuations_are_partial(tmp_path):
    adapter, pages = fixture()
    pages[1]["@odata.nextLink"] = pages[0]["@odata.nextLink"]
    result = run(tmp_path, pages)
    assert result.receipt["reasons"] == ["cursor_cycle"]
    assert len(result.records) == 2
    other = tmp_path / "other"
    other.mkdir()
    result = run(other, [Response(429, b"", "0"), pages[0]], sleep=lambda seconds: None)
    assert result.receipt["reasons"] == ["retry_continuation"]


def test_arg_truncation_without_cursor_is_partial(tmp_path):
    adapter, pages = fixture("arg")
    del pages[0]["$skipToken"]
    result = run(tmp_path, pages, adapter)
    assert result.receipt["reasons"] == ["truncated_without_cursor"]
    assert len(result.records) == 1


def test_before_commit_crash_replays_page_once(tmp_path):
    adapter, pages = fixture()
    with pytest.raises(Crash):
        run(tmp_path, pages, fault=lambda phase: (_ for _ in ()).throw(Crash()) if phase == "before_commit" else None)
    result = run(tmp_path, pages)
    assert len(result.records) == 2
    assert result.receipt["consumed"]["attempts"] == 3
    assert result.receipt["consumed"]["pages"] == 2
    assert result.receipt["consumed"]["active_seconds"] >= Limits().request_seconds


def test_retry_budget_survives_interruption(tmp_path):
    adapter, pages = fixture("arg")
    with pytest.raises(Crash):
        run(
            tmp_path,
            [Response(429, b"", "0")],
            adapter,
            Limits(retries=1),
            sleep=lambda seconds: (_ for _ in ()).throw(Crash()),
        )
    result = run(
        tmp_path, [Response(429, b"", "0"), pages[0], pages[1]], adapter, Limits(retries=1), sleep=lambda seconds: None
    )
    assert result.receipt["reasons"] == ["throttled"]
    assert result.receipt["consumed"]["attempts"] == 2


def test_resume_rejects_budget_below_spend_and_corrupt_counts(tmp_path):
    adapter, pages = fixture()
    with pytest.raises(Crash):
        run(tmp_path, pages, fault=lambda phase: (_ for _ in ()).throw(Crash()) if phase == "after_commit" else None)
    with pytest.raises(EvidenceError, match="resume_limits"):
        run(tmp_path, pages, limits=Limits(total_bytes=1))
    with Checkpoint(tmp_path / "private") as cp:
        state = cp.load()
        state["consumed"]["records"] += 1
        cp.save(state)
    with pytest.raises(EvidenceError, match="checkpoint_invalid"):
        run(tmp_path, pages)


@pytest.mark.parametrize("limits", [Limits(record_bytes=1), Limits(depth=1)])
def test_resume_rejects_bounds_that_cannot_hold_committed_records(tmp_path, limits):
    adapter, pages = fixture()
    with pytest.raises(Crash):
        run(tmp_path, pages, fault=lambda phase: (_ for _ in ()).throw(Crash()) if phase == "after_commit" else None)
    credentials, transport = Credentials(), Transport(pages[1:])
    with Checkpoint(tmp_path / "private") as checkpoint:
        with pytest.raises(EvidenceError, match="resume_limits"):
            collect(adapter, checkpoint, credentials, transport, limits=limits)
    assert credentials.refreshes == []
    assert transport.requests == []


def test_timeout_and_sleep_use_active_budget(tmp_path):
    instant = [0]

    class Slow(Transport):
        def send(self, *args, **kwargs):
            instant[0] += 2
            return super().send(*args, **kwargs)

    with Checkpoint(tmp_path / "private") as cp:
        result = collect(
            fixture()[0],
            cp,
            Credentials(),
            Slow(fixture()[1]),
            limits=Limits(request_seconds=1),
            clock=lambda: instant[0],
        )
    assert result.receipt["reasons"] == ["request_timeout"]
    other = tmp_path / "other"
    other.mkdir()
    result = run(other, [Response(429, b"", "300")])
    assert result.receipt["reasons"] == ["time_limit"]


def test_checkpoint_and_export_never_persist_auth_or_unselected_data(tmp_path):
    result = run(tmp_path, fixture()[1])
    assert CANARY.encode() not in (tmp_path / "private" / "checkpoint.sqlite3").read_bytes()
    assert CANARY not in json.dumps(result.records) + json.dumps(result.receipt)
