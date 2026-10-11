"""Executable credential expiration scenarios using synthetic adapters only."""

import json

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.connectors import Checkpoint, Limits, Response, collect
from cops.connectors.demo import AS_OF, offline_fixture
from cops.evidence import canonical

scenarios("../../specs/features/credential_expiration.feature")

EXPIRY_CANARY = "OFFLINE_CREDENTIAL_CANARY"


class ExpiringFixtureCredentials:
    def __init__(self, fail_refresh=False):
        self.calls = []
        self.fail_refresh = fail_refresh

    def headers(self, *, refresh=False):
        self.calls.append(refresh)
        if refresh and self.fail_refresh:
            raise ValueError(EXPIRY_CANARY)
        label = "refreshed" if refresh else "expired"
        return {"Authorization": f"Bearer {label}-{EXPIRY_CANARY}"}


class ExpiryFixtureTransport:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def send(self, request, headers, *, timeout, max_bytes):
        self.requests.append((request.url, headers["Authorization"]))
        if len(self.requests) == 1:
            return Response(200, canonical(self.pages[0], max_bytes=max_bytes))
        if headers["Authorization"].startswith("Bearer expired-"):
            return Response(401, EXPIRY_CANARY.encode())
        return Response(200, canonical(self.pages[1], max_bytes=max_bytes))


@pytest.fixture
def acquisition():
    return {}


@given(parsers.parse('a private checkpoint for the "{name}" adapter'))
def private_checkpoint(acquisition, tmp_path, name):
    adapter, pages = offline_fixture(name)
    acquisition.update(adapter=adapter, pages=pages, path=tmp_path / "private")


@when("a later page rejects an expired credential and accepts one refresh")
def refresh_expired(acquisition):
    credentials = ExpiringFixtureCredentials()
    transport = ExpiryFixtureTransport(acquisition["pages"])
    with Checkpoint(acquisition["path"]) as checkpoint:
        result = collect(
            acquisition["adapter"], checkpoint, credentials, transport, limits=Limits(retries=1), now=lambda: AS_OF
        )
    acquisition.update(result=result, credentials=credentials, transport=transport)


@then("two unique pages are available without exposing the credential")
def refreshed_pages(acquisition):
    result = acquisition["result"]
    requests = acquisition["transport"].requests
    assert result.receipt["status"] == "complete"
    assert result.receipt["consumed"]["pages"] == 2
    assert result.receipt["consumed"]["attempts"] == 3
    assert [record["page"] for record in result.records] == [1, 2]
    assert len({record["record_id"] for record in result.records}) == 2
    assert acquisition["credentials"].calls == [False, False, True]
    assert requests[1][0] == requests[2][0]
    assert requests[1][1] != requests[2][1]
    assert EXPIRY_CANARY not in repr(result) + json.dumps(result.records) + json.dumps(result.receipt)
    assert EXPIRY_CANARY.encode() not in (acquisition["path"] / "checkpoint.sqlite3").read_bytes()


@when("a later page rejects an expired credential and refresh fails")
def failed_refresh(acquisition):
    credentials = ExpiringFixtureCredentials(fail_refresh=True)
    transport = ExpiryFixtureTransport(acquisition["pages"])
    with Checkpoint(acquisition["path"]) as checkpoint:
        result = collect(
            acquisition["adapter"], checkpoint, credentials, transport, limits=Limits(retries=1), now=lambda: AS_OF
        )
    acquisition.update(result=result, credentials=credentials, transport=transport)


@then("only the accepted page remains with a redacted authentication result")
def rejected_page_not_committed(acquisition):
    result = acquisition["result"]
    assert result.receipt["status"] == "partial"
    assert result.receipt["reasons"] == ["authentication"]
    assert result.receipt["consumed"]["pages"] == 1
    assert result.receipt["consumed"]["attempts"] == 2
    assert len(result.records) == 1 and result.records[0]["page"] == 1
    assert acquisition["credentials"].calls == [False, False, True]
    assert len(acquisition["transport"].requests) == 2
    assert EXPIRY_CANARY not in repr(result) + json.dumps(result.records) + json.dumps(result.receipt)
    assert EXPIRY_CANARY.encode() not in (acquisition["path"] / "checkpoint.sqlite3").read_bytes()
