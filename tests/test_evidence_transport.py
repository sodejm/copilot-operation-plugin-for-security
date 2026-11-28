"""Exercise deadlines and response caps without sockets or tenant credentials."""

import http.client
import io
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cops.connectors import Request
from cops.connectors.transport import HttpsTransport
from cops.evidence import EvidenceError


class Connection:
    def __init__(self, *args, **kwargs):
        self.sock = SimpleNamespace(settimeout=lambda seconds: None, shutdown=lambda how: None)
        self.sent = False
        self.closed = threading.Event()

    def connect(self):
        pass

    def request(self, *args, **kwargs):
        self.sent = True

    def getresponse(self):
        return self.response

    def close(self):
        self.closed.set()


class Reply:
    status = 200

    def __init__(self, data=b"{}", headers=None):
        self.data, self.headers = data, headers or {}
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=lambda seconds: None)))

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def read1(self, size):
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk


def dispatch(monkeypatch, connection, *, cap=20, timeout=1):
    monkeypatch.setattr("cops.connectors.transport.http.client.HTTPSConnection", lambda *a, **k: connection)
    return HttpsTransport("example.invalid", "/read", "GET").send(
        Request("GET", "https://example.invalid/read"),
        {"Authorization": "Bearer TEST_ONLY"},
        timeout=timeout,
        max_bytes=cap,
    )


def test_deadline_includes_connect_and_prevents_late_credentials(monkeypatch):
    connection = Connection()
    released, done = threading.Event(), threading.Event()

    def stalled_connect():
        released.wait(2)
        done.set()

    connection.connect = stalled_connect
    connection.response = Reply()
    began = time.monotonic()
    try:
        with pytest.raises(EvidenceError, match="request_timeout"):
            dispatch(monkeypatch, connection, timeout=0.05)
        assert time.monotonic() - began < 0.5
    finally:
        released.set()
    assert done.wait(1)
    assert not connection.sent


def test_deadline_includes_headers(monkeypatch):
    connection = Connection()

    def stalled_headers():
        connection.closed.wait(2)
        raise TimeoutError("PRIVATE_RESPONSE")

    connection.getresponse = stalled_headers
    began = time.monotonic()
    with pytest.raises(EvidenceError, match="request_timeout") as error:
        dispatch(monkeypatch, connection, timeout=0.05)
    assert time.monotonic() - began < 0.5
    assert "PRIVATE_RESPONSE" not in str(error.value)


def test_cancelled_connection_cannot_reopen_before_sending_headers(monkeypatch):
    released, entered, finished = threading.Event(), threading.Event(), threading.Event()
    sent = []

    class Client(http.client.HTTPSConnection):
        connections = 0

        def connect(self):
            self.connections += 1
            self.sock = SimpleNamespace(
                settimeout=lambda seconds: None, shutdown=lambda how: None, close=lambda: None, sendall=sent.append
            )

        def request(self, *args, **kwargs):
            entered.set()
            try:
                assert released.wait(2)
                # Exercise HTTPConnection.send's automatic reconnection path.
                return super().request(*args, **kwargs)
            finally:
                finished.set()

        def getresponse(self):
            raise EvidenceError("transport")

    connection = Client("example.invalid")
    try:
        with pytest.raises(EvidenceError, match="request_timeout"):
            dispatch(monkeypatch, connection, timeout=0.1)
        assert entered.is_set()
    finally:
        released.set()
    assert finished.wait(1)
    assert connection.connections == 1
    assert sent == []


@pytest.mark.parametrize(
    "reply",
    [
        Reply(b"x" * 21),
        Reply(headers={"Content-Length": "21"}),
        Reply(headers={"Content-Encoding": "gzip"}),
        Reply(headers={"Content-Length": "invalid"}),
    ],
)
def test_reject_oversize_or_encoded_responses(monkeypatch, reply):
    connection = Connection()
    connection.response = reply
    with pytest.raises(EvidenceError, match="response_limit"):
        dispatch(monkeypatch, connection)
    assert connection.closed.is_set()


def test_exact_route_is_checked_before_connection(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network call")

    monkeypatch.setattr("cops.connectors.transport.http.client.HTTPSConnection", forbidden)
    with pytest.raises(EvidenceError, match="unsafe_destination"):
        HttpsTransport("example.invalid", "/read", "GET").send(
            Request("GET", "https://other.invalid/read"), {}, timeout=1, max_bytes=20
        )


@pytest.mark.parametrize(
    "framing, wire_body, expected",
    [
        (b"Content-Length: 2", b"{}", b"{}"),
        (b"Content-Length: 0", b"", b""),
        (b"Transfer-Encoding: chunked", b"2\r\n{}\r\n0\r\n\r\n", b"{}"),
    ],
)
def test_http_response_can_close_its_reader_at_end_of_body(monkeypatch, framing, wire_body, expected):
    raw = io.BytesIO(b"HTTP/1.1 200 OK\r\n" + framing + b"\r\n\r\n" + wire_body)
    raw._sock = SimpleNamespace(settimeout=lambda seconds: None)
    response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda mode: io.BufferedReader(raw)))
    response.begin()
    connection = Connection()
    connection.response = response
    assert dispatch(monkeypatch, connection).body == expected
    assert response.fp is None


def test_incomplete_fixed_length_body_is_not_accepted(monkeypatch):
    connection = Connection()
    connection.response = Reply(b"{}", {"Content-Length": "3"})
    with pytest.raises(EvidenceError, match="transport"):
        dispatch(monkeypatch, connection)
