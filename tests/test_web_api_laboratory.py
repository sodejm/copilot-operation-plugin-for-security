"""Disposable loopback fixtures are bounded and own every resource they open."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import pytest

import cops.web_api.laboratory as laboratory_module
from cops.web_api.laboratory import WebApiAssessmentLaboratory

QUERY = "query Object($objectId: ID!) { object(id: $objectId) { id owner } }"


def exchange(lab, path, *, method="GET", document=None, identity="owner"):
    address = urlsplit(lab.base_url)
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=2)
    try:
        headers = {"Authorization": f"Bearer {identity}-token"} if identity != "anonymous" else {}
        body = json.dumps(document) if document is not None else None
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


@pytest.mark.parametrize("profile", ["vulnerable", "corrected"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_graphql_query_and_variables_select_object_and_preserve_role_boundaries(profile, method):
    with WebApiAssessmentLaboratory(profile) as lab:
        for identity in ("owner", "other", "anonymous", "owner"):
            document = {"query": QUERY, "variables": {"objectId": "owner-object"}}
            path = "/graphql"
            if method == "GET":
                path += "?" + urlencode({"query": QUERY, "variables": json.dumps(document["variables"])})
            status, result = exchange(
                lab, path, method=method, document=document if method == "POST" else None, identity=identity
            )
            allowed = identity == "owner" or (identity == "other" and profile == "vulnerable")
            assert status == 200
            assert (result["data"]["object"] is not None) == allowed
        status, result = exchange(
            lab, "/graphql", method="POST", document={"query": QUERY, "variables": {"objectId": "missing"}}
        )
        assert status == 200 and result["data"]["object"] is None
        assert lab.request_count == 5


@pytest.mark.parametrize(
    "document",
    [
        {"query": "mutation { deleteEverything }", "variables": {"objectId": "owner-object"}},
        {"query": QUERY, "variables": []},
        {"query": QUERY, "variables": {"objectId": "x" * 129}},
        {"variables": {"objectId": "owner-object"}},
    ],
)
def test_graphql_rejects_unsupported_or_unbounded_documents(document):
    with WebApiAssessmentLaboratory("corrected") as lab:
        assert exchange(lab, "/graphql", method="POST", document=document)[0] == 400


def test_large_post_rejected_before_body_and_ambiguous_get_rejected():
    with WebApiAssessmentLaboratory("corrected") as lab:
        address = urlsplit(lab.base_url)
        with socket.create_connection((address.hostname, address.port), timeout=2) as client:
            client.sendall(b"POST /graphql HTTP/1.0\r\nContent-Length: 65537\r\n\r\n")
            assert b" 400 " in client.recv(4096)
        assert exchange(lab, "/graphql?query=one&query=two&variables=%7B%7D")[0] == 400


@pytest.mark.parametrize("tls", [False, True])
def test_stop_closes_partial_requests_tls_handshakes_threads_and_listener(tls):
    prior_threads = set(threading.enumerate())
    lab = WebApiAssessmentLaboratory("corrected", tls=tls)
    with lab:
        address = urlsplit(lab.base_url)
        client = socket.create_connection((address.hostname, address.port), timeout=2)
        try:
            if not tls:
                client.sendall(b"GET /objects/owner-object HTTP/1.1\r\n")
            deadline = time.monotonic() + 2
            while lab.active_connection_count == 0 and time.monotonic() < deadline:
                time.sleep(0.005)
            assert lab.active_connection_count == 1
            context = lab.tls_context if tls else None
            if context is not None:
                assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
                assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        finally:
            lab.stop()
            client.close()
    assert lab.active_connection_count == 0
    assert not [thread for thread in set(threading.enumerate()) - prior_threads if thread.is_alive()]
    with pytest.raises(OSError):
        socket.create_connection((address.hostname, address.port), timeout=0.2)
    with pytest.raises(RuntimeError):
        _ = lab.base_url
    with pytest.raises(RuntimeError):
        _ = lab.tls_context


def test_context_exception_and_restart_release_listener_and_reset_state():
    lab = WebApiAssessmentLaboratory("corrected")
    with pytest.raises(RuntimeError, match="synthetic failure"):
        with lab:
            assert exchange(lab, "/objects/owner-object")[0] == 200
            raise RuntimeError("synthetic failure")
    with lab:
        assert lab.request_count == 0
        assert not lab.request_received.is_set()
        assert exchange(lab, "/rate-limited")[1] == {"attempt": 1}
    assert lab.active_connection_count == 0


def receive_exact(client, length):
    result = bytearray()
    while len(result) < length:
        chunk = client.recv(length - len(result))
        assert chunk, "laboratory closed before its bounded response"
        result.extend(chunk)
    return bytes(result)


def read_frame(client):
    first, length = receive_exact(client, 2)
    assert first & 0x80 and not length & 0x80
    if length == 126:
        length = int.from_bytes(receive_exact(client, 2), "big")
    assert length <= 256
    return first & 0x0F, receive_exact(client, length)


def upgrade(client, authority):
    client.sendall((
        "GET /socket HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nAuthorization: Bearer owner-token\r\n\r\n"
    ).encode())
    response = bytearray()
    while not response.endswith(b"\r\n\r\n"):
        assert len(response) < 4096
        response.extend(receive_exact(client, 1))
    assert response.startswith(b"HTTP/1.1 101 ")


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize(
    ("frame", "code"),
    [
        (b"\x81\xff" + (65537).to_bytes(8, "big"), 1009),
        (b"\x82\x80", 1002),
        (b"\x81\x81\0\0\0\0\xff", 1007),
    ],
)
def test_websocket_rejects_oversized_binary_and_invalid_text_without_waiting_for_payload(tls, frame, code):
    with WebApiAssessmentLaboratory("corrected", tls=tls) as lab:
        address = urlsplit(lab.base_url)
        with socket.create_connection((address.hostname, address.port), timeout=2) as raw:
            client = lab.tls_context.wrap_socket(raw, server_hostname=address.hostname) if tls else raw
            with client:
                upgrade(client, address.netloc)
                client.sendall(frame)
                assert read_frame(client) == (8, code.to_bytes(2, "big"))
                assert client.recv(1) == b""


@pytest.mark.parametrize("tls", [False, True])
def test_websocket_frame_count_limit_bounds_responses_and_closes_connection(tls):
    with WebApiAssessmentLaboratory("corrected", tls=tls) as lab:
        address = urlsplit(lab.base_url)
        with socket.create_connection((address.hostname, address.port), timeout=2) as raw:
            client = lab.tls_context.wrap_socket(raw, server_hostname=address.hostname) if tls else raw
            with client:
                upgrade(client, address.netloc)
                client.sendall((b"\x81\x8c\0\0\0\0owner-object") * 8)
                for _ in range(8):
                    opcode, payload = read_frame(client)
                    assert opcode == 1 and json.loads(payload)["owner"] == "owner"
                assert read_frame(client) == (8, (1008).to_bytes(2, "big"))
                assert client.recv(1) == b""


def test_disposable_tls_keys_are_private_and_removed_on_stop():
    with WebApiAssessmentLaboratory("corrected", tls=True) as lab:
        directory = Path(lab._tls_directory.name)
        keys = list(directory.glob("*.key.pem"))
        assert keys
        assert all(key.stat().st_mode & 0o777 == 0o600 for key in keys)
    assert not directory.exists()


def test_thread_start_failure_cleans_listener_and_tls_material(monkeypatch):
    lab = WebApiAssessmentLaboratory("corrected", tls=True)
    resources = {}

    def fail_start(thread):
        resources["directory"] = Path(lab._tls_directory.name)
        resources["address"] = lab._server.server_address
        raise RuntimeError("synthetic thread start failure")

    monkeypatch.setattr(laboratory_module.Thread, "start", fail_start)
    with pytest.raises(RuntimeError, match="synthetic thread start failure"):
        lab.start()
    assert not resources["directory"].exists()
    assert lab.active_connection_count == 0
    with pytest.raises(OSError):
        socket.create_connection(resources["address"], timeout=0.2)
