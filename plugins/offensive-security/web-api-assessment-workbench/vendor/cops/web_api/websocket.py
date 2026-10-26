"""Bounded RFC 6455 text exchange on an already scope-checked, owned socket.

This module has no resolver, connector, approval client, redirects or cookie jar.
The replay mediator supplies the pinned socket and one absolute deadline.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import socket
import struct
from typing import Protocol
from urllib.parse import urlencode, urlparse, urlunparse

from .models import ReplayBudget, ReplayRequest, ReplayResponse, _valid_websocket_close_code
from .sanitization import authority

MAX_HANDSHAKE_BYTES = 16384
MAX_REQUEST_BYTES = 8192
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class WebSocketProtocolError(OSError):
    """Peer framing or handshake is outside the supported subset."""


class WebSocketBudgetError(WebSocketProtocolError):
    """Frame count, payload or aggregate encoded-byte limit would be exceeded."""


class Deadline(Protocol):
    def remaining(self) -> float: ...

    def pause(self, seconds: float) -> None: ...


def _frame_size(length: int, *, masked: bool) -> int:
    return length + (2 if length < 126 else 4 if length < 65536 else 10) + (4 if masked else 0)


def handshake_request(req: ReplayRequest, key: str) -> bytes:
    parsed = urlparse(req.url)
    query = parsed.query
    if req.query_parameters:
        query = "&".join(filter(None, (query, urlencode(req.query_parameters))))
    path = urlunparse(("", "", parsed.path or "/", parsed.params, query, ""))
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {authority(req.url)}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        *(f"{name}: {value}" for name, value in req.headers.items()),
        "",
        "",
    ]
    try:
        path.encode("ascii")
        authority(req.url).encode("ascii")
        content = "\r\n".join(lines).encode("latin-1")
    except UnicodeError:
        raise WebSocketProtocolError("WebSocket handshake is not HTTP encodable") from None
    if len(content) > MAX_REQUEST_BYTES:
        raise WebSocketProtocolError("WebSocket request handshake exceeds its byte limit")
    return content


def validate_request(req: ReplayRequest, budget: ReplayBudget) -> None:
    """Validate all known outbound work before approval or network effects."""
    parsed = urlparse(req.url)
    if (
        parsed.scheme not in {"ws", "wss"}
        or "#" in req.url
        or req.method.upper() != "GET"
        or req.body is not None
        or req.graphql_query is not None
    ):
        raise WebSocketProtocolError("unsupported WebSocket request")
    if any(
        name.lower().startswith("sec-websocket-") or name.lower() in {"content-length", "content-type"}
        for name in req.headers
    ):
        raise WebSocketProtocolError("transport-controlled WebSocket header")
    if not isinstance(req.query_parameters, dict) or any(
        type(key) is not str or type(value) is not str for key, value in req.query_parameters.items()
    ):
        raise WebSocketProtocolError("WebSocket query parameters must be text")
    if (
        len(req.url) > MAX_REQUEST_BYTES
        or sum(len(key) + len(value) + 4 for key, value in req.headers.items()) > MAX_REQUEST_BYTES
        or sum(len(key) + len(value) for key, value in req.query_parameters.items()) > MAX_REQUEST_BYTES
    ):
        raise WebSocketProtocolError("WebSocket request handshake exceeds its byte limit")
    validate_message_budget(req, budget)
    handshake_request(req, base64.b64encode(bytes(16)).decode("ascii"))


def validate_message_budget(req: ReplayRequest, budget: ReplayBudget) -> None:
    """Bound proposed payloads without claiming a legacy inventory can execute."""
    if not isinstance(req.websocket_messages, list) or any(type(item) is not str for item in req.websocket_messages):
        raise WebSocketProtocolError("WebSocket messages must be a list of UTF-8 text")
    if 2 * len(req.websocket_messages) + 2 > budget.max_websocket_frames:
        raise WebSocketBudgetError("WebSocket frame budget cannot complete the requested exchange")
    outbound = 10  # masked close(1000) plus minimum empty unmasked close reply.
    for message in req.websocket_messages:
        if len(message) > budget.max_websocket_message_bytes:
            raise WebSocketBudgetError("WebSocket message byte limit exceeded")
        try:
            length = len(message.encode("utf-8"))
        except UnicodeError:
            raise WebSocketProtocolError("WebSocket messages must be UTF-8 text") from None
        if length > budget.max_websocket_message_bytes:
            raise WebSocketBudgetError("WebSocket message byte limit exceeded")
        outbound += _frame_size(length, masked=True) + 2  # minimum peer text frame.
        if outbound > budget.max_websocket_bytes:
            raise WebSocketBudgetError("WebSocket encoded-byte budget is too small")
    if outbound > budget.max_websocket_bytes:
        raise WebSocketBudgetError("WebSocket encoded-byte budget is too small")


def _recv(sock: socket.socket, size: int, deadline: Deadline) -> bytes:
    data = bytearray()
    while len(data) < size:
        sock.settimeout(deadline.remaining())
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise WebSocketProtocolError("WebSocket peer closed without completing the exchange")
        data.extend(chunk)
    deadline.remaining()
    return bytes(data)


def _send(sock: socket.socket, content: bytes, deadline: Deadline) -> None:
    sock.settimeout(deadline.remaining())
    sock.sendall(content)
    deadline.remaining()


def _handshake(sock: socket.socket, req: ReplayRequest, deadline: Deadline) -> tuple[int, dict[str, str]]:
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    _send(sock, handshake_request(req, key), deadline)
    content = bytearray()
    while not content.endswith(b"\r\n\r\n"):
        if len(content) == MAX_HANDSHAKE_BYTES:
            raise WebSocketProtocolError("WebSocket response handshake exceeds its byte limit")
        content.extend(_recv(sock, 1, deadline))  # Never prefetch an unvalidated frame payload.
    lines = bytes(content[:-4]).split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.1 [1-5][0-9]{2}(?: [\x20-\x7e]*)?", lines[0]):
        raise WebSocketProtocolError("invalid WebSocket HTTP status line")
    status = int(lines[0].split(b" ")[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not _HEADER.fullmatch(name) or any(c < 32 and c != 9 or c == 127 for c in value):
            raise WebSocketProtocolError("invalid WebSocket response header")
        field = name.decode("ascii").lower()
        if field in headers:
            raise WebSocketProtocolError("duplicate WebSocket response header")
        headers[field] = value.decode("latin-1").strip(" \t")
    if status != 101:
        return status, {}  # No redirects, error bodies, cookies or arbitrary server metadata.
    expected = base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii"), usedforsecurity=False).digest()).decode()
    if (
        headers.get("upgrade", "").lower() != "websocket"
        or "upgrade" not in {token.strip().lower() for token in headers.get("connection", "").split(",")}
        or headers.get("sec-websocket-accept") != expected
        or "sec-websocket-extensions" in headers
        or "sec-websocket-protocol" in headers
        or "transfer-encoding" in headers
        or "content-length" in headers
    ):
        raise WebSocketProtocolError("unsupported or invalid WebSocket upgrade")
    # Retain canonical protocol fields, not arbitrary extra Connection tokens.
    return status, {"upgrade": "websocket", "connection": "Upgrade", "sec-websocket-accept": expected}


class _Frames:
    def __init__(self, sock: socket.socket, budget: ReplayBudget, deadline: Deadline) -> None:
        self.sock, self.budget, self.deadline = sock, budget, deadline
        self.metrics = {"frames_sent": 0, "frames_received": 0, "bytes_sent": 0, "bytes_received": 0}
        self.reserved_frames = 0
        self.reserved_bytes = 0

    def _reserve(self, size: int, *, frame: bool = False) -> None:
        if frame and self.reserved_frames >= self.budget.max_websocket_frames:
            raise WebSocketBudgetError("WebSocket frame limit exceeded")
        if self.reserved_bytes + size > self.budget.max_websocket_bytes:
            raise WebSocketBudgetError("WebSocket encoded-byte limit exceeded")
        self.reserved_frames += int(frame)
        self.reserved_bytes += size

    def send(self, opcode: int, payload: bytes) -> None:
        size = _frame_size(len(payload), masked=True)
        self._reserve(size, frame=True)
        mask = secrets.token_bytes(4)
        length = len(payload)
        head = bytes([0x80 | opcode, 0x80 | (length if length < 126 else 126 if length < 65536 else 127)])
        if length >= 126:
            head += struct.pack("!H" if length < 65536 else "!Q", length)
        encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        _send(self.sock, head + mask + encoded, self.deadline)
        self.metrics["frames_sent"] += 1
        self.metrics["bytes_sent"] += size

    def receive(self) -> tuple[int, bytes]:
        # Reserve the frame and base header before any read, including control floods.
        self._reserve(2, frame=True)
        first, second = _recv(self.sock, 2, self.deadline)
        self.metrics["bytes_received"] += 2
        opcode, length = first & 15, second & 127
        if first & 0xF0 != 0x80 or second & 0x80 or opcode not in {1, 8, 9, 10}:
            raise WebSocketProtocolError("unsupported WebSocket frame")
        if opcode >= 8 and length >= 126:
            raise WebSocketProtocolError("oversized WebSocket control frame")
        extra = 0
        if length in {126, 127}:
            extra = 2 if length == 126 else 8
            self._reserve(extra)
            encoded = _recv(self.sock, extra, self.deadline)
            self.metrics["bytes_received"] += extra
            actual = int.from_bytes(encoded, "big")
            if actual < (126 if extra == 2 else 65536) or actual >= 2**63:
                raise WebSocketProtocolError("noncanonical WebSocket frame length")
            length = actual
        if opcode == 1 and length > self.budget.max_websocket_message_bytes:
            raise WebSocketBudgetError("WebSocket message byte limit exceeded")
        self._reserve(length)
        payload = _recv(self.sock, length, self.deadline)
        self.metrics["bytes_received"] += length
        self.metrics["frames_received"] += 1
        return opcode, payload

    def next_data_or_close(self) -> tuple[int, bytes]:
        while True:
            opcode, payload = self.receive()
            if opcode == 9:
                self.send(10, payload)
            elif opcode != 10:
                return opcode, payload


def _close_code(payload: bytes) -> int | None:
    if not payload:
        return None
    if len(payload) == 1:
        raise WebSocketProtocolError("invalid WebSocket close payload")
    code = int.from_bytes(payload[:2], "big")
    if not _valid_websocket_close_code(code):
        raise WebSocketProtocolError("invalid WebSocket close code")
    payload[2:].decode("utf-8")  # Validate; never retain peer-controlled close reasons.
    return code


def exchange(sock: socket.socket, req: ReplayRequest, budget: ReplayBudget, deadline: Deadline) -> ReplayResponse:
    """Return completed or partial evidence. Caller always closes the owned socket."""
    frames = _Frames(sock, budget, deadline)
    replies: list[str] = []
    status, headers = 0, {}
    error = None
    try:
        status, headers = _handshake(sock, req, deadline)
        if status != 101:
            raise WebSocketProtocolError("WebSocket handshake rejected")
        for index, message in enumerate(req.websocket_messages):
            if index and budget.rate_limit_rps:
                deadline.pause(1.0 / budget.rate_limit_rps)
            frames.send(1, message.encode("utf-8"))
            opcode, payload = frames.next_data_or_close()
            if opcode == 8:
                _close_code(payload)
                raise WebSocketProtocolError("WebSocket closed before all replies")
            replies.append(payload.decode("utf-8"))
        frames.send(8, struct.pack("!H", 1000))
        opcode, payload = frames.next_data_or_close()
        if opcode != 8:
            raise WebSocketProtocolError("unexpected WebSocket data during close")
        code = _close_code(payload)
        if code is not None:
            frames.metrics["close_code"] = code
        if code not in {None, 1000}:
            raise WebSocketProtocolError("WebSocket close did not complete normally")
    except (OSError, UnicodeError) as failure:
        error = type(failure).__name__
    return ReplayResponse(
        request_id=req.request_id,
        status_code=status,
        headers=headers,
        final_url=req.url,
        websocket_replies=replies,
        error_message=error,
        replay_success=error is None,
        websocket_metrics=frames.metrics,
    )
