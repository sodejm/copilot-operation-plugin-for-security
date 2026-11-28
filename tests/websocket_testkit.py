"""Independent disposable RFC 6455 peer for real-socket acceptance, never isolation."""

from __future__ import annotations

import base64
import hashlib
import socket
import socketserver
import ssl
import struct
import threading


def server_frame(payload: bytes, opcode: int = 1, *, first: int | None = None) -> bytes:
    length = len(payload)
    prefix = bytes(
        [first if first is not None else 0x80 | opcode, length if length < 126 else 126 if length < 65536 else 127]
    )
    if length >= 126:
        prefix += struct.pack("!H" if length < 65536 else "!Q", length)
    return prefix + payload


class WebSocketTestServer:
    def __init__(self, *, mode="echo", profile="corrected", tls_context: ssl.SSLContext | None = None):
        self.mode, self.profile = mode, profile
        self.handshakes = []
        self.messages = []
        self.client_frames = []
        self.connected = threading.Event()
        self.closed = threading.Event()
        self.message_received = threading.Event()
        self.active = set()
        self.lock = threading.Lock()
        lab = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                with lab.lock:
                    lab.active.add(self.request)
                try:
                    self.exchange()
                except (OSError, EOFError):
                    pass
                finally:
                    with lab.lock:
                        lab.active.discard(self.request)
                    lab.closed.set()

            def exact(self, length):
                data = self.rfile.read(length)
                if len(data) != length:
                    raise EOFError
                return data

            def client_frame(self):
                first, second = self.exact(2)
                assert first & 0x80 and second & 0x80, "client must send FIN and masking"
                length = second & 127
                if length in {126, 127}:
                    length = int.from_bytes(self.exact(2 if length == 126 else 8), "big")
                assert length <= 65536, "fixture only accepts bounded client frames"
                mask = self.exact(4)
                raw = self.exact(length)
                payload = bytes(item ^ mask[i % 4] for i, item in enumerate(raw))
                lab.client_frames.append((first & 15, payload, mask))
                return first & 15, payload

            def exchange(self):
                if lab.mode == "tls-stall":
                    self.request.recv(4096)
                    lab.connected.set()
                    while self.request.recv(4096):
                        pass
                    return
                start = self.rfile.readline(8193)
                if not start:
                    return
                headers = {}
                while True:
                    line = self.rfile.readline(8193)
                    if line == b"\r\n":
                        break
                    if not line:
                        return
                    key, value = line.decode("latin-1").split(":", 1)
                    headers[key.lower()] = value.strip()
                lab.handshakes.append((start, headers))
                lab.connected.set()
                if lab.mode == "handshake-stall":
                    self.rfile.read(1)
                    return
                if lab.mode == "redirect":
                    self.wfile.write(b"HTTP/1.1 302 Found\r\nLocation: ws://unapproved.test/\r\n\r\n")
                    return
                if lab.mode == "large-handshake":
                    self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\nX-Fill: " + b"x" * 16384 + b"\r\n\r\n")
                    return
                key = headers["sec-websocket-key"]
                digest = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(), usedforsecurity=False)
                accept = base64.b64encode(digest.digest()).decode()
                if lab.mode == "bad-accept":
                    accept = "invalid"
                extra = {
                    "extension": "Sec-WebSocket-Extensions: permessage-deflate\r\n",
                    "subprotocol": "Sec-WebSocket-Protocol: unauthorized\r\n",
                    "duplicate": f"Sec-WebSocket-Accept: {accept}\r\n",
                }.get(lab.mode, "")
                self.wfile.write(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
                        f"X-Untrusted: server-private-canary\r\n{extra}\r\n"
                    ).encode()
                )
                while True:
                    opcode, payload = self.client_frame()
                    if opcode == 8:
                        reply = {
                            "bad-close": b"x",
                            "invalid-close-code": b"\x03\xed",
                            "invalid-close-reason": b"\x03\xe8\xff",
                            "abnormal-close": b"\x03\xf3",
                        }.get(lab.mode, payload)
                        self.wfile.write(server_frame(reply, 8))
                        return
                    if opcode == 10:
                        continue
                    assert opcode == 1
                    text = payload.decode("utf-8")
                    lab.messages.append((headers.get("authorization"), text))
                    lab.message_received.set()
                    raw = {
                        "binary": server_frame(b"binary", 2),
                        "fragment": server_frame(b"fragment", first=1),
                        "rsv": server_frame(b"compressed", first=0xC1),
                        "masked-server": b"\x81\x81\x00\x00\x00\x00x",
                        "utf8": server_frame(b"\xff"),
                        "huge-length": b"\x81\x7f" + struct.pack("!Q", 2**40),
                        "noncanonical": b"\x81\x7e\x00\x01x",
                        "oversized-ping": b"\x89\x7e\x00\x7e",
                        "early-close": server_frame(b"\x03\xe8", 8),
                        "flood": server_frame(b"", 9) * 30,
                        "extra-data": server_frame(b"one") + server_frame(b"unexpected"),
                    }.get(lab.mode)
                    if raw is not None:
                        self.wfile.write(raw)
                        return
                    if lab.mode == "stall":
                        self.rfile.read(1)  # Ends when client timeout/cancellation closes its socket.
                        return
                    if lab.mode == "partial-frame":
                        self.wfile.write(b"\x81\x7e\x01\x00x")
                        self.rfile.read(1)
                        return
                    if lab.mode == "ping":
                        self.wfile.write(server_frame(b"control-canary", 9) + server_frame(b"unsolicited", 10))
                    if lab.mode == "authorization":
                        actor = headers.get("authorization")
                        allowed = actor == "Bearer owner-token" or (
                            actor == "Bearer other-token" and lab.profile == "vulnerable"
                        )
                        reply = ("allow:" if allowed else "deny:") + text
                    else:
                        reply = text if lab.mode == "identity" else "echo:" + text
                    self.wfile.write(server_frame(reply.encode()))

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        if tls_context:
            self.server.socket = tls_context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"{'wss' if tls_context else 'ws'}://127.0.0.1:{self.server.server_address[1]}/socket"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        with self.lock:
            sockets = tuple(self.active)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.server.server_close()
        self.thread.join(timeout=1)
        assert not self.thread.is_alive() and not self.active
