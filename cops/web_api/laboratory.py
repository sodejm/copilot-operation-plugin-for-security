"""Disposable loopback mini-apps; these fixtures do not qualify production workers."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread
from typing import Any
from urllib.parse import parse_qs, urlparse

_MAX_BODY = 65536
_MAX_FRAMES = 8
_MAX_CONNECTIONS = 16
_OBJECT_QUERY = re.compile(r"query(?:[A-Za-z_][A-Za-z0-9_]*)?\(\$objectId:ID!\)\{object\(id:\$objectId\)\{idowner\}\}")


class _LaboratoryServer(ThreadingHTTPServer):
    """Track accepted sockets, including incomplete TLS handshakes."""

    daemon_threads = False
    block_on_close = True

    def __init__(self, handler: type[BaseHTTPRequestHandler], context: ssl.SSLContext | None) -> None:
        self.context = context
        self.connections: set[socket.socket] = set()
        self.connection_lock = Lock()
        super().__init__(("127.0.0.1", 0), handler)

    def get_request(self) -> tuple[socket.socket, Any]:
        client, address = super().get_request()
        client.settimeout(1)
        with self.connection_lock:
            if len(self.connections) >= _MAX_CONNECTIONS:
                client.close()
                raise OSError("laboratory connection limit reached")
            self.connections.add(client)
        return client, address

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            if self.context is not None:
                with self.connection_lock:
                    wrapped = self.context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                    self.connections.discard(request)
                    self.connections.add(wrapped)
                    request = wrapped
                request.do_handshake()
            super().process_request_thread(request, client_address)
        except (OSError, ValueError):
            request.close()
        finally:
            with self.connection_lock:
                self.connections.discard(request)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Malformed traffic and disconnects are expected; never log raw inputs.
        del request, client_address

    def close_clients(self) -> None:
        with self.connection_lock:
            clients = list(self.connections)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()


class WebApiAssessmentLaboratory:
    """Run vulnerable/corrected REST, GraphQL and text WebSocket fixtures.

    Only 127.0.0.1 is bound. Synthetic bearer identities are owner, other and
    anonymous. GraphQL accepts one object query with an objectId variable;
    /socket accepts the text owner-object and returns a JSON object or error.
    TLS creates a fresh local CA and certificate, deleted at stop. tls_context
    trusts that disposable CA and retains certificate/hostname validation.
    request_delay_seconds delays application replies for deadline/cancel tests.
    Observations contain counts and synchronization events, never raw requests.
    """

    def __init__(self, profile: str, *, tls: bool = False, request_delay_seconds: float = 0) -> None:
        if profile not in {"vulnerable", "corrected"}:
            raise ValueError("profile must be 'vulnerable' or 'corrected'")
        if not math.isfinite(request_delay_seconds) or not 0 <= request_delay_seconds <= 30:
            raise ValueError("laboratory delay must be between zero and thirty seconds")
        self.profile = profile
        self._tls = tls
        self._delay = request_delay_seconds
        self._server: _LaboratoryServer | None = None
        self._thread: Thread | None = None
        self._tls_directory: TemporaryDirectory | None = None
        self._client_context: ssl.SSLContext | None = None
        self._stopping = Event()
        self.request_received = Event()
        self._lock = Lock()
        self._request_count = 0
        self._rate_attempts: dict[str, int] = {}

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("laboratory is not running")
        host, port = self._server.server_address[:2]
        return f"{'https' if self._tls else 'http'}://{host}:{port}"

    @property
    def websocket_url(self) -> str:
        return self.base_url.replace("http", "ws", 1) + "/socket"

    @property
    def tls_context(self) -> ssl.SSLContext:
        if self._server is None or self._client_context is None:
            raise RuntimeError("TLS laboratory is not running")
        return self._client_context

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    @property
    def active_connection_count(self) -> int:
        server = self._server
        if server is None:
            return 0
        with server.connection_lock:
            return len(server.connections)

    def reset(self) -> None:
        with self._lock:
            self._request_count = 0
            self._rate_attempts.clear()
            self.request_received.clear()

    def _server_context(self) -> ssl.SSLContext | None:
        if not self._tls:
            return None
        from cops.laboratory.service_tls import _certificate_material

        self._tls_directory = TemporaryDirectory(prefix="cops-web-api-tls-")
        material = _certificate_material(Path(self._tls_directory.name))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(material["server_cert"]), str(material["server_key"]))
        self._client_context = ssl.create_default_context(cafile=str(material["ca"]))
        self._client_context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def start(self) -> WebApiAssessmentLaboratory:
        if self._server is not None:
            return self
        laboratory = self
        self.reset()
        self._stopping.clear()

        class Handler(BaseHTTPRequestHandler):
            server_version = "COPSWebApiLab/1"

            def log_message(self, format: str, *args: object) -> None:
                del format, args

            def parse_request(self) -> bool:
                if not super().parse_request():
                    return False
                if len(self.path) > 8192 or sum(len(k) + len(v) + 4 for k, v in self.headers.items()) > 16384:
                    self.send_error(431)
                    return False
                if len(self.headers.get_all("Authorization", [])) > 1:
                    self.send_error(400)
                    return False
                return True

            def _identity(self) -> str:
                value = self.headers.get("Authorization", "")
                if value == "Bearer owner-token":
                    return "owner"
                if value == "Bearer other-token":
                    return "other"
                return "anonymous"

            def _object(self, object_id: str) -> tuple[int, dict[str, Any]]:
                identity = self._identity()
                if object_id != "owner-object":
                    return 404, {"error": "not found"}
                if identity == "anonymous":
                    return 401, {"error": "authentication required"}
                if identity == "other" and laboratory.profile == "corrected":
                    return 403, {"error": "object access denied"}
                return 200, {"id": object_id, "owner": "owner", "value": "evidence"}

            def _json(self, status: int, document: dict[str, Any], **headers: str) -> None:
                body = json.dumps(document, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers.items():
                    self.send_header(name.replace("_", "-"), value)
                self.end_headers()
                self.wfile.write(body)

            def _record(self) -> None:
                with laboratory._lock:
                    laboratory._request_count += 1
                laboratory.request_received.set()

            def _delay_reply(self) -> bool:
                return laboratory._stopping.wait(laboratory._delay)

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                self._record()
                parsed = urlparse(self.path)
                if parsed.path == "/socket":
                    self._websocket()
                    return
                if self._delay_reply():
                    return
                if parsed.path == "/objects/owner-object":
                    self._json(*self._object("owner-object"))
                elif parsed.path == "/graphql":
                    try:
                        parameters = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
                        if set(parameters) != {"query", "variables"} or any(len(v) != 1 for v in parameters.values()):
                            raise ValueError("ambiguous GraphQL parameters")
                        self._graphql(
                            {"query": parameters["query"][0], "variables": json.loads(parameters["variables"][0])}
                        )
                    except (ValueError, RecursionError):
                        self._json(400, {"errors": [{"message": "invalid GraphQL document"}]})
                elif parsed.path == "/rate-limited":
                    identity = self._identity()
                    with laboratory._lock:
                        attempt = laboratory._rate_attempts.get(identity, 0) + 1
                        laboratory._rate_attempts[identity] = attempt
                    if laboratory.profile == "corrected" and attempt > 2:
                        self._json(429, {"error": "rate limit exceeded"}, Retry_After="1")
                    else:
                        self._json(200, {"attempt": attempt})
                else:
                    self._json(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                self._record()
                if urlparse(self.path).path != "/graphql":
                    self._json(404, {"error": "not found"})
                    return
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1:
                    self._json(400, {"errors": [{"message": "one Content-Length is required"}]})
                    return
                try:
                    length = int(lengths[0])
                    if not 0 < length <= _MAX_BODY:
                        raise ValueError("body length outside laboratory limit")
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete body")
                    document = json.loads(body)
                except (ValueError, UnicodeDecodeError, TimeoutError, RecursionError):
                    self._json(400, {"errors": [{"message": "invalid JSON"}]})
                    return
                if not self._delay_reply():
                    self._graphql(document)

            def _graphql(self, document: Any) -> None:
                if not isinstance(document, dict) or not isinstance(document.get("variables"), dict):
                    self._json(400, {"errors": [{"message": "invalid GraphQL document"}]})
                    return
                query = document.get("query")
                object_id = document["variables"].get("objectId")
                if (
                    not isinstance(query, str)
                    or not _OBJECT_QUERY.fullmatch(re.sub(r"\s+", "", query))
                    or not isinstance(object_id, str)
                    or len(object_id) > 128
                ):
                    self._json(400, {"errors": [{"message": "unsupported object query"}]})
                    return
                status, result = self._object(object_id)
                if status == 200:
                    self._json(200, {"data": {"object": {"id": object_id, "owner": "owner"}}})
                else:
                    error: dict[str, Any] = {"message": result["error"]}
                    if status in {401, 403}:
                        error["extensions"] = {"code": "UNAUTHENTICATED" if status == 401 else "FORBIDDEN"}
                    self._json(200, {"data": {"object": None}, "errors": [error]})

            def _frame(self, opcode: int, payload: bytes) -> None:
                length = len(payload)
                size = bytes([length]) if length < 126 else b"\x7e" + length.to_bytes(2, "big")
                self.wfile.write(bytes([0x80 | opcode]) + size + payload)
                self.wfile.flush()

            def _read_exact(self, length: int) -> bytes:
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ConnectionError("incomplete laboratory frame")
                return data

            def _websocket(self) -> None:
                key = self.headers.get("Sec-WebSocket-Key", "")
                try:
                    if (
                        self.headers.get("Upgrade", "").lower() != "websocket"
                        or "upgrade" not in {value.strip().lower() for value in self.headers.get("Connection", "").split(",")}
                        or self.headers.get("Sec-WebSocket-Version") != "13"
                        or len(base64.b64decode(key, validate=True)) != 16
                    ):
                        raise ValueError("invalid handshake")
                except ValueError:
                    self._json(400, {"error": "invalid WebSocket handshake"})
                    return
                accept = hashlib.sha1(  # noqa: S324 - RFC 6455 handshake, not a security digest
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"), usedforsecurity=False
                ).digest()
                self.protocol_version = "HTTP/1.1"
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", base64.b64encode(accept).decode("ascii"))
                self.end_headers()
                for _ in range(_MAX_FRAMES):
                    first, second = self._read_exact(2)
                    if first not in {0x81, 0x88} or not second & 0x80:
                        self._frame(8, (1002).to_bytes(2, "big"))
                        return
                    length = second & 0x7F
                    if length == 126:
                        length = int.from_bytes(self._read_exact(2), "big")
                    elif length == 127:
                        length = int.from_bytes(self._read_exact(8), "big")
                    if length > _MAX_BODY or (first == 0x88 and length > 125):
                        self._frame(8, (1009).to_bytes(2, "big"))
                        return
                    mask = self._read_exact(4)
                    payload = bytes(value ^ mask[index % 4] for index, value in enumerate(self._read_exact(length)))
                    if first == 0x88:
                        self._frame(8, (1000).to_bytes(2, "big"))
                        return
                    try:
                        object_id = payload.decode("utf-8")
                    except UnicodeDecodeError:
                        self._frame(8, (1007).to_bytes(2, "big"))
                        return
                    if self._delay_reply():
                        return
                    _, result = self._object(object_id)
                    self._frame(1, json.dumps(result, sort_keys=True).encode("utf-8"))
                self._frame(8, (1008).to_bytes(2, "big"))

        try:
            self._server = _LaboratoryServer(Handler, self._server_context())
            self._thread = Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, name="cops-web-api-lab"
            )
            self._thread.start()
        except BaseException:
            self.stop()
            raise
        return self

    def stop(self) -> None:
        self._stopping.set()
        if self._server is not None:
            if self._thread is not None and self._thread.is_alive():
                self._server.shutdown()
            self._server.close_clients()
            self._server.server_close()  # Join handlers after shutting down their sockets.
        if self._thread is not None and self._thread.ident is not None:
            self._thread.join()
        self._server = None
        self._thread = None
        self._client_context = None
        if self._tls_directory is not None:
            self._tls_directory.cleanup()
            self._tls_directory = None

    def __enter__(self) -> WebApiAssessmentLaboratory:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.stop()
