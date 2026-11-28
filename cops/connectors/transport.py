"""TLS-only fixed-route HTTP transport, without redirects or decompression."""

import http.client
import math
import socket
import ssl
import threading
import time

from cops.evidence import EvidenceError

from .adapters.microsoft import destination
from .interfaces import Response


class HttpsTransport:
    def __init__(self, origin, path, method):
        self.origin, self.path, self.method = origin, path, method

    def send(self, request, headers, *, timeout, max_bytes):
        parts = destination(request.url, self.origin, self.path)
        if request.method != self.method:
            raise EvidenceError("unsafe_destination")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 120
            or type(max_bytes) is not int
            or not 0 < max_bytes <= 16777216
        ):
            raise EvidenceError("invalid_limit")
        deadline = time.monotonic() + timeout
        done, cancelled = threading.Event(), threading.Event()
        outcome, active = {}, {}

        def cancel():
            cancelled.set()
            current_socket = active.get("socket")
            if current_socket is not None:
                try:
                    current_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection = active.get("connection")
            if connection is not None:
                connection.close()

        def remaining():
            value = deadline - time.monotonic()
            if cancelled.is_set() or value <= 0:
                raise EvidenceError("request_timeout")
            return value

        def exchange():
            try:
                outcome["response"] = self._exchange(request, headers, parts, max_bytes, remaining, active)
            except EvidenceError as error:
                outcome["error"] = error.code
            except TimeoutError:
                outcome["error"] = "request_timeout"
            except Exception:
                outcome["error"] = "transport"
            finally:
                connection = active.get("connection")
                if connection is not None:
                    connection.close()
                done.set()

        # A socket timeout alone does not bound DNS resolution or slow headers.
        # Cancellation prevents sending credentials after a delayed connect returns.
        # The daemon can outlive the caller while an OS resolver remains blocked.
        threading.Thread(target=exchange, daemon=True, name="cops-evidence-http").start()
        if not done.wait(max(0, deadline - time.monotonic())):
            cancel()
            raise EvidenceError("request_timeout")
        if "error" in outcome:
            raise EvidenceError(outcome["error"])
        return outcome["response"]

    def _exchange(self, request, headers, parts, max_bytes, remaining, active):
        connection = http.client.HTTPSConnection(self.origin, timeout=remaining(), context=ssl.create_default_context())
        # Closing during cancellation must not let request() reopen the socket.
        connection.auto_open = 0
        active["connection"] = connection
        try:
            connection.connect()
            connection.sock.settimeout(remaining())
            active["socket"] = connection.sock
            outgoing = dict(request.headers)
            outgoing.update(headers)
            outgoing["Accept-Encoding"] = "identity"
            target = parts.path + ("?" + parts.query if parts.query else "")
            remaining()
            connection.request(request.method, target, body=request.body, headers=outgoing)
            if connection.sock is not None:
                connection.sock.settimeout(remaining())
            response = connection.getresponse()
            remaining()
            if response.status != 200:
                # Provider error bodies are unnecessary for retry decisions.
                return Response(response.status, b"", response.getheader("Retry-After"))
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise EvidenceError("response_limit")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > max_bytes):
                raise EvidenceError("response_limit")
            body = bytearray()
            while response.fp is not None:
                # The response can retain its socket after Connection: close.
                active["socket"] = response.fp.raw._sock
                active["socket"].settimeout(remaining())
                chunk = response.read1(min(65536, max_bytes - len(body) + 1))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise EvidenceError("response_limit")
            if length is not None and len(body) != int(length):
                raise EvidenceError("transport")
            retry_after = response.getheader("Retry-After")
            return Response(response.status, bytes(body), retry_after)
        finally:
            connection.close()
