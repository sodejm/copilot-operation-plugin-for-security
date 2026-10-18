"""Disposable loopback API services for authorization and rate-limit acceptance."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlparse


class WebApiAssessmentLaboratory:
    """Run deliberately vulnerable or corrected REST and GraphQL mini-apps."""

    def __init__(self, profile: str) -> None:
        if profile not in {"vulnerable", "corrected"}:
            raise ValueError("profile must be 'vulnerable' or 'corrected'")
        self.profile = profile
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None
        self._lock = Lock()
        self._request_count = 0
        self._rate_attempts: dict[str, int] = {}

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("laboratory is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    def reset(self) -> None:
        with self._lock:
            self._request_count = 0
            self._rate_attempts.clear()

    def start(self) -> WebApiAssessmentLaboratory:
        if self._server is not None:
            return self
        laboratory = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "COPSWebApiLab/1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(3)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

            def _identity(self) -> str:
                value = self.headers.get("Authorization", "")
                if value == "Bearer owner-token":
                    return "owner"
                if value == "Bearer other-token":
                    return "other"
                return "anonymous"

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

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                self._record()
                path = urlparse(self.path).path
                identity = self._identity()
                if path == "/objects/owner-object":
                    if identity == "anonymous":
                        self._json(401, {"error": "authentication required"})
                    elif identity == "other" and laboratory.profile == "corrected":
                        self._json(403, {"error": "object access denied"})
                    else:
                        self._json(200, {"id": "owner-object", "owner": "owner", "value": "evidence"})
                    return
                if path == "/rate-limited":
                    with laboratory._lock:
                        attempt = laboratory._rate_attempts.get(identity, 0) + 1
                        laboratory._rate_attempts[identity] = attempt
                    if laboratory.profile == "corrected" and attempt > 2:
                        self._json(429, {"error": "rate limit exceeded"}, Retry_After="1")
                    else:
                        self._json(200, {"attempt": attempt})
                    return
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
                    if not 0 < length <= 65536:
                        raise ValueError("body length outside laboratory limit")
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete body")
                    document = json.loads(body)
                    if not isinstance(document, dict) or not isinstance(document.get("variables"), dict):
                        raise ValueError("expected variables object")
                    object_id = document["variables"].get("objectId")
                    if not isinstance(object_id, str) or len(object_id) > 128:
                        raise ValueError("expected bounded objectId")
                except (ValueError, UnicodeDecodeError, TimeoutError, RecursionError):
                    self._json(400, {"errors": [{"message": "invalid JSON"}]})
                    return
                identity = self._identity()
                if object_id != "owner-object":
                    self._json(200, {"data": {"object": None}, "errors": [{"message": "not found"}]})
                elif identity == "anonymous":
                    self._json(
                        200,
                        {
                            "data": {"object": None},
                            "errors": [
                                {"message": "authentication required", "extensions": {"code": "UNAUTHENTICATED"}}
                            ],
                        },
                    )
                elif identity == "other" and laboratory.profile == "corrected":
                    self._json(
                        200,
                        {
                            "data": {"object": None},
                            "errors": [{"message": "object access denied", "extensions": {"code": "FORBIDDEN"}}],
                        },
                    )
                else:
                    self._json(200, {"data": {"object": {"id": object_id, "owner": "owner"}}})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._server.serve_forever, name="cops-web-api-lab", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None

    def __enter__(self) -> WebApiAssessmentLaboratory:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.stop()
