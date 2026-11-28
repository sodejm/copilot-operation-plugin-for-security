"""Laboratory HTTP traffic stays bounded and cannot escape through redirects."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cops.laboratory.http_client import request_loopback


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/hosts",
        "https://127.0.0.1:1234/",
        "http://localhost:1234/",
        "http://192.0.2.1:1234/",
        "http://127.0.0.1/",
        "http://127.0.0.1:0/",
        "http://user@127.0.0.1:1234/",
        "http://127.0.0.1:1234/#fragment",
        "http://127.0.0.1:1234/\n",
        "http://127.0.0.1:1234/\\path",
        "http://127.0.0.1:99999/",
        "http://[::1/",
    ],
)
def test_invalid_destination_rejected_before_io(monkeypatch, url):
    def unexpected_network(*_args, **_kwargs):
        pytest.fail("invalid laboratory URL reached the network")

    monkeypatch.setattr("urllib.request.build_opener", unexpected_network)
    with pytest.raises(ValueError):
        request_loopback(url)


def test_real_http_refuses_redirects_proxies_and_oversized_responses(monkeypatch):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/forbidden")
                body = b"redirect refused"
            else:
                self.send_response(401 if self.path == "/denied" else 200)
                body = b"x" * 65537 if self.path == "/large" else b"{}"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    try:
        assert request_loopback(base + "/ok")[0] == 200
        assert request_loopback(base + "/redirect")[0] == 302
        assert request_loopback(base + "/denied")[0] == 401
        with pytest.raises(RuntimeError, match="evidence budget"):
            request_loopback(base + "/large")
        assert paths == ["/ok", "/redirect", "/denied", "/large"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert not thread.is_alive()
