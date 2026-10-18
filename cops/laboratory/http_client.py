"""Bounded HTTP requests to literal loopback laboratory services."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_loopback(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Ignore proxies, refuse redirects, and cap responses at 64 KiB."""
    if any(ord(character) < 33 or ord(character) == 127 for character in url) or "\\" in url:
        raise ValueError("laboratory URL contains forbidden characters")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.port is None
        or not 1 <= parsed.port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("laboratory URL must be literal loopback HTTP with an explicit port")
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)  # noqa: S310
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=3)  # noqa: S310 -- URL validated before any network I/O.
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        payload = response.read(65537)
        if len(payload) > 65536:
            raise RuntimeError("laboratory response exceeded evidence budget")
        return response.status, dict(response.headers), payload
