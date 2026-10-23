"""Actual loopback API authorization and JWT checks inside the isolated lab."""

from __future__ import annotations

import base64
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cops.assessments.crypto_inputs import verify_artifact
from cops.assessments.jwt import JWTValidationError, verify_jwt
from cops.web_api.assessment import AuthorizationCase, assess_object_authorization, assess_rate_limit
from cops.web_api.laboratory import WebApiAssessmentLaboratory
from cops.web_api.models import ReplayResponse

from .http_client import request_loopback


def _request(url: str, request_id: str, token: str = "", body: bytes | None = None) -> ReplayResponse:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    status, response_headers, payload = request_loopback(
        url, method="POST" if body is not None else "GET", data=body, headers=headers
    )
    return ReplayResponse(request_id, status, response_headers, payload.decode("utf-8"))


def run_api_acceptance(profile: str) -> dict[str, Any]:
    """Exercise six role/object requests and four throttling attempts over TCP."""
    cases: list[AuthorizationCase] = []
    laboratory = WebApiAssessmentLaboratory(profile)
    with laboratory:
        base = laboratory.base_url
        for actor in ("owner", "other", "anonymous"):
            token = f"{actor}-token" if actor != "anonymous" else ""
            for surface in ("rest", "graphql"):
                request_id = f"{surface}-{actor}"
                body = (
                    json.dumps(
                        {
                            "query": "query($objectId: ID!) { object(id: $objectId) { id owner } }",
                            "variables": {"objectId": "owner-object"},
                        }
                    ).encode()
                    if surface == "graphql"
                    else None
                )
                response = _request(base + ("/graphql" if body else "/objects/owner-object"), request_id, token, body)
                cases.append(AuthorizationCase(request_id, surface, actor, "owner-object", actor == "owner", response))
        rate = [_request(base + "/rate-limited", f"rate-{index}", "owner-token") for index in range(4)]
        observed = laboratory.request_count
        laboratory.reset()
        reset_verified = laboratory.request_count == 0
    try:
        _ = laboratory.base_url
        stopped = False
    except RuntimeError:
        stopped = True
    return {
        "schema_version": "cops.api-laboratory-acceptance/v1",
        "profile": profile,
        "authorization_verdict": assess_object_authorization(cases).verdict.value,
        "rate_limit_verdict": assess_rate_limit(rate).verdict.value,
        "role_statuses": {case.request_id: case.response.status_code for case in cases},
        "rate_statuses": [response.status_code for response in rate],
        "actual_requests": observed,
        "reset_verified": reset_verified,
        "service_stopped": stopped,
        "scope": "loopback mini-app with synthetic identities; provider integration unverified",
    }


def run_jwt_acceptance() -> dict[str, Any]:
    """Verify real HTTP authentication with fresh RSA keys and hostile tokens."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    def encoded(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    def integer(value: int) -> str:
        return encoded(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "ephemeral",
                "alg": "RS256",
                "use": "sig",
                "n": integer(numbers.n),
                "e": integer(numbers.e),
            }
        ]
    }
    now = 1800000000.0
    claims = {"iss": "cops-lab", "aud": "resource", "sub": "synthetic-user", "exp": now + 60, "iat": now - 1}

    def signed(changes: dict[str, Any] | None = None, header_changes: dict[str, Any] | None = None) -> str:
        header = {"alg": "RS256", "kid": "ephemeral", **(header_changes or {})}
        content = {**claims, **(changes or {})}
        message = encoded(json.dumps(header).encode()) + "." + encoded(json.dumps(content).encode())
        signature = private.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
        return message + "." + encoded(signature)

    valid = signed()
    head, payload, signature = valid.split(".")
    tampered = head + "." + encoded(json.dumps({**claims, "sub": "administrator"}).encode()) + "." + signature
    tokens = {
        "valid": valid,
        "expired": signed({"exp": now - 1}),
        "wrong_issuer": signed({"iss": "other"}),
        "wrong_audience": signed({"aud": "other"}),
        "future_nbf": signed({"nbf": now + 60}),
        "unknown_key": signed(header_changes={"kid": "unknown"}),
        "unsigned": signed(header_changes={"alg": "none"}),
        "algorithm_confusion": signed(header_changes={"alg": "HS256"}),
        "tampered": tampered,
    }
    observed: dict[str, int] = {}
    offline = {
        name: verify_artifact(
            "jwt_verification",
            {"token": token, "jwks": jwks, "issuer": "cops-lab", "audience": "resource"},
            as_of=datetime.fromtimestamp(now, UTC),
        ).status
        for name, token in tokens.items()
    }

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            authorization = self.headers.get("Authorization", "")
            try:
                if self.path != "/identity" or not authorization.startswith("Bearer "):
                    raise JWTValidationError("identity unavailable")
                verify_jwt(authorization[7:], jwks=jwks, issuer="cops-lab", audience="resource", now=now)
                status = 204
            except JWTValidationError:
                status = 401
            self.send_response(status)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for name, token in tokens.items():
            observed[name] = _request(f"http://127.0.0.1:{server.server_port}/identity", name, token).status_code
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    return {
        "schema_version": "cops.jwt-laboratory-acceptance/v1",
        "algorithm": "RS256",
        "statuses": observed,
        "actual_requests": len(observed),
        "service_stopped": not thread.is_alive(),
        "ephemeral_keys": True,
        "external_key_discovery": False,
        "offline_verification": offline,
    }
