"""Exercise real signatures and reject untrusted JWT key and claim inputs."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from cops.assessments.jwt import JWTValidationError, verify_jwt

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def signing_material() -> tuple[Any, dict[str, Any]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    n = encoded(numbers.n.to_bytes(256, "big"))
    return private, {"keys": [{"kty": "RSA", "kid": "ephemeral", "n": n, "e": "AQAB"}]}


def token(private: Any, *, claims: dict[str, Any] | None = None,
          header: dict[str, Any] | None = None, raw_claims: bytes | None = None) -> str:
    payload = {"iss": "lab", "aud": "service", "sub": "synthetic", "exp": 2000, **(claims or {})}
    head = {"alg": "RS256", "kid": "ephemeral", **(header or {})}
    message = encoded(json.dumps(head).encode()) + "." + encoded(raw_claims if raw_claims is not None else json.dumps(payload).encode())
    signature = private.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
    return message + "." + encoded(signature)


def verify(value: str, jwks: dict[str, Any], **kwargs: Any) -> Any:
    return verify_jwt(value, jwks=jwks, issuer="lab", audience="service", now=1000, **kwargs)


def test_verified_identity_has_key_provenance_and_no_token(signing_material: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_material
    signed = token(private, claims={"aud": ["other", "service"]})
    result = verify(signed, jwks)
    assert result.subject == "synthetic"
    assert len(result.key_sha256) == 64
    assert signed not in repr(result)


@pytest.mark.parametrize("claims", [
    {"exp": 1000}, {"exp": True}, {"exp": "2000"}, {"exp": float("nan")},
    {"exp": float("inf")}, {"iss": "other"}, {"aud": "other"}, {"aud": ["service", 1]},
    {"nbf": 1001}, {"iat": 1001}, {"sub": ""},
])
def test_invalid_identity_and_temporal_claims_are_rejected(signing_material: tuple[Any, dict[str, Any]], claims: dict[str, Any]) -> None:
    private, jwks = signing_material
    with pytest.raises(JWTValidationError):
        verify(token(private, claims=claims), jwks)


@pytest.mark.parametrize("header", [
    {"alg": "none"}, {"alg": "HS256"}, {"kid": "unknown"},
    {"jku": "https://example.invalid/keys"}, {"jwk": {}}, {"x5u": "https://example.invalid/cert"},
    {"crit": []}, {"b64": False},
])
def test_token_cannot_select_an_algorithm_or_external_trust(signing_material: tuple[Any, dict[str, Any]], header: dict[str, Any]) -> None:
    private, jwks = signing_material
    with pytest.raises(JWTValidationError):
        verify(token(private, header=header), jwks)


@pytest.mark.parametrize("change", [
    {"key_ops": ["sign"]}, {"use": "enc"}, {"alg": "RS512"}, {"d": "forbidden"},
    {"n": 123}, {"e": "Aw"}, {"n": "A"},
])
def test_invalid_or_private_jwks_cannot_verify(signing_material: tuple[Any, dict[str, Any]], change: dict[str, Any]) -> None:
    private, jwks = signing_material
    invalid = {"keys": [{**jwks["keys"][0], **change}]}
    with pytest.raises(JWTValidationError):
        verify(token(private), invalid)


def test_duplicate_key_identifiers_and_payload_members_are_rejected(signing_material: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_material
    with pytest.raises(JWTValidationError):
        verify(token(private), {"keys": jwks["keys"] * 2})
    with pytest.raises(JWTValidationError):
        verify(token(private, raw_claims=b'{"iss":"lab","iss":"other"}'), jwks)


def test_tampering_malformed_and_deep_json_fail_closed(signing_material: tuple[Any, dict[str, Any]]) -> None:
    private, jwks = signing_material
    signed = token(private)
    head, payload, signature = signed.split(".")
    for invalid in [head + "." + encoded(b'{"sub":"administrator"}') + "." + signature,
                    signed + "=", "A.A.A", "token", "a" * 16385,
                    token(private, raw_claims=b"[" * 1500 + b"]" * 1500)]:
        with pytest.raises(JWTValidationError):
            verify(invalid, jwks)
    assert payload not in repr(verify(signed, jwks))
