"""Bounded RS256 verification against caller-supplied, pinned local JWKS evidence.

This verifier never discovers keys or follows token-controlled URLs. Other signing
algorithms require a separately registered verifier and are explicitly unsupported.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any


class JWTValidationError(ValueError):
    """The supplied token or trust configuration cannot establish identity."""


@dataclass(frozen=True)
class VerifiedJWT:
    issuer: str
    subject: str
    audience: str
    expires_at: float
    key_sha256: str


def _decode(value: str, limit: int = 12288) -> bytes:
    if not isinstance(value, str) or not value or len(value) > limit or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise JWTValidationError("invalid bounded base64url value")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise JWTValidationError("invalid base64url encoding") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise JWTValidationError("noncanonical base64url encoding")
    return decoded


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise JWTValidationError("duplicate JSON member")
        result[key] = value
    return result


def _object(value: str) -> dict[str, Any]:
    try:
        document = json.loads(_decode(value), object_pairs_hook=_pairs)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise JWTValidationError("invalid token JSON") from exc
    if not isinstance(document, dict) or len(document) > 64:
        raise JWTValidationError("expected bounded JSON object")
    return document


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JWTValidationError(f"{name} must be a NumericDate")
    try:
        number = float(value)
    except (ValueError, OverflowError) as exc:
        raise JWTValidationError(f"invalid {name}") from exc
    if not math.isfinite(number):
        raise JWTValidationError(f"invalid {name}")
    return number


def verify_jwt(
    token: str, *, jwks: dict[str, Any], issuer: str, audience: str,
    now: float | None = None, leeway: float = 0,
) -> VerifiedJWT:
    """Verify signature, key selection, issuer, audience, and temporal claims.

    Callers own the provenance and authorization of the supplied JWKS. A successful
    result establishes this local trust policy, not provider integration readiness.
    """
    if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
        raise JWTValidationError("expected bounded compact JWT")
    if not isinstance(issuer, str) or not issuer or not isinstance(audience, str) or not audience:
        raise JWTValidationError("issuer and audience must be pinned")
    clock = _number(time.time() if now is None else now, "clock")
    tolerance = _number(leeway, "leeway")
    if not 0 <= tolerance <= 60:
        raise JWTValidationError("leeway must be between zero and sixty seconds")
    header_part, claims_part, signature_part = token.split(".")
    header, claims = _object(header_part), _object(claims_part)
    if header.get("alg") != "RS256":
        raise JWTValidationError("only pinned RS256 signing is supported")
    if any(name in header for name in ("crit", "jku", "x5u", "jwk", "b64")):
        raise JWTValidationError("token-controlled key sources and extensions are forbidden")
    kid = header.get("kid")
    if not isinstance(kid, str) or not 0 < len(kid) <= 128:
        raise JWTValidationError("a bounded key identifier is required")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list) or not 0 < len(keys) <= 16 or not all(isinstance(k, dict) for k in keys):
        raise JWTValidationError("expected bounded local JWKS")
    matches = [key for key in keys if key.get("kid") == kid]
    if len(matches) != 1:
        raise JWTValidationError("key identifier must resolve uniquely")
    key = matches[0]
    if key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256" or key.get("use", "sig") != "sig":
        raise JWTValidationError("key is not an RS256 signing key")
    if "key_ops" in key and key["key_ops"] != ["verify"]:
        raise JWTValidationError("key operations must permit verification only")
    if any(name in key for name in ("d", "p", "q", "dp", "dq", "qi")):
        raise JWTValidationError("private key material is forbidden")
    try:
        modulus, exponent = _decode(key["n"], 700), _decode(key["e"], 8)
    except (KeyError, TypeError) as exc:
        raise JWTValidationError("invalid RSA public key") from exc
    n, e = int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")
    if not modulus or modulus[0] == 0 or not 2048 <= n.bit_length() <= 4096 or e != 65537:
        raise JWTValidationError("RSA key must have 2048-4096 bits and exponent 65537")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:
        raise NotImplementedError("RS256 verification requires the registered cryptography prerequisite") from exc
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            _decode(signature_part, 700), f"{header_part}.{claims_part}".encode("ascii"),
            padding.PKCS1v15(), hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise JWTValidationError("signature verification failed") from exc
    if claims.get("iss") != issuer:
        raise JWTValidationError("issuer mismatch")
    audiences = claims.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    if not isinstance(audiences, list) or not audiences or len(audiences) > 16 or not all(isinstance(a, str) for a in audiences) or audience not in audiences:
        raise JWTValidationError("audience mismatch")
    expiry = _number(claims.get("exp"), "exp")
    if clock >= expiry + tolerance:
        raise JWTValidationError("token expired")
    for name in ("nbf", "iat"):
        if name in claims and _number(claims[name], name) > clock + tolerance:
            raise JWTValidationError(f"{name} is in the future")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not 0 < len(subject) <= 256:
        raise JWTValidationError("subject is required")
    fingerprint = hashlib.sha256(json.dumps({"kty": "RSA", "n": key["n"], "e": key["e"]}, sort_keys=True).encode()).hexdigest()
    return VerifiedJWT(issuer, subject, audience, expiry, fingerprint)
