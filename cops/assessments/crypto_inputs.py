"""Bounded offline cryptographic verification with explicit local trust inputs.

No keys, issuers, revocation data, or intermediates are discovered over the network.
Outcomes describe this verifier and supplied policy, never a remote service.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from cops.adapters.artifacts import artifact_adapter
from cops.assessments.jwt import JWTValidationError, _decode, verify_jwt

ADAPTER_ID = "cryptographic-verification/v1"
KINDS = frozenset({"certificate_chain", "jwt_verification"})
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)


@dataclass(frozen=True)
class VerificationResult:
    status: str
    code: str
    fingerprints: tuple[str, ...] = ()
    adapter_id: str = ADAPTER_ID

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "fingerprints": list(self.fingerprints)}


def _certificate(content: dict[str, Any], as_of: datetime) -> VerificationResult:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

    def certificate(pem: Any) -> Any:
        if not isinstance(pem, str) or len(pem) > 8192 or not _PEM.fullmatch(pem):
            raise ValueError("invalid bounded certificate")
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            if not 2048 <= key.key_size <= 4096 or key.public_numbers().e != 65537:
                raise ValueError("unsupported RSA key")
        elif not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name not in {"secp256r1", "secp384r1"}:
            raise ValueError("unsupported certificate key")
        return cert

    purpose = content.get("purpose")
    intermediates, anchors = content.get("intermediates_pem", []), content.get("trust_anchors_pem")
    if (
        purpose not in {"server", "client"}
        or not isinstance(intermediates, list)
        or len(intermediates) > 6
        or not isinstance(anchors, list)
        or not 0 < len(anchors) <= 8
    ):
        return VerificationResult("unknown", "certificate_policy_missing")
    if purpose == "client":
        allowed = content.get("authorized_client_sha256")
        if (
            not isinstance(allowed, list)
            or len(allowed) > 32
            or any(not isinstance(item, str) or not _FINGERPRINT.fullmatch(item) for item in allowed)
        ):
            return VerificationResult("unknown", "client_authorization_missing")
    else:
        hostname = content.get("hostname")
        if not isinstance(hostname, str) or len(hostname) > 253 or "%" in hostname:
            return VerificationResult("unknown", "hostname_missing")
        try:
            subject = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            if not _HOSTNAME.fullmatch(hostname):
                return VerificationResult("unknown", "hostname_invalid")
            subject = x509.DNSName(hostname)
    leaf = certificate(content.get("leaf_pem"))
    chain = [certificate(pem) for pem in intermediates]
    roots = [certificate(pem) for pem in anchors]
    policy = PolicyBuilder().store(Store(roots)).time(as_of).max_chain_depth(6)
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    try:
        if purpose == "server":
            policy.build_server_verifier(subject).verify(leaf, chain)
        else:
            policy.build_client_verifier().verify(leaf, chain)
    except VerificationError:
        return VerificationResult("rejected", "certificate_rejected", (fingerprint,))
    if purpose == "client" and fingerprint not in allowed:
        return VerificationResult("rejected", "client_not_authorized", (fingerprint,))
    return VerificationResult("accepted", "certificate_verified", (fingerprint,))


def _jwt(content: dict[str, Any], as_of: datetime) -> VerificationResult:
    token, jwks = content.get("token"), content.get("jwks")
    issuer, audience = content.get("issuer"), content.get("audience")
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 16384
        or any(not isinstance(value, str) or not 0 < len(value) <= 2048 for value in (issuer, audience))
        or not isinstance(jwks, dict)
    ):
        return VerificationResult("unknown", "jwt_policy_missing")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not 0 < len(keys) <= 16:
        return VerificationResult("unknown", "jwt_policy_missing")
    # Validate the local trust policy before attributing rejection to a token.
    seen: set[str] = set()
    try:
        for key in keys:
            if (
                not isinstance(key, dict)
                or key.get("kty") != "RSA"
                or key.get("alg", "RS256") != "RS256"
                or key.get("use", "sig") != "sig"
                or key.get("key_ops", ["verify"]) != ["verify"]
                or any(name in key for name in ("d", "p", "q", "dp", "dq", "qi"))
            ):
                raise ValueError("unsupported trust policy")
            kid = key.get("kid")
            if not isinstance(kid, str) or not 0 < len(kid) <= 128 or kid in seen:
                raise ValueError("ambiguous key")
            seen.add(kid)
            modulus, exponent = _decode(key.get("n"), 700), _decode(key.get("e"), 8)
            if (
                modulus[0] == 0
                or not 2048 <= int.from_bytes(modulus, "big").bit_length() <= 4096
                or int.from_bytes(exponent, "big") != 65537
            ):
                raise ValueError("unsupported key")
    except (ValueError, TypeError):
        return VerificationResult("unknown", "jwt_policy_invalid")
    try:
        verified = verify_jwt(token, jwks=jwks, issuer=issuer, audience=audience, now=as_of.timestamp())
    except JWTValidationError:
        return VerificationResult("rejected", "jwt_rejected")
    return VerificationResult("accepted", "jwt_verified", (verified.key_sha256,))


def verify_artifact(kind: str, content: Any, *, as_of: datetime) -> VerificationResult:
    """Return content-free accepted, rejected, or unknown outcomes within fixed limits."""
    if kind not in KINDS:
        return VerificationResult("unknown", "unsupported_format")
    if not isinstance(as_of, datetime) or as_of.tzinfo is None or as_of.utcoffset() is None:
        return VerificationResult("unknown", "assessment_time_missing")
    adapter = artifact_adapter(ADAPTER_ID)
    try:
        if not isinstance(content, dict) or len(json.dumps(content, allow_nan=False).encode()) > adapter.max_bytes:
            return VerificationResult("unknown", "input_limit")
    except (ValueError, TypeError, RecursionError):
        return VerificationResult("unknown", "invalid_input")
    try:
        if version("cryptography") != "50.0.2":
            return VerificationResult("unknown", "prerequisite_unavailable")
        from cryptography.exceptions import UnsupportedAlgorithm
    except (PackageNotFoundError, ImportError):
        return VerificationResult("unknown", "prerequisite_unavailable")
    try:
        return _certificate(content, as_of) if kind == "certificate_chain" else _jwt(content, as_of)
    except (ImportError, NotImplementedError):
        return VerificationResult("unknown", "prerequisite_unavailable")
    except (ValueError, TypeError, OverflowError, UnsupportedAlgorithm):
        return VerificationResult("unknown", "invalid_or_unsupported_input")
