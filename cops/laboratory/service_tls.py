"""Ephemeral mutual-TLS acceptance cases for the disposable service laboratory."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TLSAcceptanceResult:
    """Observed outcomes from real TLS handshakes against an ephemeral server."""

    valid_client_status: int
    missing_client_rejected: bool
    untrusted_client_rejected: bool
    untrusted_server_rejected: bool
    unauthorized_client_status: int
    offline_verification: dict[str, str]
    service_stopped: bool
    server_address: str = "127.0.0.1"
    protocol: str = "TLS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid_client_status": self.valid_client_status,
            "missing_client_rejected": self.missing_client_rejected,
            "untrusted_client_rejected": self.untrusted_client_rejected,
            "untrusted_server_rejected": self.untrusted_server_rejected,
            "unauthorized_client_status": self.unauthorized_client_status,
            "offline_verification": self.offline_verification,
            "service_stopped": self.service_stopped,
            "server_address": self.server_address,
            "protocol": self.protocol,
        }


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/health":
            self.send_error(404)
            return
        peer = self.connection.getpeercert(binary_form=True)
        allowed = getattr(self.server, "authorized_client_sha256", frozenset())
        self.send_response(204 if peer and hashlib.sha256(peer).hexdigest() in allowed else 403)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _certificate_material(directory: Path, *, server_dns_names: tuple[str, ...] = ()) -> dict[str, Path]:
    if (
        type(server_dns_names) is not tuple
        or len(set(server_dns_names)) != len(server_dns_names)
        or any(
            type(name) is not str
            or not re.fullmatch(
                r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                name,
            )
            for name in server_dns_names
        )
    ):
        raise ValueError("invalid laboratory server DNS name")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as err:  # pragma: no cover - exercised by installations without the extra
        raise RuntimeError("the laboratory TLS acceptance requires the 'laboratory' optional dependency") from err

    now = datetime.now(UTC)

    def key() -> Any:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def write_key(name: str, private_key: Any) -> Path:
        path = directory / f"{name}.key.pem"
        path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        return path

    def write_cert(name: str, cert: Any) -> Path:
        path = directory / f"{name}.cert.pem"
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return path

    def ca(name: str) -> tuple[Any, Any, Path]:
        private_key = key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        return private_key, cert, write_cert(name, cert)

    def leaf(name: str, issuer_key: Any, issuer_cert: Any, usage: Any) -> tuple[Path, Path]:
        private_key = key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        )
        if usage == ExtendedKeyUsageOID.SERVER_AUTH:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                    + [x509.DNSName(hostname) for hostname in server_dns_names]
                ),
                critical=False,
            )
        else:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(f"{name}.example.invalid")]),
                critical=False,
            )
        cert = builder.sign(issuer_key, hashes.SHA256())
        return write_key(name, private_key), write_cert(name, cert)

    trusted_key, trusted_ca, trusted_ca_path = ca("trusted-ca")
    untrusted_key, untrusted_ca, untrusted_ca_path = ca("untrusted-ca")
    server_key, server_cert = leaf("server", trusted_key, trusted_ca, ExtendedKeyUsageOID.SERVER_AUTH)
    client_key, client_cert = leaf("client", trusted_key, trusted_ca, ExtendedKeyUsageOID.CLIENT_AUTH)
    unauthorized_key, unauthorized_cert = leaf(
        "unauthorized-client", trusted_key, trusted_ca, ExtendedKeyUsageOID.CLIENT_AUTH
    )
    bad_key, bad_cert = leaf("untrusted-client", untrusted_key, untrusted_ca, ExtendedKeyUsageOID.CLIENT_AUTH)
    return {
        "ca": trusted_ca_path,
        "untrusted_ca": untrusted_ca_path,
        "server_key": server_key,
        "server_cert": server_cert,
        "client_key": client_key,
        "client_cert": client_cert,
        "unauthorized_key": unauthorized_key,
        "unauthorized_cert": unauthorized_cert,
        "bad_key": bad_key,
        "bad_cert": bad_cert,
    }


def _request(url: str, context: ssl.SSLContext) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(url, timeout=3)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status


def _was_rejected(url: str, context: ssl.SSLContext) -> bool:
    try:
        _request(url, context)
    except (ssl.SSLError, urllib.error.URLError, ConnectionError):
        return True
    return False


def run_ephemeral_mtls_acceptance() -> TLSAcceptanceResult:
    """Compare local certificate verification with real TLS and client authorization."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    from cops.assessments.crypto_inputs import verify_artifact

    with tempfile.TemporaryDirectory(prefix="cops-service-tls-") as temporary:
        material = _certificate_material(Path(temporary))
        allowed = (
            x509.load_pem_x509_certificate(material["client_cert"].read_bytes()).fingerprint(hashes.SHA256()).hex()
        )
        evidence = {
            "purpose": "server",
            "leaf_pem": material["server_cert"].read_text(),
            "trust_anchors_pem": [material["ca"].read_text()],
            "hostname": "127.0.0.1",
        }
        client = {
            **evidence,
            "purpose": "client",
            "leaf_pem": material["client_cert"].read_text(),
            "authorized_client_sha256": [allowed],
        }
        cases = {
            "server": evidence,
            "wrong_hostname": {**evidence, "hostname": "other.example.invalid"},
            "untrusted_server": {**evidence, "trust_anchors_pem": [material["untrusted_ca"].read_text()]},
            "authorized_client": client,
            "unauthorized_client": {**client, "leaf_pem": material["unauthorized_cert"].read_text()},
        }
        offline = {
            name: verify_artifact("certificate_chain", content, as_of=datetime.now(UTC)).status
            for name, content in cases.items()
        }
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
        server.authorized_client_sha256 = frozenset({allowed})
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(str(material["server_cert"]), str(material["server_key"]))
        server_context.load_verify_locations(cafile=str(material["ca"]))
        server_context.verify_mode = ssl.CERT_REQUIRED
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, name="cops-mtls-server", daemon=True)
        thread.start()
        url = f"https://127.0.0.1:{server.server_port}/health"
        try:
            valid = ssl.create_default_context(cafile=str(material["ca"]))
            valid.minimum_version = ssl.TLSVersion.TLSv1_2
            valid.load_cert_chain(str(material["client_cert"]), str(material["client_key"]))
            missing = ssl.create_default_context(cafile=str(material["ca"]))
            missing.minimum_version = ssl.TLSVersion.TLSv1_2
            untrusted = ssl.create_default_context(cafile=str(material["ca"]))
            untrusted.minimum_version = ssl.TLSVersion.TLSv1_2
            untrusted.load_cert_chain(str(material["bad_cert"]), str(material["bad_key"]))
            wrong_server = ssl.create_default_context(cafile=str(material["untrusted_ca"]))
            wrong_server.load_cert_chain(str(material["client_cert"]), str(material["client_key"]))
            unauthorized = ssl.create_default_context(cafile=str(material["ca"]))
            unauthorized.load_cert_chain(str(material["unauthorized_cert"]), str(material["unauthorized_key"]))
            valid_status = _request(url, valid)
            missing_rejected = _was_rejected(url, missing)
            untrusted_rejected = _was_rejected(url, untrusted)
            server_rejected = _was_rejected(url, wrong_server)
            unauthorized_status = _request(url, unauthorized)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        return TLSAcceptanceResult(
            valid_client_status=valid_status,
            missing_client_rejected=missing_rejected,
            untrusted_client_rejected=untrusted_rejected,
            untrusted_server_rejected=server_rejected,
            unauthorized_client_status=unauthorized_status,
            offline_verification=offline,
            service_stopped=not thread.is_alive() and server.socket.fileno() == -1,
        )
