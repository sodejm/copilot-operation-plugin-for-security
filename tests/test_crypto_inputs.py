"""Cryptographic outcomes require real signatures and explicit local trust."""
from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from cops.assessments.artifacts import assess
from cops.assessments.crypto_inputs import verify_artifact
from cops.evidence.canonical import utc_now

pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cops.laboratory.service_tls import _certificate_material


@pytest.fixture(scope="module")
def material(tmp_path_factory):
    paths = _certificate_material(tmp_path_factory.mktemp("crypto"))
    return {name: path.read_text() for name, path in paths.items() if "key" not in name}


def server(material):
    return {"purpose": "server", "leaf_pem": material["server_cert"],
            "intermediates_pem": [], "trust_anchors_pem": [material["ca"]], "hostname": "127.0.0.1"}


def check(content, kind="certificate_chain", now=None):
    return verify_artifact(kind, content, as_of=now or datetime.now(UTC))


def test_certificate_correction_and_untrusted_or_expired_chains(material):
    content = server(material)
    assert check(content).status == "accepted"
    for changes in ({"hostname": "wrong.example.invalid"}, {"trust_anchors_pem": [material["untrusted_ca"]]},
                    {"leaf_pem": material["client_cert"]}):
        assert check({**content, **changes}).status == "rejected"
    assert check(content, now=datetime.now(UTC) + timedelta(days=2)).status == "rejected"
    assert check(content).status == "accepted"


def test_client_identity_is_authorized_separately_from_chain(material):
    fingerprint = x509.load_pem_x509_certificate(material["client_cert"].encode()).fingerprint(hashes.SHA256()).hex()
    content = {**server(material), "purpose": "client", "leaf_pem": material["client_cert"],
               "authorized_client_sha256": [fingerprint]}
    assert check(content).status == "accepted"
    assert check({**content, "authorized_client_sha256": ["0" * 64]}).code == "client_not_authorized"
    del content["authorized_client_sha256"]
    assert check(content).status == "unknown"


@pytest.mark.parametrize("changes", [
    {"leaf_pem": "invalid"}, {"leaf_pem": "x" * 9000}, {"trust_anchors_pem": []},
    {"trust_anchors_pem": ["invalid"]}, {"intermediates_pem": ["x"] * 7},
    {"purpose": "other"}, {"hostname": "https://example.invalid"}, {"hostname": ""},
])
def test_missing_malformed_or_unbounded_cert_inputs_remain_unknown(material, changes):
    assert check({**server(material), **changes}).status == "unknown"


def test_pem_bundle_and_extra_bytes_are_not_silently_ignored(material):
    content = server(material)
    assert check({**content, "leaf_pem": content["leaf_pem"] * 2}).status == "unknown"
    assert check({**content, "leaf_pem": content["leaf_pem"] + "ignored"}).status == "unknown"


def test_prerequisite_is_exact_and_optional(material, monkeypatch):
    import cops.assessments.crypto_inputs as crypto
    monkeypatch.setattr(crypto, "version", lambda name: "0.0.0")
    result = check(server(material))
    assert (result.status, result.code) == ("unknown", "prerequisite_unavailable")


@pytest.fixture(scope="module")
def jwt_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    encode = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    def token(**claims):
        body = {"iss": "lab", "aud": "service", "sub": "synthetic", "exp": 2000, **claims}
        message = encode(b'{"alg":"RS256","kid":"ephemeral"}') + "." + encode(json.dumps(body).encode())
        return message + "." + encode(private.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256()))
    jwks = {"keys": [{"kty": "RSA", "kid": "ephemeral", "n": encode(public.n.to_bytes(256, "big")), "e": "AQAB"}]}
    return token, jwks


def test_jwt_signature_claims_and_missing_trust(jwt_material):
    token, jwks = jwt_material
    now = datetime.fromtimestamp(1000, UTC)
    content = {"token": token(), "jwks": jwks, "issuer": "lab", "audience": "service"}
    assert check(content, "jwt_verification", now).status == "accepted"
    for changes in ({"token": token(exp=999)}, {"audience": "other"}, {"issuer": "other"},
                    {"token": token() + "x"}):
        assert check({**content, **changes}, "jwt_verification", now).status == "rejected"
    for changes in ({"jwks": {}}, {"issuer": ""}, {"audience": None}, {"token": None}):
        assert check({**content, **changes}, "jwt_verification", now).status == "unknown"


def test_assessment_reports_outcomes_without_tokens_or_pem(material, jwt_material):
    token, jwks = jwt_material
    content = {"token": token(), "jwks": jwks, "issuer": "lab", "audience": "service"}
    artifacts = [{"artifact_id": "jwt", "kind": "jwt_verification", "content": content}]
    original = copy.deepcopy(artifacts)
    report = assess("transport_identity", artifacts, as_of="1970-01-01T00:16:40Z")
    assert report["verification_results"][0]["status"] == "accepted"
    assert report["findings"] == []
    assert content["token"] not in json.dumps(report)
    assert artifacts == original
    artifacts[0]["content"]["audience"] = "other"
    report = assess("transport_identity", artifacts, as_of="1970-01-01T00:16:40Z")
    assert report["verification_results"][0]["status"] == "rejected"
    assert report["findings"][0]["verification"] == "verified"
    assert report["findings"][0]["classification"] == "observation"
    report = assess("transport_identity", [{"artifact_id": "cert", "kind": "certificate_chain", "content": server(material)}], as_of=utc_now())
    assert report["verification_results"][0]["status"] == "accepted"
    assert "BEGIN CERTIFICATE" not in json.dumps(report)


@pytest.mark.parametrize("changes", [
    {"alg": "HS256"}, {"use": "enc"}, {"key_ops": ["sign"]}, {"d": "private"},
    {"n": ""}, {"n": "AQAB"}, {"e": "Aw"}, {"kid": ""},
])
def test_invalid_trust_policy_is_unknown_not_a_token_rejection(jwt_material, changes):
    token, jwks = jwt_material
    policy = {"keys": [{**jwks["keys"][0], **changes}]}
    content = {"token": token(), "jwks": policy, "issuer": "lab", "audience": "service"}
    assert check(content, "jwt_verification", datetime.fromtimestamp(1000, UTC)).status == "unknown"


def test_ambiguous_keys_and_missing_crypto_are_inconclusive(jwt_material, monkeypatch):
    from importlib.metadata import PackageNotFoundError
    import cops.assessments.crypto_inputs as crypto
    token, jwks = jwt_material
    content = {"token": token(), "jwks": {"keys": jwks["keys"] * 2}, "issuer": "lab", "audience": "service"}
    assert check(content, "jwt_verification").code == "jwt_policy_invalid"
    def unavailable(_name):
        raise PackageNotFoundError
    monkeypatch.setattr(crypto, "version", unavailable)
    report = assess("transport_identity", [{"artifact_id": "missing", "kind": "jwt_verification", "content": content}], as_of="1970-01-01T00:16:40Z")
    assert report["readiness"] == "insufficient_evidence"
    assert report["verification_results"][0]["status"] == "unknown"
    assert report["findings"][0]["verification"] == "unverified"


def test_time_size_and_nonfinite_inputs_are_bounded(material):
    assert check(server(material), now=datetime(2026, 1, 1)).status == "unknown"
    assert check({**server(material), "extra": "x" * (256 * 1024)}).code == "input_limit"
    assert check({"bad": float("nan")}).code == "invalid_input"
    assert check({}, "unsupported").code == "unsupported_format"


def test_empty_client_allowlist_denies_even_a_trusted_client(material):
    content = {**server(material), "purpose": "client", "leaf_pem": material["client_cert"], "authorized_client_sha256": []}
    assert check(content).code == "client_not_authorized"


def test_shared_report_preserves_outcome_and_rejects_tampering(jwt_material):
    from cops.assessments.artifacts import ArtifactAssessmentError
    from cops.assessments.reporting import to_assessment_report
    token, jwks = jwt_material
    context = {"engagement_id": "eng-crypto", "scenario_id": "COPS-CRYPTO", "result_id": "res-crypto"}
    report_context = {**context, "report_id": "report-crypto", "target": "fixture:jwt"}
    content = {"token": token(), "jwks": jwks, "issuer": "lab", "audience": "service"}
    assessment = assess("transport_identity", [{"artifact_id": "jwt", "kind": "jwt_verification", "content": content}],
                        as_of="1970-01-01T00:16:40Z", **context)
    report = to_assessment_report(assessment, **report_context)
    assert any("accepted (jwt_verified)" in value for value in report["limitations"])
    assert content["token"] not in json.dumps(report)
    for key, value in (("evidence_ref", "artifact:other:sha256:" + "0" * 64), ("status", "unknown"),
                       ("code", "secret"), ("fingerprints", ["secret"]), ("adapter_id", "other")):
        changed = copy.deepcopy(assessment)
        changed["verification_results"][0][key] = value
        with pytest.raises(ArtifactAssessmentError, match="invalid_artifact_assessment"):
            to_assessment_report(changed, **report_context)
