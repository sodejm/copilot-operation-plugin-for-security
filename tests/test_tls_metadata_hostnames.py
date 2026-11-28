"""Bounded hostname matching for legacy structured TLS metadata."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from cops.assessments.artifacts import assess

AS_OF = "2026-10-15T12:00:00Z"


def _artifact(hostname: object, sans: object, **changes: object) -> dict[str, object]:
    content: dict[str, object] = {
        "hostname": hostname,
        "expected_mtls": True,
        "require_client_certificate": True,
        "chain": [
            {
                "subject": "leaf-subject-must-not-leak",
                "issuer": "root-subject-must-not-leak",
                "san": sans,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            },
            {
                "subject": "root-subject-must-not-leak",
                "issuer": "root-subject-must-not-leak",
                "san": [],
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
            },
        ],
    }
    content.update(changes)
    return {"artifact_id": "tls-metadata", "kind": "tls_config", "content": content}


def _report(hostname: object, sans: object, **changes: object) -> dict[str, object]:
    return assess("transport_identity", [_artifact(hostname, sans, **changes)], as_of=AS_OF)


def _codes(report: dict[str, object]) -> list[str]:
    finding_codes = report["finding_codes"]
    assert isinstance(finding_codes, dict)
    return list(finding_codes.values())


@pytest.mark.parametrize(
    ("hostname", "san"),
    [
        ("api.example.com", "*.example.com"),
        ("API.Example.COM", "api.example.com"),
        ("api.example.com", "API.EXAMPLE.COM"),
        ("127.0.0.1", "127.0.0.1"),
        ("2001:db8::1", "2001:0DB8:0:0:0:0:0:1"),
    ],
)
def test_supported_dns_and_ip_sans_match(hostname: str, san: str) -> None:
    assert "certificate_hostname" not in _codes(_report(hostname, [san]))
    assert "certificate_hostname_insufficient_evidence" not in _codes(_report(hostname, [san]))


@pytest.mark.parametrize("hostname", ["example.com", "a.b.example.com", "127.0.0.1"])
def test_wildcard_does_not_match_apex_multiple_labels_or_ip(hostname: str) -> None:
    report = _report(hostname, ["*.example.com"])

    assert "certificate_hostname" in _codes(report)
    assert "certificate_hostname_insufficient_evidence" not in _codes(report)


@pytest.mark.parametrize(
    "san",
    [
        "api*.example.com",
        "*.*.example.com",
        "example.*",
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}.example",
        "xn--caf-dma.example",
        "XN--CAF-DMA.example",
        "api.example.com ",
        "api.\nexample.com",
        "example..com",
        "-api.example.com",
        "01.2.3.4",
        "a" * 64 + ".example.com",
        "a." * 126 + "example",
    ],
)
def test_unsupported_san_is_insufficient_not_a_mismatch(san: str) -> None:
    report = _report("api.example.com", [san])

    assert "certificate_hostname_insufficient_evidence" in _codes(report)
    assert "certificate_hostname" not in _codes(report)
    serialized = json.dumps(report, sort_keys=True)
    assert san not in serialized
    assert "leaf-subject-must-not-leak" not in serialized


@pytest.mark.parametrize(
    "sans",
    ["api.example.com", {"dns": "api.example.com"}, ["other.example.com", 7]],
)
def test_malformed_san_collections_are_insufficient(sans: object) -> None:
    report = _report("api.example.com", sans)

    assert "certificate_hostname_insufficient_evidence" in _codes(report)
    assert "certificate_hostname" not in _codes(report)


@pytest.mark.parametrize(
    "hostname",
    [
        7,
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}.example",
        "xn--caf-dma.example",
        "XN--CAF-DMA.example",
        "api.example.com ",
        "999.0.0.1",
        "a" * 254,
    ],
)
def test_unsupported_expected_hostname_is_insufficient(hostname: object) -> None:
    report = _report(hostname, ["api.example.com"])

    assert "certificate_hostname_insufficient_evidence" in _codes(report)
    assert "certificate_hostname" not in _codes(report)
    if isinstance(hostname, str):
        assert hostname not in json.dumps(report, sort_keys=True)


def test_mixed_supported_and_unsupported_sans_are_conservative() -> None:
    unresolved = _report("api.example.com", ["other.example.com", "xn--caf-dma.example"])
    matched = _report("api.example.com", ["xn--caf-dma.example", "API.EXAMPLE.COM"])

    assert _codes(unresolved) == ["certificate_hostname_insufficient_evidence"]
    assert _codes(matched) == []


def test_well_formed_nonmatching_sans_retain_stable_singleton_finding() -> None:
    artifact = _artifact("api.example.com", ["other.example.com", "*.other.example.com"])
    original = copy.deepcopy(artifact)

    first = assess("transport_identity", [artifact], as_of=AS_OF)
    second = assess("transport_identity", [artifact], as_of=AS_OF)

    assert artifact == original
    assert first == second
    assert _codes(first) == ["certificate_hostname"]
    finding = first["findings"][0]
    reference = finding["evidence_references"][0]
    suffix = hashlib.sha256(("transport_identity" + "certificate_hostname" + reference).encode()).hexdigest()[:24]
    assert finding["finding_id"] == f"find-{suffix}"


def test_hostname_uncertainty_does_not_hide_time_chain_or_mtls_findings() -> None:
    chain = [
        {
            "subject": "leaf-subject-must-not-leak",
            "issuer": "unexpected-issuer-must-not-leak",
            "san": ["api*.example.com"],
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2021-01-01T00:00:00Z",
        },
        {
            "subject": "root-subject-must-not-leak",
            "issuer": "root-subject-must-not-leak",
            "san": [],
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2030-01-01T00:00:00Z",
        },
    ]
    report = _report(
        "api.example.com",
        ["ignored.example.com"],
        chain=chain,
        require_client_certificate=False,
    )

    assert set(_codes(report)) == {
        "certificate_time_invalid",
        "certificate_chain_link",
        "certificate_hostname_insufficient_evidence",
        "mtls_not_required",
    }
    serialized = json.dumps(report, sort_keys=True)
    assert "must-not-leak" not in serialized
