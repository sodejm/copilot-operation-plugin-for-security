"""Reproducible offline package archive and locally observed integrity evidence."""

from __future__ import annotations

import io
import re
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import validate_library
from .errors import ContentError
from .evaluator import run_library
from .package_validation import validate_package
from .paths import EVIDENCE_DIR, PACKAGE_ROOT, RELEASE_DIR, load_hunts, load_json, sha256_bytes, write_json
from .rendering import compatibility_report
from .reports import EXTERNAL_EVIDENCE_SCHEMA, INTEGRITY_EVIDENCE_SCHEMA, release_report, release_subject


ARCHIVE_NAME = "sentinel-hunt-workbench.zip"
_SECRET_PATTERNS = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "openai_key": re.compile(rb"\bsk-[A-Za-z0-9]{20,}\b"),
}


def _source_bytes(relative: str, expected_hash: str) -> bytes:
    path = PACKAGE_ROOT / relative
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ContentError(f"release input is not a regular file: {relative}")
    content = path.read_bytes()
    if sha256_bytes(content) != expected_hash:
        raise ContentError(f"release input changed after subject calculation: {relative}")
    return content


def archive_bytes(subject: dict[str, Any]) -> bytes:
    """Build a byte-stable ZIP with fixed timestamps, permissions, and order."""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for relative, expected_hash in sorted(subject["artifacts"].items()):
            entry = zipfile.ZipInfo(f"sentinel-hunt-workbench/{relative}", date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_STORED
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, _source_bytes(relative, expected_hash))
    return buffer.getvalue()


def secret_findings(relative: str, content: bytes) -> list[dict[str, str]]:
    """Return only pattern names and paths; never echo possible secret values."""

    return [
        {"path": relative, "pattern": name}
        for name, pattern in _SECRET_PATTERNS.items()
        if pattern.search(content)
    ]


def _evidence_file(name: str, value: Any) -> tuple[Path, str]:
    path = EVIDENCE_DIR / name
    if path.is_symlink() or EVIDENCE_DIR.is_symlink():
        raise ContentError(f"release evidence path is a symbolic link: {name}")
    write_json(path, value)
    return path, sha256_bytes(path.read_bytes())


def _pointer(path: Path, digest: str) -> dict[str, str]:
    return {"artifact_path": path.relative_to(EVIDENCE_DIR).as_posix(), "artifact_sha256": digest}


def _release_file(name: str, value: Any) -> Path:
    path = RELEASE_DIR / name
    if RELEASE_DIR.is_symlink() or path.is_symlink():
        raise ContentError(f"release output path is a symbolic link: {name}")
    write_json(path, value)
    return path


def build_release_artifacts(seed: int = 20260916) -> dict[str, Any]:
    """Run local gates and emit a content-addressed archive, evidence, and report."""

    package = validate_package()
    subject = release_subject()
    if package["release_subject_sha256"] != subject["sha256"]:
        raise ContentError("release subject changed during package validation")
    validation = validate_library()
    stress = run_library(seed)
    compatibility = {
        "schema": "huntwb.compatibility-report/v1",
        "status": "passed",
        "subject_sha256": subject["sha256"],
        "reports": [compatibility_report(hunt["id"]) for hunt in load_hunts()],
    }

    findings: list[dict[str, str]] = []
    for relative, expected_hash in sorted(subject["artifacts"].items()):
        findings.extend(secret_findings(relative, _source_bytes(relative, expected_hash)))
    if findings:
        kinds = sorted({finding["pattern"] for finding in findings})
        raise ContentError(f"release secret scan found {len(findings)} potential secret(s): {kinds}")

    first = archive_bytes(subject)
    second = archive_bytes(subject)
    archive_hash = sha256_bytes(first)
    if first != second:
        raise ContentError("two independent archive builds differ")
    if RELEASE_DIR.is_symlink():
        raise ContentError("release directory is a symbolic link")
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = RELEASE_DIR / ARCHIVE_NAME
    if archive_path.is_symlink():
        raise ContentError("release archive path is a symbolic link")
    archive_path.write_bytes(first)
    if sha256_bytes(archive_path.read_bytes()) != archive_hash:
        raise ContentError("release archive did not survive writing unchanged")

    subject_hash = subject["sha256"]
    _release_file("package-validation.json", package)
    _release_file("library-validation.json", {"subject_sha256": subject_hash, **validation})
    _release_file("stress-test.json", {"subject_sha256": subject_hash, **stress})
    _release_file("compatibility.json", compatibility)
    payloads: dict[str, dict[str, Any]] = {
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {"type": "application", "name": "sentinel-hunt-workbench", "version": "2.0.0"},
                "properties": [{"name": "huntwb.release_subject_sha256", "value": subject_hash}],
            },
            "components": [
                {"type": "file", "name": relative, "hashes": [{"alg": "SHA-256", "content": digest}]}
                for relative, digest in sorted(subject["artifacts"].items())
            ],
        },
        "provenance_manifest": {
            "schema": "huntwb.provenance-manifest/v1",
            "subject_sha256": subject_hash,
            "artifacts": subject["artifacts"],
            "archive_name": ARCHIVE_NAME,
            "archive_sha256": archive_hash,
        },
        "secret_scan": {
            "schema": "huntwb.secret-scan-result/v1",
            "status": "passed",
            "subject_sha256": subject_hash,
            "findings": [],
            "scanned_file_count": subject["artifact_count"],
            "scanner": "huntwb-bounded-pattern-scan/v1",
        },
        "reproducible_build": {
            "schema": "huntwb.reproducible-build-result/v1",
            "status": "passed",
            "subject_sha256": subject_hash,
            "build_a_sha256": archive_hash,
            "build_b_sha256": sha256_bytes(second),
            "archive_name": ARCHIVE_NAME,
        },
    }
    index: dict[str, dict[str, str]] = {}
    completed_at = datetime.now(timezone.utc).isoformat()
    for kind, payload in payloads.items():
        payload_path, payload_hash = _evidence_file(f"{kind}.payload.json", payload)
        wrapper = {
            "schema": INTEGRITY_EVIDENCE_SCHEMA,
            "kind": kind,
            "subject_sha256": subject_hash,
            "status": "passed",
            "completed_at": completed_at,
            "tool": "huntwb.build_release_artifacts",
            "tool_version": "1.0.0",
            "payload_path": payload_path.relative_to(EVIDENCE_DIR).as_posix(),
            "payload_sha256": payload_hash,
        }
        wrapper_path, wrapper_hash = _evidence_file(f"{kind}.evidence.json", wrapper)
        index[kind] = _pointer(wrapper_path, wrapper_hash)
    index_path, index_hash = _evidence_file("release-integrity.index.json", index)
    envelope = {
        "schema": EXTERNAL_EVIDENCE_SCHEMA,
        "subject_sha256": subject_hash,
        "release_integrity": _pointer(index_path, index_hash),
    }
    envelope_path = _release_file("local-evidence.json", envelope)
    report = release_report(seed, load_json(envelope_path))
    if report["gates"]["release_integrity"]["status"] != "passed":
        raise ContentError(f"generated integrity evidence failed validation: {report['gates']['release_integrity']['findings']}")
    for name in ("contract_and_schema", "static_validation", "reference_fixture_execution", "adapter_integrity"):
        if report["gates"][name]["status"] != "passed":
            raise ContentError(f"local release gate failed: {name}")
    report_path = _release_file("release-report.json", report)
    return {
        "status": report["status"],
        "qualification_state": report["qualification_state"],
        "release_subject_sha256": subject_hash,
        "archive_sha256": archive_hash,
        "archive_path": str(archive_path),
        "evidence_path": str(envelope_path),
        "report_path": str(report_path),
        "gates": {name: gate["status"] for name, gate in report["gates"].items()},
    }
