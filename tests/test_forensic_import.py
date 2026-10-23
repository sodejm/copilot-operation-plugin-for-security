from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.adapters.forensic import ForensicImportError, import_forensic_image
from cops.cli import main

scenarios("../specs/features/forensic_import.feature")
RAW = b"synthetic raw image: private file content must never appear in a report"
SHA = hashlib.sha256(RAW).hexdigest()


@pytest.fixture
def evidence(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path.resolve()
    (root / "disk.raw").write_bytes(RAW)
    return root, {
        "schema_version": "cops.forensic-import-input/v1",
        "artifact_id": "image-1",
        "source_relative": "disk.raw",
        "kind": "disk_image",
        "format": "raw",
        "sha256": SHA,
        "source_ref": "source-1",
        "authorization_ref": "permission-1",
        "collection_authorized": True,
        "collected_at": "2026-10-15T10:00:00Z",
        "as_of": "2026-10-15T12:00:00Z",
        "custody": [{"actor_ref": "collector-1", "action": "acquire", "at": "2026-10-15T10:00:00Z", "sha256": SHA}],
    }


@pytest.mark.parametrize("kind", ["disk_image", "memory_image"])
def test_import_preserves_source_and_redacts(evidence: tuple, kind: str) -> None:
    root, manifest = evidence
    manifest["kind"] = kind
    before = (root / "disk.raw").stat()
    report = import_forensic_image(root, manifest)
    assert report["integrity"] == "verified"
    assert report["analysis"] == "not_performed"
    assert report["source"]["sha256"] == SHA
    assert report["source"]["bytes"] == len(RAW)
    assert report["authorization"]["verification"] == "caller_asserted"
    assert report["limitations"]
    assert RAW.decode() not in json.dumps(report)
    assert str(root) not in json.dumps(report)
    assert "disk.raw" not in json.dumps(report)
    assert (root / "disk.raw").read_bytes() == RAW
    assert (root / "disk.raw").stat().st_mtime_ns == before.st_mtime_ns
    assert sorted(p.name for p in root.iterdir()) == ["disk.raw"]


@pytest.mark.parametrize(
    "patch",
    [
        {"sha256": "0" * 64},
        {"collection_authorized": False},
        {"collection_authorized": "true"},
        {"authorization_ref": ""},
        {"source_ref": "/private/source"},
        {"format": "E01"},
        {"kind": "native_memory"},
        {"custody": []},
        {"unexpected": "private data"},
        {"collected_at": "2027-01-01T00:00:00Z"},
        {"as_of": "invalid"},
        {"source_relative": "../disk.raw"},
        {"source_relative": "/dev/mem"},
    ],
)
def test_rejects_incomplete_unsafe_or_modified_evidence(evidence: tuple, patch: dict) -> None:
    root, manifest = evidence
    with pytest.raises(ForensicImportError):
        import_forensic_image(root, {**manifest, **patch})
    assert (root / "disk.raw").read_bytes() == RAW


@pytest.mark.parametrize(
    "patch",
    [
        {"sha256": "0" * 64},
        {"action": "execute"},
        {"actor_ref": ""},
        {"at": "2026-10-15T09:00:00Z"},
        {"at": "2026-10-15T13:00:00Z"},
    ],
)
def test_rejects_unbound_or_unordered_custody(evidence: tuple, patch: dict) -> None:
    root, manifest = evidence
    manifest["custody"].append({**manifest["custody"][0], "action": "verify", **patch})
    with pytest.raises(ForensicImportError):
        import_forensic_image(root, manifest)


@pytest.mark.parametrize("level", ["leaf", "parent", "root"])
def test_rejects_symlinks(evidence: tuple, level: str) -> None:
    root, manifest = evidence
    (root / "link").symlink_to(root if level != "leaf" else root / "disk.raw")
    if level == "root":
        root = root / "link"
    else:
        manifest["source_relative"] = "link" if level == "leaf" else "link/disk.raw"
    with pytest.raises(ForensicImportError):
        import_forensic_image(root, manifest)


def test_rejects_fifo_and_budget(evidence: tuple) -> None:
    root, manifest = evidence
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "pipe")
        with pytest.raises(ForensicImportError):
            import_forensic_image(root, {**manifest, "source_relative": "pipe"})
    for budget in (True, 0, 2, 128 * 1024 * 1024 + 1):
        with pytest.raises(ForensicImportError):
            import_forensic_image(root, manifest, max_bytes=budget)


def test_cli_import_and_content_free_failure(evidence: tuple, capsys: pytest.CaptureFixture) -> None:
    root, manifest = evidence
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest))
    args = ["forensic", "import", "--root", str(root), "--manifest", str(path)]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["integrity"] == "verified"
    manifest["sha256"] = "0" * 64
    path.write_text(json.dumps(manifest))
    assert main(args) == 2
    output = capsys.readouterr()
    assert not output.out
    assert str(root) not in output.err and RAW.decode() not in output.err


@given("a raw image with pinned identity and complete custody", target_fixture="scenario")
def image(evidence: tuple) -> dict:
    return {"root": evidence[0], "manifest": copy.deepcopy(evidence[1])}


@when("the image is imported")
def imported(scenario: dict) -> None:
    scenario["report"] = import_forensic_image(scenario["root"], scenario["manifest"])


@then("its integrity is verified with explicit analysis limitations")
def verified(scenario: dict) -> None:
    assert scenario["report"]["integrity"] == "verified"
    assert scenario["report"]["analysis"] == "not_performed"


@when("the image bytes are changed before import")
def tampered(scenario: dict) -> None:
    (scenario["root"] / "disk.raw").write_bytes(b"changed")


@then("import rejects the modified evidence")
def rejected(scenario: dict) -> None:
    with pytest.raises(ForensicImportError):
        import_forensic_image(scenario["root"], scenario["manifest"])


@pytest.mark.parametrize("replacement", [False, True])
def test_rejects_source_change_during_stream(
    evidence: tuple, monkeypatch: pytest.MonkeyPatch, replacement: bool
) -> None:
    root, manifest = evidence
    read = os.read
    changed = False

    def mutate(fd: int, count: int) -> bytes:
        nonlocal changed
        chunk = read(fd, count)
        if chunk and not changed:
            changed = True
            if replacement:
                (root / "replacement").write_bytes(RAW)
                (root / "replacement").replace(root / "disk.raw")
            else:
                (root / "disk.raw").write_bytes(b"changed during import")
        return chunk

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(ForensicImportError, match="source_changed"):
        import_forensic_image(root, manifest)


def test_large_source_is_streamed(evidence: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, manifest = evidence
    raw = b"large synthetic image" * 100_000
    (root / "disk.raw").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    manifest["sha256"] = manifest["custody"][0]["sha256"] = sha
    read = os.read
    sizes = []

    def bounded_read(fd: int, count: int) -> bytes:
        sizes.append(count)
        return read(fd, count)

    monkeypatch.setattr(os, "read", bounded_read)
    assert import_forensic_image(root, manifest)["source"]["bytes"] == len(raw)
    assert len(sizes) > 2 and max(sizes) <= 65_536


@pytest.mark.parametrize("case", ["empty", "missing", "custody_limit", "wrong_type"])
def test_rejects_incomplete_manifest_or_source(evidence: tuple, case: str) -> None:
    root, manifest = evidence
    if case == "empty":
        (root / "disk.raw").write_bytes(b"")
    elif case == "missing":
        del manifest["source_ref"]
    elif case == "custody_limit":
        manifest["custody"] *= 129
    else:
        manifest = []
    with pytest.raises(ForensicImportError):
        import_forensic_image(root, manifest)


@pytest.mark.parametrize("case", ["duplicate", "symlink", "fifo", "oversized", "array"])
def test_cli_rejects_unsafe_manifest(evidence: tuple, capsys: pytest.CaptureFixture, case: str) -> None:
    root, manifest = evidence
    path = root / "manifest.json"
    if case == "symlink":
        path.symlink_to(root / "disk.raw")
    elif case == "fifo":
        os.mkfifo(path)
    else:
        path.write_text(
            {"duplicate": '{"source_ref":"one","source_ref":"two"}', "oversized": " " * 65_537, "array": "[]"}[case]
        )
    assert main(["forensic", "import", "--root", str(root), "--manifest", str(path)]) == 2
    output = capsys.readouterr()
    assert not output.out and str(root) not in output.err
