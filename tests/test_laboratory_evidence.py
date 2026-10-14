"""Security regressions for durable laboratory evidence storage."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import cops.laboratory.evidence as evidence_module
from cops.evidence.canonical import canonical
from cops.laboratory import LaboratoryEvidenceStore, LaboratoryGateError


def test_evidence_digest_covers_exact_canonical_bytes(tmp_path: Path) -> None:
    store = LaboratoryEvidenceStore(tmp_path / "evidence")
    value = {"unicode": "snowman \u2603", "count": 2}
    reference = store.write_json("observation", value)
    assert reference["path"] == f"observation-{reference['sha256']}.json"
    assert not Path(reference["path"]).is_absolute()
    assert str(tmp_path) not in str(reference)
    raw = store.resolve(reference).read_bytes()
    assert raw == canonical(value)
    assert reference["sha256"] == hashlib.sha256(raw).hexdigest()
    assert reference["byte_length"] == len(raw)


@pytest.mark.parametrize(
    "path",
    ["../evidence.json", "/tmp/evidence.json", "observation-wrong.json"],
)
def test_evidence_reference_path_must_match_content_address(path: str, tmp_path: Path) -> None:
    store = LaboratoryEvidenceStore(tmp_path / "evidence")
    reference = store.write_json("observation", {"status": "observed"})
    reference["path"] = path

    with pytest.raises(LaboratoryGateError, match="invalid laboratory evidence reference"):
        store.resolve(reference)


def test_existing_evidence_symlink_is_rejected(tmp_path: Path) -> None:
    store = LaboratoryEvidenceStore(tmp_path / "evidence")
    value = {"status": "observed"}
    digest = hashlib.sha256(canonical(value)).hexdigest()
    destination = tmp_path / "outside.json"
    destination.write_text("outside", encoding="utf-8")
    (store.directory / f"observation-{digest}.json").symlink_to(destination)

    with pytest.raises(LaboratoryGateError, match="safely read"):
        store.write_json("observation", value)
    assert destination.read_text(encoding="utf-8") == "outside"


def test_directory_redirection_is_rejected_and_partial_evidence_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LaboratoryEvidenceStore(tmp_path / "evidence")
    original_directory = tmp_path / "original-evidence"
    replacement_directory = tmp_path / "replacement-evidence"
    original_validate = store._validate_directory_binding
    swapped = False

    def swap_before_validation(descriptor: int) -> None:
        nonlocal swapped
        if not swapped:
            store.directory.rename(original_directory)
            replacement_directory.mkdir(mode=0o700)
            store.directory.symlink_to(replacement_directory, target_is_directory=True)
            swapped = True
        original_validate(descriptor)

    monkeypatch.setattr(store, "_validate_directory_binding", swap_before_validation)
    with pytest.raises(LaboratoryGateError, match="changed during write"):
        store.write_json("observation", {"status": "observed"})

    assert not list(original_directory.glob("*.json"))
    assert not list(replacement_directory.glob("*.json"))


def test_checked_directory_descriptor_is_closed_when_fstat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "evidence"
    directory.mkdir(mode=0o700)
    store = object.__new__(LaboratoryEvidenceStore)
    store.directory = directory
    descriptor = os.open(directory, os.O_RDONLY)
    original_fstat = os.fstat
    original_close = os.close
    closed: list[int] = []

    monkeypatch.setattr(evidence_module, "open_directory_no_symlinks", lambda path: descriptor)

    def fail_fstat(fd: int):
        if fd == descriptor:
            raise OSError("injected fstat failure")
        return original_fstat(fd)

    def record_close(fd: int) -> None:
        closed.append(fd)
        original_close(fd)

    monkeypatch.setattr(evidence_module.os, "fstat", fail_fstat)
    monkeypatch.setattr(evidence_module.os, "close", record_close)
    with pytest.raises(LaboratoryGateError, match="cannot protect"):
        store._open_checked_directory()
    assert closed == [descriptor]


def test_failed_write_removes_partial_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = LaboratoryEvidenceStore(tmp_path / "evidence")
    original_write = os.write
    write_count = 0

    def fail_after_partial_write(descriptor: int, data: bytes) -> int:
        nonlocal write_count
        write_count += 1
        if write_count == 1:
            return original_write(descriptor, data[:1])
        raise OSError("injected write failure")

    monkeypatch.setattr(evidence_module.os, "write", fail_after_partial_write)
    with pytest.raises(LaboratoryGateError, match="cannot write"):
        store.write_json("observation", {"status": "observed"})
    assert not list(store.directory.glob("*.json"))
