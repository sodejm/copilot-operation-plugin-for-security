from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from cops.assessments.acquisition import ADAPTER_ID, AcquisitionError, acquire_disposable_file
from cops.assessments.artifacts import assess


@pytest.fixture
def acquisition(tmp_path: Path) -> dict:
    root = tmp_path.resolve()
    (root / "source.bin").write_bytes(b"synthetic disk evidence")
    return dict(adapter_id=ADAPTER_ID, lab_root=root, source_relative="source.bin", output_relative="acquired.bin",
                expected_sha256=hashlib.sha256(b"synthetic disk evidence").hexdigest(), source_ref="lab-disk",
                actor_ref="collector-1", collected_at="2026-10-15T10:00:00Z", collection_authorized=True,
                disposable_lab=True)


def test_acquisition_preserves_original_and_custody_and_refuses_overwrite(acquisition: dict) -> None:
    root = acquisition["lab_root"]
    before = (root / "source.bin").read_bytes()
    artifact, receipt = acquire_disposable_file(**acquisition)
    assert (root / "source.bin").read_bytes() == (root / "acquired.bin").read_bytes() == before
    assert receipt["original_unchanged"] is receipt["exclusive_copy"] is True
    assert artifact["custody"][0]["actor_ref"] == "collector-1"
    assert not assess("forensic_evidence", [artifact], as_of="2026-10-15T12:00:00Z")["finding_codes"]
    with pytest.raises(AcquisitionError):
        acquire_disposable_file(**acquisition)
    assert (root / "acquired.bin").read_bytes() == before


@pytest.mark.parametrize("update", [
    {"collection_authorized": False}, {"disposable_lab": False}, {"collection_authorized": "true"},
    {"adapter_id": "unregistered"}, {"max_bytes": 2}, {"max_bytes": True},
    {"expected_sha256": "0" * 64}, {"source_ref": "/private/identity"}, {"collected_at": "invalid"},
    {"source_relative": "../source.bin"}, {"output_relative": "../outside"},
    {"source_relative": "/absolute"}, {"source_relative": "source.bin", "output_relative": "source.bin"},
])
def test_unsafe_acquisition_is_rejected_without_partial_outputs(acquisition: dict, update: dict) -> None:
    with pytest.raises(AcquisitionError):
        acquire_disposable_file(**{**acquisition, **update})
    assert not (acquisition["lab_root"] / "acquired.bin").exists()
    assert (acquisition["lab_root"] / "source.bin").read_bytes() == b"synthetic disk evidence"


@pytest.mark.parametrize("target", ["source", "parent", "output", "root"])
def test_acquisition_rejects_symlinks(acquisition: dict, target: str) -> None:
    root = acquisition["lab_root"]
    if target == "source":
        (root / "link").symlink_to(root / "source.bin")
        acquisition["source_relative"] = "link"
    elif target == "parent":
        (root / "link").symlink_to(root, target_is_directory=True)
        acquisition["source_relative"] = "link/source.bin"
    elif target == "output":
        (root / "acquired.bin").symlink_to(root / "source.bin")
    else:
        (root / "link").symlink_to(root, target_is_directory=True)
        acquisition["lab_root"] = root / "link"
    with pytest.raises(AcquisitionError):
        acquire_disposable_file(**acquisition)
    assert (root / "source.bin").read_bytes() == b"synthetic disk evidence"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX acquisition adapter")
def test_acquisition_rejects_fifo_without_blocking(acquisition: dict) -> None:
    root = acquisition["lab_root"]
    os.mkfifo(root / "source.fifo")
    with pytest.raises(AcquisitionError, match="source_type"):
        acquire_disposable_file(**{**acquisition, "source_relative": "source.fifo"})


def test_acquisition_rejects_replaced_source(acquisition: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    root = acquisition['lab_root']
    read = os.read
    changed = False

    def replace_after_read(fd: int, count: int) -> bytes:
        nonlocal changed
        raw = read(fd, count)
        if raw and not changed:
            changed = True
            (root / 'replacement').write_bytes(raw)
            (root / 'replacement').replace(root / 'source.bin')
        return raw

    monkeypatch.setattr(os, 'read', replace_after_read)
    with pytest.raises(AcquisitionError, match='source_changed'):
        acquire_disposable_file(**acquisition)
    assert not (root / 'acquired.bin').exists()
