# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Required SOC object IDs are rejected before a handoff can be written."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins/detection-hunting/soc-investigation-workbench"
sys.path.insert(0, str(PLUGIN))

from investigationwb.engine import ContractError, validate
from investigationwb.handoff import write_handoff


@pytest.mark.parametrize("collection", ("hypotheses", "entities", "evidence"))
def test_missing_required_object_id_rejected_before_handoff(tmp_path: Path, collection: str) -> None:
    case = json.loads((PLUGIN / "examples/case.json").read_text())
    validate(case)
    del case[collection][0]["id"]

    destination = tmp_path / f"{collection}-handoff"
    with pytest.raises(ContractError, match=r"^Record must have an ID\.$"):
        write_handoff(destination, case)
    assert not destination.exists()
