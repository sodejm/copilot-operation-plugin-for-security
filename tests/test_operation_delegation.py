from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from cops.operations.contracts import response
from cops.operations.runs import RunStore
from cops.operations.service import OperationService
from tests.test_operation_runs import call

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "posix", reason="private state requires POSIX")


def test_optional_delegation_and_single_use_peer_claim(tmp_path):
    service = OperationService(run_store=RunStore(tmp_path / "private"))
    loose = call(service, "cops.delegate.prepare", {"task": "Quick second opinion"})
    assert loose["result"]["binding"] is None
    assert loose["result"]["execution_authorized"] is False
    prepared = call(
        service,
        "cops.delegate.prepare",
        {
            "task": "Review the supplied case",
            "scope_ref": "tenant-a",
            "specialist_id": "cops-soc-analyst",
            "skill_id": "soc-investigation-planning",
            "operation_id": "cops.soc.next",
        },
    )
    document = prepared["result"]
    assert document["binding"]["plugin_id"] == "soc-investigation-workbench"
    peer = {"binding_digest": document["binding_digest"], "scope_ref": "tenant-a", "notes": ["Probably inconclusive"]}
    accepted = call(
        service, "cops.delegate.accept", {"delegation_id": document["delegation_id"], "peer_response": peer}
    )
    assert accepted["result"]["verification"] == "untrusted_peer_claims_only"
    assert accepted["result"]["execution_authorized"] is False
    replay = call(service, "cops.delegate.accept", {"delegation_id": document["delegation_id"], "peer_response": peer})
    assert replay["error"]["code"] == "delegation_replayed"


def test_scope_substitution_and_changed_product_skill_rejected(tmp_path):
    installed = tmp_path / "installed"
    (installed / "agents").mkdir(parents=True)
    (installed / "catalog").mkdir()
    shutil.copyfile(ROOT / "agents/registry.json", installed / "agents/registry.json")
    shutil.copyfile(ROOT / "catalog/plugins.json", installed / "catalog/plugins.json")
    skill = Path("plugins/detection-hunting/soc-investigation-workbench/skills/soc-investigation-planning/SKILL.md")
    (installed / skill).parent.mkdir(parents=True)
    shutil.copyfile(ROOT / skill, installed / skill)
    service = OperationService(run_store=RunStore(tmp_path / "state"), installed_root=installed)
    prepared = call(
        service,
        "cops.delegate.prepare",
        {
            "task": "Review",
            "scope_ref": "tenant-a",
            "specialist_id": "cops-soc-analyst",
            "skill_id": "soc-investigation-planning",
        },
    )["result"]
    peer = {"binding_digest": prepared["binding_digest"], "scope_ref": "tenant-b", "notes": []}
    rejected = call(
        service, "cops.delegate.accept", {"delegation_id": prepared["delegation_id"], "peer_response": peer}
    )
    assert rejected["error"]["code"] == "peer_scope_or_binding_mismatch"
    (installed / skill).write_text((installed / skill).read_text() + "\nChanged installed skill.\n")
    peer["scope_ref"] = "tenant-a"
    rejected = call(
        service, "cops.delegate.accept", {"delegation_id": prepared["delegation_id"], "peer_response": peer}
    )
    assert rejected["error"]["code"] == "delegation_binding_changed"


def test_operation_substitution_and_fake_authority_rejected(tmp_path):
    service = OperationService(run_store=RunStore(tmp_path / "state"))
    document = call(
        service,
        "cops.delegate.prepare",
        {
            "task": "Review",
            "specialist_id": "cops-soc-analyst",
            "skill_id": "soc-investigation-planning",
            "operation_id": "cops.soc.next",
        },
    )["result"]
    peer = {"binding_digest": document["binding_digest"], "operation_result": response("cops.soc.report", result={})}
    rejected = call(
        service, "cops.delegate.accept", {"delegation_id": document["delegation_id"], "peer_response": peer}
    )
    assert rejected["error"]["code"] == "peer_operation_mismatch"
    peer["operation_result"] = response("cops.soc.next", result={})
    peer["execution_authorized"] = True
    rejected = call(
        service, "cops.delegate.accept", {"delegation_id": document["delegation_id"], "peer_response": peer}
    )
    assert rejected["error"]["code"] == "invalid_peer_response"
