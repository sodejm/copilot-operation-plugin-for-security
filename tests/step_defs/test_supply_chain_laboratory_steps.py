from __future__ import annotations

from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.laboratory.service_supply_chain import prerequisite_status, run_supply_chain_acceptance

scenarios("../../specs/features/supply_chain_laboratory.feature")


@given("the registered supply-chain laboratory has its pinned installer", target_fixture="supply_context")
def supply_context() -> dict[str, Any]:
    prerequisite = prerequisite_status()
    if not prerequisite["available"]:
        pytest.skip(prerequisite["limitation"])
    return {}


@when(parsers.parse('the "{profile}" synthetic wheel is built and installed offline'))
def install(supply_context: dict[str, Any], profile: str) -> None:
    supply_context.update(run_supply_chain_acceptance(profile))


@then("the installed package preserves the owner's permitted query")
def benign(supply_context: dict[str, Any]) -> None:
    assert supply_context["runtime"]["benign_objects"] == ["owner-object"]
    assert supply_context["installed_source_verified"] is True
    assert supply_context["install_exit_code"] == 0


@then(parsers.parse("the installed injection exposes {rows:d} objects"))
def injection(supply_context: dict[str, Any], rows: int) -> None:
    assert len(supply_context["runtime"]["injection_objects"]) == rows


@then(parsers.parse('the pinned advisory assessment is "{assessment}"'))
def advisory(supply_context: dict[str, Any], assessment: str) -> None:
    assert supply_context["advisory_assessment"] == assessment


@then("a modified wheel is rejected by the installer")
def tampering(supply_context: dict[str, Any]) -> None:
    assert supply_context["hash_mismatch_rejected"] is True
    assert supply_context["tampered_install_absent"] is True


@then("missing dependency evidence remains unknown")
def unknown(supply_context: dict[str, Any]) -> None:
    assert supply_context["insufficient_evidence_status"] == "unknown"


@then("the package service stops and its disposable installation is removed")
def cleanup(supply_context: dict[str, Any]) -> None:
    assert supply_context["runtime"]["service_stopped"] is True
    assert supply_context["runtime"]["actual_requests"] == 2
    assert supply_context["disposable_root_removed"] is True
