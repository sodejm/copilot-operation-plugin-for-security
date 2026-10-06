"""Unit tests for COPS dynamic specialist routing, Triad orchestration, and interactive authorization."""

from __future__ import annotations

import io
import json
from pathlib import Path

import jsonschema
import pytest

from cops.authorization import (
    AuthorizationDeniedError,
    AuthorizationError,
    AuthorizationReceipt,
    AuthorizationRequiredError,
    create_authorization_receipt,
    ensure_authorization,
    request_interactive_authorization,
    validate_receipt_document,
)
from cops.routing.classifier import route_request
from cops.routing.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]


def test_route_kql_engineer():
    """Verify routing for Sentinel KQL tasks."""
    decision = route_request("Please help write a high-performance KQL query for Sentinel")
    assert decision.primary_profile.id == "cops-sentinel-kql-engineer"
    assert decision.criticality == "normal"
    assert not decision.interactive_authorization_required
    assert decision.triad_plan is None
    assert "author-sentinel-kql" in decision.recommended_skills


def test_route_pentest_specialist_and_triad():
    """Verify routing for penetration testing triggers critical level and Triad orchestration."""
    decision = route_request("Plan an authorized penetration test on internal web services")
    assert decision.primary_profile.id == "cops-pentest-specialist"
    assert decision.criticality == "critical"
    assert decision.interactive_authorization_required
    assert decision.triad_plan is not None

    triad = decision.triad_plan
    assert triad.primary.specialist_id == "cops-pentest-specialist"
    assert triad.skeptic.specialist_id == "cops-detection-engineer"
    assert triad.auditor.specialist_id == "cops-compliance-auditor"
    assert len(triad.handoff_steps) == 7


def test_route_redteam_operator():
    """Verify routing for red team adversary emulation."""
    decision = route_request("Model red team lateral movement to crown jewels using assumed breach")
    assert decision.primary_profile.id == "cops-redteam-operator"
    assert decision.criticality == "critical"
    assert decision.triad_plan is not None
    assert decision.triad_plan.skeptic.specialist_id == "cops-threat-hunter"


def test_route_incident_responder():
    """Verify routing for containment and incident response."""
    decision = route_request("We have a ransomware incident: calculate blast radius and plan host isolation")
    assert decision.primary_profile.id == "cops-incident-responder"
    assert decision.criticality == "critical"
    assert decision.interactive_authorization_required
    assert decision.triad_plan is not None
    assert decision.triad_plan.skeptic.specialist_id == "cops-soc-analyst"
    assert decision.triad_plan.auditor.specialist_id == "cops-forensic-collector"


def test_route_forensics_evidence_collector():
    """Verify routing for evidence capture and data collection."""
    decision = route_request("We need to capture forensic evidence envelopes and generate an acquisition receipt")
    assert decision.primary_profile.id == "cops-forensic-collector"
    assert decision.criticality == "normal"
    assert not decision.interactive_authorization_required


def test_route_identity_governance():
    """Verify routing for Entra ID privilege escalation."""
    decision = route_request("Audit Entra ID service principal privilege escalation and toxic combinations")
    assert decision.primary_profile.id == "cops-identity-specialist"
    assert decision.criticality == "critical"
    assert decision.triad_plan is not None
    assert decision.triad_plan.skeptic.specialist_id == "cops-redteam-operator"


def test_route_fallback():
    """Verify that an ambiguous query defaults safely to cops-soc-analyst triage."""
    decision = route_request("hello, what should we do today?")
    assert decision.primary_profile.id == "cops-soc-analyst"
    assert decision.confidence < 0.50


def test_direct_profile_mention():
    """Verify that referencing an explicit profile ID matches with high confidence."""
    decision = route_request("Let's talk to cops-logging-architect about audit logs")
    assert decision.primary_profile.id == "cops-logging-architect"
    assert decision.confidence == 0.99


# --- Interactive Authorization Tests ---


def test_authorization_receipt_creation_and_schema():
    """Verify that create_authorization_receipt generates a valid schema-conforming receipt."""
    schema_path = ROOT / "catalog" / "schemas" / "authorization-receipt.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    receipt = create_authorization_receipt(
        operator="test-operator",
        specialist_id="cops-pentest-specialist",
        action_type="scoped-port-audit",
        target_scope=["10.0.0.0/24"],
        allowed_operations=["port-scan-review"],
    )

    doc = receipt.to_dict()
    jsonschema.validate(instance=doc, schema=schema)

    # Validate receipt with validate_receipt_document
    validated = validate_receipt_document(doc)
    assert validated.receipt_id == receipt.receipt_id
    assert validated.verification_hash == receipt.verification_hash


def test_authorization_receipt_tamper_detection():
    """Verify that modifying receipt fields invalidates the verification hash."""
    receipt = create_authorization_receipt(
        operator="test-operator",
        specialist_id="cops-incident-responder",
        action_type="host-isolation",
        target_scope=["server-01.corp"],
        allowed_operations=["isolate"],
    )
    doc = receipt.to_dict()

    # Tamper with scope
    doc["target_scope"] = ["server-99.corp"]
    with pytest.raises(AuthorizationError, match="hash mismatch"):
        validate_receipt_document(doc)


def test_interactive_authorization_approved():
    """Verify interactive authorization prompt succeeds when operator types 'APPROVE'."""
    buffer = io.StringIO()
    receipt = request_interactive_authorization(
        specialist_id="cops-pentest-specialist",
        action_type="vulnerability-scan",
        target_scope=["test.corp"],
        allowed_operations=["passive-review"],
        input_func=lambda _: "APPROVE",
        output_stream=buffer,
    )
    assert isinstance(receipt, AuthorizationReceipt)
    assert receipt.specialist_id == "cops-pentest-specialist"
    assert "Authorization granted" in buffer.getvalue()


def test_interactive_authorization_denied():
    """Verify interactive authorization fails when operator aborts."""
    buffer = io.StringIO()
    with pytest.raises(AuthorizationDeniedError, match="aborted by operator"):
        request_interactive_authorization(
            specialist_id="cops-pentest-specialist",
            action_type="vulnerability-scan",
            target_scope=["test.corp"],
            allowed_operations=["passive-review"],
            input_func=lambda _: "no",
            output_stream=buffer,
        )


def test_non_interactive_without_receipt_fails_closed():
    """Verify that ensure_authorization fails closed if interactive=False and no receipt given."""
    with pytest.raises(AuthorizationRequiredError, match="Authorization required"):
        ensure_authorization(
            specialist_id="cops-pentest-specialist",
            action_type="vulnerability-scan",
            target_scope=["test.corp"],
            allowed_operations=["passive-review"],
            receipt_path=None,
            interactive=False,
        )


def test_cli_routing_and_listing(capsys):
    """Verify CLI commands run without error."""
    # Test list command
    ret = cli_main(["list"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "cops-pentest-specialist" in out
    assert "cops-sentinel-kql-engineer" in out

    # Test info command
    ret = cli_main(["info", "cops-sentinel-kql-engineer"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "Primary Plugin" in out

    # Test route command
    ret = cli_main(["route", "How do I optimize KQL in Sentinel?", "--json"])
    assert ret == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["primary_profile"]["id"] == "cops-sentinel-kql-engineer"
