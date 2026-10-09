"""Step definitions for credential masking and execution evidence capture BDD scenarios."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from cops.execution.evidence import EvidenceRecorder
from cops.execution.redaction import StreamRedactor

scenarios("../../specs/features/credential_evidence.feature")


@pytest.fixture
def cred_context():
    return {}


@given("a stream redactor configured with default patterns")
def given_default_redactor(cred_context):
    cred_context["redactor"] = StreamRedactor()


@given(parsers.parse('a stream redactor configured with known secret "{secret}"'))
def given_secret_redactor(cred_context, secret):
    cred_context["redactor"] = StreamRedactor(known_secrets=[secret])


@when(parsers.parse('redacting the stream text "{text}"'))
def when_redact_text(cred_context, text):
    cred_context["output"] = cred_context["redactor"].redact(text)


@then(parsers.parse('the redacted text contains "{substring}"'))
def then_contains_substring(cred_context, substring):
    assert substring in cred_context["output"]


@then(parsers.parse('the secret "{secret}" is not in the redacted text'))
def then_secret_not_in_output(cred_context, secret):
    assert secret not in cred_context["output"]


@given("an evidence recorder with a temporary workspace")
def given_evidence_recorder_tmp(cred_context):
    tmp = tempfile.mkdtemp(prefix="cops-evidence-test-")
    cred_context["tmp_dir"] = Path(tmp).resolve(strict=True)
    cred_context["recorder"] = EvidenceRecorder(workspace_dir=cred_context["tmp_dir"])


@when(parsers.parse('recording execution output "{output_text}" for step "{step_id}"'))
def when_record_execution(cred_context, output_text, step_id):
    raw_bytes = output_text.encode("utf-8")
    cred_context["recorder"].record_step_output(
        step_id=step_id,
        tool="echo",
        action="print",
        stdout=raw_bytes,
        stderr=b"",
        exit_code=0,
        started_at="2026-10-02T10:00:00Z",
        finished_at="2026-10-02T10:00:01Z",
    )
    cred_context["step_id"] = step_id


@when(parsers.parse('recording execution output with a synthetic credential for step "{step_id}"'))
def when_record_synthetic_credential(cred_context, step_id):
    # Construct a recognizable token only in memory; no usable credential is stored.
    token = "ghp" + "_" + "a1B2c3D4" * 5
    cred_context["synthetic_secret"] = token
    when_record_execution(cred_context, "credential=" + token, step_id)


@then("the synthetic credential is absent from the artifact")
def then_synthetic_credential_absent(cred_context):
    assert cred_context["synthetic_secret"] not in cred_context["artifact_content"]


@then("the recorded artifact is saved to disk")
def then_artifact_saved(cred_context):
    step_id = cred_context["step_id"]
    artifact_path = cred_context["tmp_dir"] / "artifacts" / f"{step_id}_output.txt"
    assert artifact_path.exists()
    cred_context["artifact_content"] = artifact_path.read_text(encoding="utf-8")


@then(parsers.parse('the artifact contains "{substring}"'))
def then_artifact_contains(cred_context, substring):
    assert substring in cred_context["artifact_content"]


@then("at least one evidence hash is generated")
def then_evidence_hashes_generated(cred_context):
    hashes = cred_context["recorder"].get_evidence_hashes()
    assert len(hashes) >= 1
