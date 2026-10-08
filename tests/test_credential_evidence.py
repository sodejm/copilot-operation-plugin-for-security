"""Unit tests for stream redactor, evidence recorder, and credential handling."""

import tempfile
from pathlib import Path

from cops.execution.evidence import EvidenceRecorder
from cops.execution.redaction import StreamRedactor


def test_redactor_masks_bearer_token():
    redactor = StreamRedactor()
    raw = "Authorization: Bearer secret_token_1234567890abcdef"
    redacted = redactor.redact(raw)
    assert "Bearer [REDACTED:TOKEN]" in redacted
    assert "secret_token_1234567890abcdef" not in redacted


def test_redactor_masks_github_token():
    redactor = StreamRedactor()
    raw = "Cloning with ghp_1111222233334444555566667777888899990000"
    redacted = redactor.redact(raw)
    assert "[REDACTED:GITHUB_TOKEN]" in redacted
    assert "ghp_" not in redacted


def test_redactor_masks_aws_key():
    redactor = StreamRedactor()
    raw = "Found AWS access key AKIAIOSFODNN7EXAMPLE in output"
    redacted = redactor.redact(raw)
    assert "[REDACTED:AWS_KEY]" in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted


def test_redactor_masks_private_key():
    redactor = StreamRedactor()
    raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    redacted = redactor.redact(raw)
    assert "[REDACTED:PRIVATE_KEY]" in redacted
    assert "MIIEowIBAAKCAQEA0" not in redacted


def test_redactor_masks_known_engagement_secret():
    redactor = StreamRedactor(known_secrets=["EngagementSuperSecretPassword123!"])
    raw = "Connecting with EngagementSuperSecretPassword123! to host"
    redacted = redactor.redact(raw)
    assert "[REDACTED:SECRET]" in redacted
    assert "EngagementSuperSecretPassword123!" not in redacted


def test_evidence_recorder_creates_redacted_artifacts():
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir).resolve(strict=True)
        recorder = EvidenceRecorder(workspace_dir=workspace)
        raw_output = b"Connecting with Bearer super_secret_long_token_12345678"
        redacted, artifact = recorder.record_step_output(
            step_id="step-001",
            tool="echo",
            action="print",
            stdout=raw_output,
            stderr=b"",
            exit_code=0,
            started_at="2026-10-02T10:00:00Z",
            finished_at="2026-10-02T10:00:01Z",
        )
        assert b"super_secret_long_token_12345678" not in redacted
        assert b"Bearer [REDACTED:TOKEN]" in redacted
        assert artifact.name == "step-001_output.txt"
        assert (workspace / "artifacts" / "step-001_output.txt").exists()
        assert len(recorder.get_evidence_hashes()) == 1
