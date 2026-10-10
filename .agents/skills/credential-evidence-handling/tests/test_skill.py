"""Tests for credential-evidence-handling contributor skill."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from cops.execution import EvidenceContext, EvidenceRecorder, StreamRedactor


class TestCredentialEvidenceSkill(unittest.TestCase):
    def test_skill_redaction_flow(self):
        redactor = StreamRedactor()
        redacted = redactor.redact("Bearer abcdef1234567890deadbeef")
        self.assertIn("Bearer [REDACTED:TOKEN]", redacted)

    def test_skill_evidence_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = EvidenceRecorder(
                workspace_dir=Path(tmp).resolve(strict=True),
                context=EvidenceContext(
                    plan_id="skill-test-plan",
                    plan_digest=hashlib.sha256(b"skill-test-plan").hexdigest(),
                    authorization_id="skill-test-authorization",
                    engagement_id="skill-test-engagement",
                    worker_identity="skill-test-worker",
                    target="example.test",
                ),
            )
            recorder.record_step_output(
                step_id="step-1",
                tool="echo",
                tool_version="1.0.0",
                action="print",
                stdout=b"hello test",
                stderr=b"",
                exit_code=0,
                started_at="2026-10-02T10:00:00Z",
                finished_at="2026-10-02T10:00:01Z",
            )
            hashes = recorder.get_evidence_hashes()
            self.assertEqual(len(hashes), 1)


if __name__ == "__main__":
    unittest.main()
