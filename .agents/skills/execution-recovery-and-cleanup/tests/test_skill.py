"""Tests for execution-recovery-and-cleanup contributor skill."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from cops.execution import CleanupManager, SideEffectLedger


class TestExecutionRecoveryAndCleanupSkill(unittest.TestCase):
    def test_skill_cleanup_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve(strict=True)
            ledger = SideEffectLedger("plan-test-01", "eng-test-01", "worker-skill-01")
            manager = CleanupManager(ledger, "worker-skill-01", workspace_dir=workspace)

            test_file = workspace / "temp_artifact.txt"
            effect = ledger.record_effect(
                step_id="step-skill-1",
                resource_type="file",
                target=str(test_file),
                cleanup_action="delete",
            )
            creation_fd = os.open(
                test_file,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.write(creation_fd, b"transient data")
                ledger.record_created_identity(effect, creation_fd=creation_fd)
            finally:
                os.close(creation_fd)

            receipt = manager.rollback()
            self.assertEqual(receipt.status, "completed")
            self.assertFalse(test_file.exists())
            self.assertEqual(len(receipt.cleaned_effects), 1)


if __name__ == "__main__":
    unittest.main()
