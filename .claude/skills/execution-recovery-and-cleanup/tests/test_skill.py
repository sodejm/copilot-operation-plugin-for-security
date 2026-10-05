"""Tests for execution-recovery-and-cleanup contributor skill."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cops.execution import CleanupManager, SideEffectLedger


class TestExecutionRecoveryAndCleanupSkill(unittest.TestCase):
    def test_skill_cleanup_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            ledger = SideEffectLedger("plan-test-01", "eng-test-01", "worker-skill-01")
            manager = CleanupManager(ledger, "worker-skill-01", workspace_dir=workspace)

            test_file = workspace / "temp_artifact.txt"
            test_file.write_text("transient data", encoding="utf-8")

            ledger.record_effect(
                step_id="step-skill-1",
                resource_type="file",
                target=str(test_file),
                cleanup_action="delete",
            )

            receipt = manager.rollback()
            self.assertEqual(receipt.status, "completed")
            self.assertFalse(test_file.exists())
            self.assertEqual(len(receipt.cleaned_effects), 1)


if __name__ == "__main__":
    unittest.main()
