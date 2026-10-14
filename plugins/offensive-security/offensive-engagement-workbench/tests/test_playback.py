"""Focused tests for the inert engagement playback."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from offensive_engagement_workbench.playback import (  # noqa: E402
    DispatchResult,
    PlaybackError,
    run_playback,
)

EXPECTED_RESULT = {
    "engagement_id": "eng-synthetic-e03",
    "mode": "planning",
    "network_requests": 0,
    "operations_count": 1,
    "status": "passed",
    "target": "10.100.0.10",
}
EXPECTED_ARTIFACTS = {
    "action-plan.json",
    "engagement.json",
    "execution-evidence.json",
    "handoff.json",
    "inert-observation.json",
    "playback-result.json",
}


class CorruptDispatcher:
    """Return well-formed but semantically unsafe observation data."""

    def dispatch(self, payload: dict[str, object]) -> DispatchResult:
        observation = {
            "dispatcher": "local-inert",
            "engagement_id": payload["engagement_id"],
            "mode": payload["mode"],
            "network_requests": 1,
            "operation_ids": ["step-01-execute"],
            "operations_count": 1,
            "target": payload["target"],
        }
        stdout = (json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return DispatchResult(("corrupt-dispatcher",), 0, stdout, b"")


class TestEngagementPlayback(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = PACKAGE_ROOT / "fixtures" / "synthetic" / "engagement.json"

    def _run(self, output_dir: Path) -> dict[str, object]:
        return run_playback(
            self.manifest,
            output_dir=output_dir,
            tool_versions={"python3": "3.11.9"},
            root=REPO_ROOT,
        )

    def test_playback_writes_validated_artifacts_and_hashes_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            result = self._run(output_dir)

            self.assertEqual(result, EXPECTED_RESULT)
            self.assertEqual({path.name for path in output_dir.iterdir()}, EXPECTED_ARTIFACTS)
            observation = json.loads((output_dir / "inert-observation.json").read_text())
            evidence = json.loads((output_dir / "execution-evidence.json").read_text())
            expected_stdout = (json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self.assertEqual(
                evidence["stdout_sha256"],
                f"sha256:{hashlib.sha256(expected_stdout).hexdigest()}",
            )
            self.assertEqual(evidence["stderr_sha256"], f"sha256:{hashlib.sha256(b'').hexdigest()}")
            handoff = json.loads((output_dir / "handoff.json").read_text())
            self.assertEqual(handoff["status"], "proposed")
            self.assertEqual(handoff["approval_status"], "pending")

    def test_rerun_replaces_known_artifacts_and_preserves_unknown_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            first = self._run(output_dir)
            (output_dir / "action-plan.json").write_text("corrupt", encoding="utf-8")
            sentinel = output_dir / "operator-note.txt"
            sentinel.write_text("preserve me", encoding="utf-8")

            second = self._run(output_dir)

            self.assertEqual(second, first)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me")
            self.assertIsInstance(json.loads((output_dir / "action-plan.json").read_text()), dict)

    def test_playback_reports_validated_manifest_and_requested_target(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["engagement_id"] = "eng-custom-planning"
        target = "k8s-api.internal"

        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            result = run_playback(
                manifest,
                output_dir=output_dir,
                tool_versions={"python3": "3.11.9"},
                target=target,
                root=REPO_ROOT,
            )

            self.assertEqual(result["engagement_id"], manifest["engagement_id"])
            self.assertEqual(result["mode"], manifest["mode"])
            self.assertEqual(result["target"], target)
            observation = json.loads((output_dir / "inert-observation.json").read_text())
            self.assertEqual(observation["engagement_id"], manifest["engagement_id"])
            self.assertEqual(observation["mode"], manifest["mode"])
            self.assertEqual(observation["target"], target)

    def test_semantic_failure_removes_stale_success_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            self._run(output_dir)

            with self.assertRaisesRegex(PlaybackError, "semantic validation"):
                run_playback(
                    self.manifest,
                    output_dir=output_dir,
                    tool_versions={"python3": "3.11.9"},
                    root=REPO_ROOT,
                    dispatcher=CorruptDispatcher(),
                )

            self.assertFalse((output_dir / "playback-result.json").exists())


if __name__ == "__main__":
    unittest.main()
