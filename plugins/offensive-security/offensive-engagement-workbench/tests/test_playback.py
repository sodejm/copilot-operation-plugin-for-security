"""Focused tests for the inert engagement playback."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from offensive_engagement_workbench.playback import (  # noqa: E402
    DispatchResult,
    InertSubprocessDispatcher,
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


class SyntheticObservationDispatcher:
    """Return a valid observation with caller-controlled process arguments."""

    def __init__(self, argv: tuple[str, ...]) -> None:
        self.argv = argv

    def dispatch(self, payload: dict[str, object]) -> DispatchResult:
        observation = {
            "dispatcher": "local-inert",
            "engagement_id": payload["engagement_id"],
            "mode": payload["mode"],
            "network_requests": 0,
            "operation_ids": ["step-01-execute"],
            "operations_count": 1,
            "target": payload["target"],
        }
        stdout = (json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return DispatchResult(self.argv, 0, stdout, b"")


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

    def _run_with_reported_argv(
        self,
        output_dir: Path,
        argv: tuple[str, ...],
    ) -> dict[str, object]:
        dispatch_result = SyntheticObservationDispatcher(argv).dispatch(
            {
                "engagement_id": EXPECTED_RESULT["engagement_id"],
                "mode": EXPECTED_RESULT["mode"],
                "target": EXPECTED_RESULT["target"],
            }
        )
        with mock.patch.object(
            InertSubprocessDispatcher,
            "dispatch",
            return_value=dispatch_result,
        ):
            return self._run(output_dir)

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
            self.assertEqual(evidence["dispatcher"], "python-isolated")
            self.assertEqual(evidence["flags"], ["-I"])
            self.assertNotIn("argv", evidence)
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

    def test_untrusted_dispatch_arguments_are_rejected_without_persisting_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            argv = (
                sys.executable,
                "-I",
                "-c",
                "sensitive child program",
                "--api-key=must-not-persist",
            )

            with self.assertRaisesRegex(PlaybackError, "argument shape is not approved"):
                self._run_with_reported_argv(output_dir, argv)

            self.assertFalse((output_dir / "execution-evidence.json").exists())
            self.assertFalse((output_dir / "playback-result.json").exists())
            persisted = "".join(path.read_text(encoding="utf-8") for path in output_dir.iterdir())
            self.assertNotIn("must-not-persist", persisted)
            self.assertNotIn("sensitive child program", persisted)

    def test_non_python_dispatch_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)

            with self.assertRaisesRegex(PlaybackError, "current Python runtime"):
                self._run_with_reported_argv(
                    output_dir,
                    ("other-runtime", "-I", "-c", "ignored"),
                )

            self.assertFalse((output_dir / "execution-evidence.json").exists())

    def test_unapproved_child_program_is_rejected_without_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            forged_program = "sensitive child program"

            with self.assertRaisesRegex(PlaybackError, "child program is not approved"):
                self._run_with_reported_argv(
                    output_dir,
                    (sys.executable, "-I", "-c", forged_program),
                )

            self.assertFalse((output_dir / "execution-evidence.json").exists())
            self.assertFalse((output_dir / "playback-result.json").exists())
            persisted = "".join(path.read_text(encoding="utf-8") for path in output_dir.iterdir())
            self.assertNotIn(forged_program, persisted)

    def test_injected_dispatcher_cannot_claim_python_isolated_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            dispatcher = SyntheticObservationDispatcher((sys.executable, "-I", "-c", "ignored"))

            with self.assertRaisesRegex(PlaybackError, "requires the built-in dispatcher"):
                run_playback(
                    self.manifest,
                    output_dir=output_dir,
                    tool_versions={"python3": "3.11.9"},
                    root=REPO_ROOT,
                    dispatcher=dispatcher,
                )

            self.assertFalse((output_dir / "execution-evidence.json").exists())
            self.assertFalse((output_dir / "playback-result.json").exists())

    def test_missing_or_misplaced_isolation_flag_is_rejected(self) -> None:
        invalid_arguments = (
            (sys.executable, "-c", "ignored"),
            (sys.executable, "-c", "ignored", "-I"),
        )
        for argv in invalid_arguments:
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as directory:
                output_dir = Path(directory)

                with self.assertRaisesRegex(PlaybackError, "place -I immediately"):
                    self._run_with_reported_argv(output_dir, argv)

                self.assertFalse((output_dir / "execution-evidence.json").exists())


if __name__ == "__main__":
    unittest.main()
