import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PACKAGE_ROOT / "fixtures" / "synthetic"
PLAYBACK_MANIFEST = PACKAGE_ROOT / "scripts" / "playback" / "manifest.json"


def _write_contract(path: Path, scope_manifest: Path) -> None:
    contract = json.loads(PLAYBACK_MANIFEST.read_text(encoding="utf-8"))
    contract["scope_manifest"] = str(scope_manifest)
    path.write_text(json.dumps(contract), encoding="utf-8")


def _run_playback(manifest: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(PACKAGE_ROOT / "scripts" / "run_playback.py")]
    if manifest is not None:
        command.extend(("--manifest", str(manifest)))
    return subprocess.run(
        command,
        cwd=PACKAGE_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _symlink_or_skip(
    test_case: unittest.TestCase,
    target: Path,
    link: Path,
    *,
    target_is_directory: bool,
) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        test_case.skipTest(f"symbolic links are unavailable: {exc}")


class PlaybackTest(unittest.TestCase):
    def test_manifest_playback(self):
        result = _run_playback()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status": "passed"', result.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_unrelated_fifo_is_not_staged(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            fixture = work / "fixture"
            shutil.copytree(FIXTURE_ROOT, fixture)
            os.mkfifo(fixture / "unrelated.fifo")
            contract = work / "manifest.json"
            _write_contract(contract, fixture / "scope.json")

            result = _run_playback(contract)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"status": "passed"', result.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_unrelated_symlink_tree_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            fixture = work / "fixture"
            shutil.copytree(FIXTURE_ROOT, fixture)
            unrelated = work / "unrelated"
            unrelated.mkdir()
            os.mkfifo(unrelated / "blocking.fifo")
            _symlink_or_skip(self, unrelated, fixture / "unrelated-link", target_is_directory=True)
            contract = work / "manifest.json"
            _write_contract(contract, fixture / "scope.json")

            result = _run_playback(contract)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"status": "passed"', result.stdout)

    def test_declared_source_through_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            fixture = work / "fixture"
            shutil.copytree(FIXTURE_ROOT, fixture)
            outside = work / "outside"
            outside.mkdir()
            shutil.copy2(fixture / "azure_resource_graph.json", outside)
            _symlink_or_skip(self, outside, fixture / "linked", target_is_directory=True)
            scope_path = fixture / "scope.json"
            scope = json.loads(scope_path.read_text(encoding="utf-8"))
            scope["sources"][0]["path"] = "linked/azure_resource_graph.json"
            scope_path.write_text(json.dumps(scope), encoding="utf-8")
            contract = work / "manifest.json"
            _write_contract(contract, scope_path)

            result = _run_playback(contract)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("playback input gate: source could not be safely opened", result.stderr)


if __name__ == "__main__":
    unittest.main()
