import subprocess
import sys
import unittest
from pathlib import Path


class PlaybackTest(unittest.TestCase):
    def test_manifest_playback(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, str(root / "scripts/run_playback.py")], cwd=root, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status": "passed"', result.stdout)


if __name__ == "__main__":
    unittest.main()
