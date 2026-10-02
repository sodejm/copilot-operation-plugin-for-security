"""Offline unit gate."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = Path(__file__).resolve().parents[1]
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=f'{ROOT}:{PACKAGE}')
raise SystemExit(subprocess.call([sys.executable, '-m', 'unittest', 'discover', '-s', str(PACKAGE / 'tests')], cwd=ROOT, env=env))
