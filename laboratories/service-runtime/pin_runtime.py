"""Record immutable, root-owned prerequisites from the reviewed base image."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main() -> None:
    if os.getuid() != 0:
        raise SystemExit("Runtime prerequisite pins must be generated during the root build stage")
    executable = shutil.which("git")
    if executable is None:
        raise SystemExit("The reviewed base image must contain Git")
    resolved = Path(executable).resolve(strict=True)
    version = subprocess.run(
        [str(resolved), "--version"], check=True, capture_output=True, text=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()
    if version != "git version 2.47.3":
        raise SystemExit("The reviewed Git version has changed; review the runtime before updating its pin")
    with resolved.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    destination = Path("/opt/cops-runtime/git-prerequisite.json")
    destination.write_text(json.dumps({
        "schema_version": "cops.runtime-prerequisite/v1",
        "tool": "git", "sha256": digest, "version": version,
    }, sort_keys=True) + "\n", encoding="utf-8")
    destination.chmod(0o444)


if __name__ == "__main__":
    main()
