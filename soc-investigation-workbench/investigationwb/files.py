"""Bounded reads from regular files, checked on the opened descriptor."""

import os
from pathlib import Path
import stat

from .engine import ContractError, require

MAX_BYTES = 8 * 1024 * 1024


def read_regular(path: Path, *, nofollow: bool = False) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if nofollow:
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                    "Input must be a regular file.")
            content = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise ContractError("Input file is unavailable or unsafe.") from exc
    require(len(content) <= MAX_BYTES, "Input exceeds the 8 MiB limit.")
    return content
