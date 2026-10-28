"""Deterministic, isolated agent fixture for local boundary tests.

This process is intentionally not an LLM. It converts a bounded untrusted
TOOL_CALL marker into a proposal; the laboratory applies authorization outside
this process. No proposal made here is evidence of a tool effect.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_decoder_spec = importlib.util.spec_from_file_location(
    "cops_fixed_bounded_json", Path(__file__).resolve().with_name("bounded_json.py")
)
if _decoder_spec is None or _decoder_spec.loader is None:
    raise RuntimeError("Fixed bounded JSON decoder is unavailable")
_decoder = importlib.util.module_from_spec(_decoder_spec)
_decoder_spec.loader.exec_module(_decoder)


def main() -> int:
    while line := sys.stdin.buffer.readline(65537):
        try:
            if not line.endswith(b"\n"):
                return 2
            request = _decoder.decode_json(line, max_bytes=65536)
            if not isinstance(request, dict) or set(request) != {"untrusted_text", "approved_call"}:
                return 2
            untrusted_text = request["untrusted_text"]
            if not isinstance(untrusted_text, str) or len(untrusted_text) > 2048:
                return 2
            marker = "TOOL_CALL:"
            if marker in untrusted_text:
                proposal = _decoder.decode_json(
                    untrusted_text.split(marker, 1)[1].strip().encode("utf-8"), max_bytes=8192
                )
                origin = "untrusted_content"
            else:
                proposal = request["approved_call"]
                origin = "trusted_task"
            if (
                not isinstance(proposal, dict)
                or set(proposal) != {"name", "arguments"}
                or not isinstance(proposal["name"], str)
                or not isinstance(proposal["arguments"], dict)
            ):
                return 2
        except (ValueError, UnicodeError, RecursionError):
            return 2
        result = {
            "model_text": "Deterministic fixture proposed a tool call; no effect is implied.",
            "proposed_calls": [{"name": proposal["name"], "arguments": proposal["arguments"]}],
            "proposal_origin": origin,
        }
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
