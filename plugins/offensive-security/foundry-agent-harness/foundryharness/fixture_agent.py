"""Deterministic, isolated agent fixture for local boundary tests.

This process is intentionally not an LLM. It converts a bounded untrusted
TOOL_CALL marker into a proposal; the laboratory applies authorization outside
this process. No proposal made here is evidence of a tool effect.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    for line in sys.stdin:
        request = json.loads(line)
        untrusted_text = request["untrusted_text"]
        marker = "TOOL_CALL:"
        if marker in untrusted_text:
            proposal, _ = json.JSONDecoder().raw_decode(untrusted_text.split(marker, 1)[1].lstrip())
            origin = "untrusted_content"
        else:
            proposal = request["approved_call"]
            origin = "trusted_task"
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
