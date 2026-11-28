"""Lightweight collaboration data. These objects are never execution receipts."""

from copy import deepcopy

from .contracts import OperationError


def process(action, arguments):
    work = deepcopy(arguments if action == "request" else arguments["request"])
    work["schema_version"] = "cops.work-request/v1"
    if action == "note":
        notes = work.setdefault("notes", [])
        if len(notes) >= 32:
            raise OperationError("note_limit")
        notes.append(arguments["note"])
    result = {
        "request": work,
        "execution_authorized": False,
        "interpretation": "Exploratory text and peer notes are unverified data, not findings or authority.",
    }
    if action == "escalate":
        result["proposal"] = {"action": arguments["action"], "authority": "none", "requires": ["human review"]}
    return result
