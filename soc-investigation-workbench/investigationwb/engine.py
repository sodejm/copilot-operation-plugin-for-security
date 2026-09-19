"""Validate case snapshots and select explainable, bounded next steps."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from hashlib import sha256
import json
import re
from typing import Any

Document = dict[str, Any]
OUTCOMES = {"supports", "refutes", "empty", "unavailable", "inconclusive"}
SURFACES = {"sentinel_analytics", "sentinel_data_lake", "defender_advanced_hunting"}
ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")


class ContractError(ValueError):
    """A public, constant message that never includes input values."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def fields(value: Any, keys: str) -> None:
    require(type(value) is dict and set(value) == set(keys.split()),
            "Object has missing or unknown fields.")


def alias(value: Any) -> None:
    require(type(value) is str and ID.fullmatch(value) is not None,
            "Expected an opaque lowercase alias, not a raw identifier.")


def prose(value: Any) -> None:
    require(type(value) is str and 0 < len(value) <= 2000,
            "Expected bounded redacted text.")


def integer(value: Any, minimum: int, maximum: int) -> None:
    require(type(value) is int and minimum <= value <= maximum,
            "Integer is outside its allowed range.")


def array(value: Any, maximum: int = 1000) -> None:
    require(type(value) is list and len(value) <= maximum,
            "Expected a bounded list.")


def unique_refs(value: Any, allowed: set[str], nonempty: bool = False) -> None:
    array(value)
    require(all(type(item) is str for item in value), "References must be strings.")
    require(len(value) == len(set(value)) and set(value) <= allowed,
            "Reference is unknown or duplicated.")
    require(not nonempty or bool(value), "At least one reference is required.")


def indexed(values: Any) -> dict[str, Document]:
    array(values)
    result: dict[str, Document] = {}
    for value in values:
        require(type(value) is dict and "id" in value, "Record must have an ID.")
        alias(value["id"])
        require(value["id"] not in result, "Record ID is duplicated.")
        result[value["id"]] = value
    return result


def utc(value: Any) -> datetime:
    require(type(value) is str and
            re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None,
            "Timestamp must be UTC with whole seconds and a Z suffix.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("Timestamp is not a valid date.") from exc


def digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def evidence_content(item: Document) -> Document:
    return {key: value for key, value in item.items() if key != "id"}


def provenance(item: Document) -> tuple[str, str]:
    return item["source"], item["record_ref"]


def _visible(case: Document, results: list[Document]) -> set[str]:
    introduced = {ref for result in case["results"] for ref in result["new_evidence_ids"]}
    initial = {item["id"] for item in case["evidence"]} - introduced
    return initial | {ref for result in results for ref in result["new_evidence_ids"]}


def _ready(step: Document, results: list[Document], visible: set[str]) -> bool:
    done = {result["step_id"]: result for result in results}
    return (step["id"] not in done and set(step["depends_on"]) <= done.keys()
            and set(step["basis"]) <= visible
            and all(done.get(guard["step_id"], {}).get("outcome") in guard["outcomes"]
                    for guard in step["when"]))


def _no_progress(results: list[Document]) -> int:
    stalled = 0
    for result in reversed(results):
        if result["new_evidence_ids"]:
            break
        stalled += 1
    return stalled


def _stop(case: Document, results: list[Document]) -> str | None:
    budget = case["budget"]
    if len(results) >= budget["max_steps"]:
        return "step_budget"
    if sum(result["cost"] for result in results) >= budget["max_cost"]:
        return "cost_budget"
    return "no_progress" if _no_progress(results) >= budget["max_no_progress"] else None


def validate(case: Document) -> Document:
    """Validate full state, including historical eligibility and result semantics."""
    fields(case, "schema_version id scope budget hypotheses entities steps evidence results")
    require(type(case["schema_version"]) is int and case["schema_version"] == 1,
            "Unsupported case schema version.")
    alias(case["id"])
    scope = case["scope"]
    fields(scope, "tenant workspace start end")
    alias(scope["tenant"])
    alias(scope["workspace"])
    start, end = utc(scope["start"]), utc(scope["end"])
    require(start < end, "Case time interval must increase.")
    fields(case["budget"], "max_steps max_cost max_no_progress")
    for value in case["budget"].values():
        integer(value, 1, 10000)

    hypotheses = indexed(case["hypotheses"])
    require(bool(hypotheses), "Case needs hypotheses.")
    for hypothesis in hypotheses.values():
        fields(hypothesis, "id kind statement")
        require(hypothesis["kind"] in ("malicious", "benign"), "Unknown hypothesis kind.")
        prose(hypothesis["statement"])
    require({h["kind"] for h in hypotheses.values()} == {"malicious", "benign"},
            "Include both malicious and benign alternative hypotheses.")
    entities = indexed(case["entities"])
    identities = set()
    for entity in entities.values():
        fields(entity, "id kind key")
        require(entity["kind"] in ("account", "app", "device", "ip", "resource"),
                "Unknown entity kind.")
        require(type(entity["key"]) is str and HASH.fullmatch(entity["key"]) is not None,
                "Entity key must be a case-scoped SHA-256 digest.")
        identity = (entity["kind"], entity["key"])
        require(identity not in identities, "One identity has multiple aliases.")
        identities.add(identity)

    evidence = indexed(case["evidence"])
    sources = set()
    for item in evidence.values():
        fields(item, "id source record_ref scope event_time entities assessments summary")
        alias(item["source"])
        require(type(item["record_ref"]) is str and HASH.fullmatch(item["record_ref"]) is not None,
                "Evidence record reference must be a SHA-256 digest.")
        require(item["scope"] == {"tenant": scope["tenant"], "workspace": scope["workspace"]},
                "Evidence is outside the case scope.")
        require(start <= utc(item["event_time"]) < end, "Evidence is outside the case interval.")
        unique_refs(item["entities"], set(entities), nonempty=True)
        prose(item["summary"])
        array(item["assessments"])
        assessed = set()
        for assessment in item["assessments"]:
            fields(assessment, "hypothesis_id stance reason")
            require(type(assessment["hypothesis_id"]) is str and
                    assessment["hypothesis_id"] in hypotheses, "Assessment hypothesis is unknown.")
            require(assessment["stance"] in ("supports", "refutes"), "Unknown assessment stance.")
            prose(assessment["reason"])
            key = (assessment["hypothesis_id"], assessment["stance"])
            require(key not in assessed, "Assessment is duplicated.")
            assessed.add(key)
        require(provenance(item) not in sources, "Evidence provenance is duplicated.")
        sources.add(provenance(item))

    steps = indexed(case["steps"])
    fingerprints = set()
    for step in steps.values():
        fields(step, "id question hypothesis_ids basis depends_on when query expected value")
        prose(step["question"])
        unique_refs(step["hypothesis_ids"], set(hypotheses), nonempty=True)
        unique_refs(step["basis"], set(evidence))
        unique_refs(step["depends_on"], set(steps))
        array(step["when"])
        guarded = set()
        for guard in step["when"]:
            fields(guard, "step_id outcomes")
            require(type(guard["step_id"]) is str and guard["step_id"] in step["depends_on"],
                    "Branch guard must reference a direct dependency.")
            require(guard["step_id"] not in guarded, "Branch guard is duplicated.")
            guarded.add(guard["step_id"])
            unique_refs(guard["outcomes"], OUTCOMES, nonempty=True)
        query = step["query"]
        fields(query, "hunt_id surface entities start end")
        require(type(query["hunt_id"]) is str and re.fullmatch(r"H\d{2}", query["hunt_id"]) is not None,
                "Hunt reference must name a catalog hunt.")
        require(type(query["surface"]) is str and query["surface"] in SURFACES,
                "Unknown query surface.")
        unique_refs(query["entities"], set(entities), nonempty=True)
        require(start <= utc(query["start"]) < utc(query["end"]) <= end,
                "Query interval is outside the case interval.")
        fingerprint = digest({**query, "entities": sorted(query["entities"])})
        require(fingerprint not in fingerprints, "Hunt request duplicates another step; reuse its result.")
        fingerprints.add(fingerprint)
        fields(step["expected"], "supports refutes empty unavailable inconclusive")
        for meaning in step["expected"].values():
            prose(meaning)
        fields(step["value"], "information_gain urgency impact cost")
        for name in ("information_gain", "urgency", "impact"):
            integer(step["value"][name], 0, 5)
        integer(step["value"]["cost"], 1, 10000)

    # Iterative topological validation avoids recursion limits on adversarial DAGs.
    remaining = set(steps)
    visited: set[str] = set()
    while remaining:
        ready = {key for key in remaining if set(steps[key]["depends_on"]) <= visited}
        require(bool(ready), "Step dependencies contain a cycle.")
        visited |= ready
        remaining -= ready

    results = indexed(case["results"])
    history: list[Document] = []
    done: set[str] = set()
    introduced: set[str] = set()
    # Check all result shapes before _visible or _stop reads history fields.
    for result in results.values():
        fields(result, "id step_id outcome coverage cost evidence_ids new_evidence_ids input_hash")
        require(type(result["step_id"]) is str and result["step_id"] in steps,
                "Result step is unknown.")
        require(type(result["outcome"]) is str and result["outcome"] in OUTCOMES,
                "Unknown result outcome.")
        require(result["coverage"] in ("complete", "partial", "unavailable"), "Unknown coverage.")
        integer(result["cost"], 1, 10000)
        unique_refs(result["evidence_ids"], set(evidence))
        unique_refs(result["new_evidence_ids"], set(result["evidence_ids"]))
        require(not introduced.intersection(result["new_evidence_ids"]),
                "Evidence cannot be introduced twice.")
        introduced.update(result["new_evidence_ids"])
        require(type(result["input_hash"]) is str and HASH.fullmatch(result["input_hash"]) is not None,
                "Result import digest is invalid.")
    for result in results.values():
        step = steps[result["step_id"]]
        require(result["step_id"] not in done, "A completed step cannot run again.")
        require(_stop(case, history) is None, "Result exceeds a stopping budget.")
        require(_ready(step, history, _visible(case, history)), "Result step was not eligible.")
        require(result["cost"] == step["value"]["cost"], "Result cost must match reserved step cost.")
        require(sum(r["cost"] for r in history) + result["cost"] <= case["budget"]["max_cost"],
                "Result exceeds remaining cost budget.")
        require(set(result["evidence_ids"]) <= _visible(case, history) | set(result["new_evidence_ids"]),
                "Result references evidence from a future result.")
        outcome, coverage = result["outcome"], result["coverage"]
        if coverage == "complete" and not result["evidence_ids"]:
            require(outcome == "empty", "Complete coverage without evidence requires an empty outcome.")
        if outcome == "empty":
            require(coverage == "complete" and not result["evidence_ids"],
                    "Empty results require complete coverage and no evidence.")
        elif outcome == "unavailable":
            require(coverage == "unavailable" and not result["evidence_ids"],
                    "Unavailable results cannot establish evidence.")
        else:
            require(coverage != "unavailable", "Unavailable coverage needs an unavailable outcome.")
        if outcome in ("supports", "refutes"):
            require(any(a["stance"] == outcome and a["hypothesis_id"] in step["hypothesis_ids"]
                        for ref in result["evidence_ids"] for a in evidence[ref]["assessments"]),
                    "Result outcome lacks an explicit relevant evidence assessment.")
        for ref in result["new_evidence_ids"]:
            item = evidence[ref]
            require(utc(step["query"]["start"]) <= utc(item["event_time"]) < utc(step["query"]["end"]),
                    "New evidence is outside the step query interval.")
        history.append(result)
        done.add(result["step_id"])
    return case


def import_result(case: Document, incoming: Document) -> Document:
    """Append a validated observation; exact request retries are idempotent."""
    validate(case)
    fields(incoming, "id step_id outcome coverage cost evidence")
    alias(incoming["id"])
    array(incoming["evidence"])
    incoming_hash = digest(incoming)
    for result in case["results"]:
        if result["id"] == incoming["id"]:
            require(result["input_hash"] == incoming_hash, "Replay changed an existing result.")
            return deepcopy(case)
    revised = deepcopy(case)
    by_source = {provenance(item): item for item in revised["evidence"]}
    by_id = {item["id"]: provenance(item) for item in revised["evidence"]}
    refs, new_refs = [], []
    for item in incoming["evidence"]:
        # Validate shape before using provenance, then full semantics with new state.
        fields(item, "id source record_ref scope event_time entities assessments summary")
        alias(item["id"])
        alias(item["source"])
        require(type(item["record_ref"]) is str, "Evidence reference must be a digest.")
        require(item["id"] not in by_id or by_id[item["id"]] == provenance(item),
                "Evidence alias is already assigned to another observation.")
        previous = by_source.get(provenance(item))
        if previous:
            require(evidence_content(previous) == evidence_content(item),
                    "Duplicate provenance has conflicting content.")
            ref = previous["id"]
        else:
            ref = item["id"]
            revised["evidence"].append(deepcopy(item))
            by_source[provenance(item)] = item
            new_refs.append(ref)
        by_id[item["id"]] = provenance(item)
        if ref not in refs:
            refs.append(ref)
    revised["results"].append({key: deepcopy(incoming[key]) for key in
                               ("id", "step_id", "outcome", "coverage", "cost")} |
                              {"evidence_ids": refs, "new_evidence_ids": new_refs,
                               "input_hash": incoming_hash})
    return validate(revised)


def revise(case: Document, steps: list[Document]) -> Document:
    """Replace pending plan, preserving every completed step exactly."""
    validate(case)
    updated = indexed(steps)
    old = indexed(case["steps"])
    for result in case["results"]:
        key = result["step_id"]
        require(updated.get(key) == old[key], "Completed steps are immutable.")
    revised = deepcopy(case)
    revised["steps"] = deepcopy(steps)
    return validate(revised)


def hypothesis_status(case: Document) -> list[Document]:
    observations = []
    for hypothesis in case["hypotheses"]:
        refs: dict[str, list[str]] = {"supports": [], "refutes": []}
        for item in case["evidence"]:
            for assessment in item["assessments"]:
                if assessment["hypothesis_id"] == hypothesis["id"]:
                    refs[assessment["stance"]].append(item["id"])
        status = ("contested" if refs["supports"] and refs["refutes"] else
                  "support_observed" if refs["supports"] else
                  "refutation_observed" if refs["refutes"] else "unresolved")
        observations.append({"id": hypothesis["id"], "status": status, **refs})
    return observations


def next_steps(case: Document) -> Document:
    validate(case)
    reason = _stop(case, case["results"])
    remaining_cost = case["budget"]["max_cost"] - sum(r["cost"] for r in case["results"])
    slots = min(case["budget"]["max_steps"] - len(case["results"]),
                case["budget"]["max_no_progress"] - _no_progress(case["results"]))
    contested = {h["id"] for h in hypothesis_status(case) if h["status"] == "contested"}
    candidates = []
    for step in case["steps"]:
        if _ready(step, case["results"], _visible(case, case["results"])):
            value = step["value"]
            bonus = 3 if contested.intersection(step["hypothesis_ids"]) else 0
            numerator = 3 * value["information_gain"] + 2 * value["urgency"] + value["impact"] + bonus
            candidates.append((Fraction(numerator, value["cost"]), step["id"],
                               {"step_id": step["id"], "score_numerator": numerator,
                                "cost": value["cost"], "contradiction_bonus": bonus,
                                "information_gain": value["information_gain"],
                                "urgency": value["urgency"], "impact": value["impact"]}))
    selected = []
    if reason is None:
        for _, _, candidate in sorted(candidates, key=lambda entry: (-entry[0], entry[1])):
            if candidate["cost"] <= remaining_cost and len(selected) < slots:
                selected.append(candidate)
                remaining_cost -= candidate["cost"]
        if not selected:
            reason = "cost_budget" if candidates else "plan_exhausted_or_blocked"
    return {"state": "needs_review" if reason else "ready", "reason": reason,
            "candidates": selected, "selection": "deterministic_greedy_heuristic"}


def report(case: Document) -> Document:
    validate(case)
    return {"case_id": case["id"], "snapshot_hash": digest(case),
            "hypotheses": hypothesis_status(case), "next": next_steps(case),
            "completed_steps": [r["step_id"] for r in case["results"]],
            "coverage_gaps": [{"step_id": r["step_id"], "coverage": r["coverage"]}
                              for r in case["results"] if r["coverage"] != "complete"],
            "graph": {"entities": [{"id": e["id"], "kind": e["kind"],
                                    "identity_strength": "context_only" if e["kind"] == "ip" else "explicit"}
                                   for e in case["entities"]],
                      "evidence_edges": [{"evidence_id": e["id"], "entity_ids": e["entities"],
                                          "hypothesis_links": [{"id": a["hypothesis_id"], "stance": a["stance"]}
                                                               for a in e["assessments"]]}
                                         for e in case["evidence"]]},
            "limitations": ["Analyst assessments are not independently verified.",
                            "Shared entities establish associations, not causation.",
                            "No automatic case verdict, probability, or live query validation."]}
