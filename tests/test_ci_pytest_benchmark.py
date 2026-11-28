"""Check the benchmark's execution evidence contract with synthetic reports."""

import pytest

from scripts.agent.benchmark_pytest import compare, validate_part

NODE = "tests/test_sample.py::test_example[value]"


def report(phase, outcome="passed", skip_reason=None):
    return {
        "nodeid": NODE,
        "phase": phase,
        "outcome": outcome,
        "skip_reason": skip_reason,
        "xfail_reason": None,
        "seconds": 0.25,
    }


def evidence(*reports, exit_code=0):
    return {"exit_code": exit_code, "collections": {"serial": [NODE]}, "reports": reports}


def test_accepts_exact_outcomes_even_if_worker_reports_arrive_in_different_order():
    serial = evidence(report("setup"), report("call"), report("teardown"))
    parallel = evidence(report("teardown"), report("setup"), report("call"))
    parallel["collections"] = {"gw0": [NODE], "gw1": [NODE]}
    reference, durations = validate_part(serial, 0)
    candidate, _ = validate_part(parallel, 2)
    compare(reference, candidate)
    assert durations == {NODE: 0.75}


@pytest.mark.parametrize(
    ("reports", "message"),
    [
        ([report("setup"), report("call")], "incomplete execution"),
        ([report("setup"), report("teardown")], "unexpected call phase"),
        ([report("setup"), report("call"), report("call")], "unexpected or repeated report"),
    ],
)
def test_rejects_incomplete_or_duplicate_reports(reports, message):
    with pytest.raises(ValueError, match=message):
        validate_part(evidence(*reports), 0)


def test_rejects_changed_skip_reason():
    reference, _ = validate_part(evidence(report("setup", "skipped", "first reason"), report("teardown")), 0)
    candidate, _ = validate_part(evidence(report("setup", "skipped", "different reason"), report("teardown")), 0)
    with pytest.raises(ValueError, match="execution drift"):
        compare(reference, candidate)


def test_compares_subtest_outcomes_without_counting_their_duration_twice():
    reference_case = evidence(
        report("setup"),
        dict(report("call"), subtest="first"),
        dict(report("call"), subtest="second"),
        report("call"),
        report("teardown"),
    )
    changed_case = evidence(
        report("setup"),
        dict(report("call"), subtest="first"),
        dict(report("call", "skipped", "unavailable"), subtest="second"),
        report("call"),
        report("teardown"),
    )
    reference, durations = validate_part(reference_case, 0)
    candidate, _ = validate_part(changed_case, 0)
    assert durations == {NODE: 0.75}
    with pytest.raises(ValueError, match="execution drift"):
        compare(reference, candidate)


def test_rejects_a_failed_teardown():
    with pytest.raises(ValueError, match="pytest failed"):
        validate_part(evidence(report("setup"), report("call"), report("teardown", "failed"), exit_code=1), 0)
