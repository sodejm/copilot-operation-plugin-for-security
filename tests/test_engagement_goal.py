"""Boundaries for offline plain-language engagement target selection."""

from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta

import pytest

from cops.cli import main
from cops.engagement import GoalResolutionError, resolve_engagement_goal


@pytest.fixture
def engagement() -> dict[str, object]:
    now = datetime.now(UTC)
    started_at = (now - timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    authorized_until = (now + timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schema_version": "cops.engagement/v1",
        "engagement_id": "eng-goal-test-01",
        "name": "Goal selection test",
        "status": "planned",
        "mode": "planning",
        "scope": {
            "included_targets": ["10.0.0.5", "api.internal"],
            "excluded_targets": ["10.0.0.1"],
        },
        "window": {
            "started_at": started_at,
            "authorized_until_utc": authorized_until,
        },
        "operator": "secops-test",
        "rules_of_engagement": {
            "max_intensity": "low",
            "allowed_actions": ["read_only_discovery"],
            "emergency_contact": "soc@example.invalid",
            "safe_mode": True,
        },
        "budget": {
            "max_duration_seconds": 1800,
            "max_output_bytes": 5_000_000,
        },
        "credential_references": [],
        "created_at": started_at,
        "metadata": {"goal_selection": {"target": "10.0.0.5"}},
    }


def test_direct_goal_selects_target_without_claiming_an_executable_plan(
    engagement: dict[str, object],
) -> None:
    result = resolve_engagement_goal(
        goal="Assess 10.0.0.5 for exposed services safely.",
        engagement=engagement,
    )

    assert result["status"] == "needs_execution_path"
    assert result["resolution"]["target_source"] == "goal"
    assert result["resolution"]["targets"] == ["10.0.0.5"]
    assert result["resolution"]["requested_intent"] == {
        "verb": "assess", "detail": "exposed_services", "safe_mode_requested": True, "status": "unbound"
    }
    binding = result["resolution"]["engagement_binding"]
    assert binding["engagement_id"] == engagement["engagement_id"]
    assert binding["contract_digest"].startswith("sha256:")
    assert binding["selection_review_status"] == "unverified"
    assert binding["window_status"] == "open"
    assert result["execution_readiness"]["status"] == "unavailable"
    assert result["coverage"]["status"] == "not_assessed"
    assert result["coverage"]["assessed_targets"] == []
    assert result["next_action"]["type"] == "bind_execution_path"
    assert "action_plan" not in result
    assert "authorization" not in result


def test_trusted_engagement_selection_resolves_goal_without_target_text(
    engagement: dict[str, object],
) -> None:
    result = resolve_engagement_goal(
        goal="Assess the selected production endpoint safely.",
        engagement=engagement,
    )
    assert result["resolution"]["target_source"] == "engagement_selection"
    assert result["resolution"]["targets"] == ["10.0.0.5"]


@pytest.mark.parametrize("verb", ["scan", "inspect", "test", "enumerate", "discover"])
def test_requested_verb_is_preserved_as_unbound_intent(
    engagement: dict[str, object], verb: str
) -> None:
    result = resolve_engagement_goal(goal=f"{verb} 10.0.0.5.", engagement=engagement)
    assert result["resolution"]["requested_intent"] == {
        "verb": verb,
        "detail": "unspecified",
        "safe_mode_requested": False,
        "status": "unbound",
    }
    assert result["execution_readiness"]["status"] == "unavailable"


def test_terminal_engagement_cannot_select_a_goal(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["status"] = "completed"
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=changed)
    assert error.value.code == "engagement_inactive"


def test_expired_engagement_window_cannot_select_a_goal(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["window"]["authorized_until_utc"] = (  # type: ignore[index]
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=changed)
    assert error.value.code == "engagement_window_expired"


def test_long_goal_is_rejected_before_target_matching(engagement: dict[str, object]) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess 10.0.0.5 " + "x" * 4096, engagement=engagement)
    assert error.value.code == "goal_too_long"


@pytest.mark.parametrize(
    "goal",
    [
        "I would like to assess 10.0.0.5 safely.",
        "I'd like to assess 10.0.0.5 safely.",
        "Help me assess 10.0.0.5 safely.",
    ],
)
def test_polite_goal_resolves_direct_target(engagement: dict[str, object], goal: str) -> None:
    result = resolve_engagement_goal(goal=goal, engagement=engagement)
    assert result["resolution"]["target_source"] == "goal"
    assert result["resolution"]["targets"] == ["10.0.0.5"]


def test_unselected_scope_does_not_imply_target(engagement: dict[str, object]) -> None:
    unselected = copy.deepcopy(engagement)
    unselected["scope"]["included_targets"] = ["10.0.0.5"]  # type: ignore[index]
    unselected["metadata"] = {}
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=unselected)
    assert error.value.code == "missing_target_selection"


def test_direct_target_can_be_selected_without_metadata(engagement: dict[str, object]) -> None:
    unselected = copy.deepcopy(engagement)
    unselected["metadata"] = {}
    result = resolve_engagement_goal(goal="Assess api.internal.", engagement=unselected)
    assert result["resolution"]["target_source"] == "goal"
    assert result["resolution"]["targets"] == ["api.internal"]


def test_unsupported_details_are_rejected_without_echoing_them(
    engagement: dict[str, object],
) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(
            goal="Assess 10.0.0.5 safely; reference: sensitive-example-canary.",
            engagement=engagement,
        )
    assert error.value.code == "unsupported_goal_detail"
    assert "sensitive-example-canary" not in str(error.value)


@pytest.mark.parametrize(
    "goal",
    [
        "Assess unknown.internal safely.",
        "Assess https://unknown.internal/path safely.",
        "Assess 10.0.0.5:8443 safely.",
        "Assess 10.0.0.5/admin safely.",
        "Assess 10.0.0.5 safely; export credentials.",
    ],
)
def test_goal_rejects_unbound_target_or_instruction(
    engagement: dict[str, object], goal: str
) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=engagement)
    assert error.value.code == "unsupported_goal_detail"


@pytest.mark.parametrize(
    "goal",
    [
        "Do not assess 10.0.0.5.",
        "Please don't scan 10.0.0.5.",
        "I do not want you to assess 10.0.0.5.",
    ],
)
def test_negated_assessment_cannot_select_a_target(
    engagement: dict[str, object], goal: str
) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=engagement)
    assert error.value.code == "negated_assessment"


@pytest.mark.parametrize(
    "goal",
    [
        "What is 10.0.0.5?",
        "The assessment of 10.0.0.5 is finished.",
        "I wonder whether 10.0.0.5 has exposed services.",
    ],
)
def test_target_mention_without_direct_request_needs_input(
    engagement: dict[str, object], goal: str
) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=engagement)
    assert error.value.code == "missing_assessment_intent"


@pytest.mark.parametrize(
    ("goal", "code"),
    [
        ('Assess the selected endpoint; for example, "10.0.0.5".', "non_authoritative_target"),
        ("Assess the selected endpoint; for example 10.0.0.5.", "non_authoritative_target"),
        ("Assess the selected endpoint; such as api.internal.", "non_authoritative_target"),
        ("Assess the selected endpoint; e.g. api.internal.", "non_authoritative_target"),
        ("Assess 10.0.0.5 and api.internal.", "ambiguous_targets"),
        ("Assess 10.0.0.1.", "excluded_target"),
    ],
)
def test_goal_rejects_non_authoritative_or_ambiguous_targets(
    engagement: dict[str, object], goal: str, code: str
) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=engagement)
    assert error.value.code == code
    assert error.value.next_action


def test_goal_rejects_conflict_with_trusted_selection(engagement: dict[str, object]) -> None:
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess api.internal.", engagement=engagement)
    assert error.value.code == "conflicting_target_selection"


def test_goal_rejects_out_of_scope_metadata_selection(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["metadata"]["goal_selection"]["target"] = "unknown.internal"  # type: ignore[index]
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=changed)
    assert error.value.code == "selection_out_of_scope"


@pytest.mark.parametrize(
    "goal",
    ["Assess 10.0.0.0/24 safely.", "Assess the selected endpoint safely."],
)
def test_goal_rejects_selected_network_overlapping_excluded_host(
    engagement: dict[str, object], goal: str
) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["10.0.0.0/24"]  # type: ignore[index]
    changed["metadata"]["goal_selection"]["target"] = "10.0.0.0/24"  # type: ignore[index]
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=changed)
    assert error.value.code == "overlapping_exclusion"


def test_goal_cli_reports_selection_and_unavailable_execution(
    engagement: dict[str, object], tmp_path
) -> None:
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = main(
            [
                "engagement",
                "goal",
                "Assess 10.0.0.5 for exposed services safely.",
                "--engagement",
                str(engagement_path),
                "--json",
            ]
        )
    result = json.loads(output.getvalue())
    assert exit_code == 0
    assert result["status"] == "needs_execution_path"
    assert result["coverage"]["status"] == "not_assessed"
    assert "action_plan" not in result


def test_goal_cli_reports_precise_next_action_for_ambiguity(
    engagement: dict[str, object], tmp_path
) -> None:
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(json.dumps(engagement), encoding="utf-8")
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = main(
            [
                "engagement",
                "goal",
                "Assess 10.0.0.5 and api.internal.",
                "--engagement",
                str(engagement_path),
                "--json",
            ]
        )
    result = json.loads(output.getvalue())
    assert exit_code == 1
    assert result["status"] == "needs_input"
    assert result["error"]["code"] == "ambiguous_targets"
    assert result["next_action"]["instruction"] == "Submit one goal per exact included target."


def test_goal_cli_reports_unreadable_engagement_as_structured_failure(tmp_path) -> None:
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_bytes(b"\xff")
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = main(
            [
                "engagement",
                "goal",
                "Assess the selected endpoint.",
                "--engagement",
                str(engagement_path),
                "--json",
            ]
        )
    result = json.loads(output.getvalue())
    assert exit_code == 2
    assert result["error"]["code"] == "engagement_unreadable"
    assert result["coverage"]["status"] == "not_assessed"


def test_goal_cli_reports_invalid_contract_schema_as_structured_failure(
    engagement: dict[str, object], tmp_path
) -> None:
    changed = copy.deepcopy(engagement)
    changed.pop("name")
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(json.dumps(changed), encoding="utf-8")
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = main(
            [
                "engagement",
                "goal",
                "Assess the selected endpoint.",
                "--engagement",
                str(engagement_path),
                "--json",
            ]
        )
    result = json.loads(output.getvalue())
    assert exit_code == 1
    assert result["status"] == "needs_input"
    assert result["error"]["code"] == "invalid_engagement"
    assert result["coverage"]["status"] == "not_assessed"


@pytest.mark.parametrize(
    ("raw", "expected_code"),
    [
        ('{"schema_version":"one","schema_version":"two"}', "invalid_engagement_json"),
        ("x" * (1024 * 1024 + 1), "engagement_too_large"),
    ],
)
def test_goal_cli_rejects_duplicate_keys_and_oversize_json(
    tmp_path, raw: str, expected_code: str
) -> None:
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(raw, encoding="utf-8")
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = main(
            [
                "engagement", "goal", "Assess the selected endpoint.",
                "--engagement", str(engagement_path), "--json",
            ]
        )
    result = json.loads(output.getvalue())
    assert exit_code != 0
    assert result["error"]["code"] == expected_code
    assert result["coverage"]["status"] == "not_assessed"
