"""Boundaries for offline plain-language engagement target selection."""

from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
        "verb": "assess",
        "detail": "exposed_services",
        "safe_mode_requested": True,
        "status": "unbound",
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
def test_requested_verb_is_preserved_as_unbound_intent(engagement: dict[str, object], verb: str) -> None:
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
    changed["window"]["authorized_until_utc"] = (
        (  # type: ignore[index]
            datetime.now(UTC) - timedelta(seconds=1)
        )
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
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
        "Can you assess 10.0.0.5 safely?",
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


def test_ascii_case_variation_selects_exact_target(engagement: dict[str, object]) -> None:
    unselected = copy.deepcopy(engagement)
    unselected["scope"]["included_targets"] = ["wiki"]  # type: ignore[index]
    unselected["metadata"] = {}
    result = resolve_engagement_goal(goal="ASSESS WIKI.", engagement=unselected)
    assert result["resolution"]["targets"] == ["wiki"]


@pytest.mark.parametrize("lookalike", ["wiKi", "wıkı", "wİkİ"])
def test_unicode_lookalike_cannot_select_ascii_target(engagement: dict[str, object], lookalike: str) -> None:
    unselected = copy.deepcopy(engagement)
    unselected["scope"]["included_targets"] = ["wiki"]  # type: ignore[index]
    unselected["metadata"] = {}
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=f"Assess {lookalike}.", engagement=unselected)
    assert error.value.code == "missing_target_selection"


def test_unicode_lookalike_cannot_select_via_engagement_metadata(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["wiki"]  # type: ignore[index]
    changed["metadata"]["goal_selection"]["target"] = "wiKi"  # type: ignore[index]
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=changed)
    assert error.value.code == "selection_out_of_scope"


@pytest.mark.parametrize(
    ("goal", "other_target"),
    [
        ("Assess 10.0.0.5.", "assess"),
        ("Can you assess the selected endpoint?", "you"),
        ("Assess 10.0.0.5 for exposed services.", "services"),
    ],
)
def test_request_framing_and_detail_cannot_select_another_target(
    engagement: dict[str, object], goal: str, other_target: str
) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"].append(other_target)  # type: ignore[index]
    result = resolve_engagement_goal(goal=goal, engagement=changed)
    assert result["resolution"]["targets"] == ["10.0.0.5"]


def test_excluded_target_in_request_verb_does_not_block_explicit_target(
    engagement: dict[str, object],
) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["excluded_targets"].append("assess")  # type: ignore[index]
    result = resolve_engagement_goal(goal="Assess 10.0.0.5.", engagement=changed)
    assert result["resolution"]["targets"] == ["10.0.0.5"]


def test_request_can_select_target_named_like_verb(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"].append("assess")  # type: ignore[index]
    changed["metadata"] = {}
    result = resolve_engagement_goal(goal="Assess assess.", engagement=changed)
    assert result["resolution"]["targets"] == ["assess"]


def test_polite_question_selects_recorded_target(engagement: dict[str, object]) -> None:
    result = resolve_engagement_goal(goal="Can you assess the selected endpoint?", engagement=engagement)
    assert result["resolution"]["targets"] == ["10.0.0.5"]
    assert result["coverage"]["status"] == "not_assessed"


def test_duplicate_scope_representations_are_one_target(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["10.0.0.5", "api.internal", "API.INTERNAL"]  # type: ignore[index]
    changed["metadata"] = {}
    result = resolve_engagement_goal(goal="Assess api.internal.", engagement=changed)
    assert result["resolution"]["targets"] == ["api.internal"]


def test_scope_limit_precedes_intake_validation(engagement: dict[str, object], monkeypatch) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["10.0.0.5"] * 1025  # type: ignore[index]

    def unexpected_validation(_engagement):
        pytest.fail("intake validation ran before the scope-size preflight")

    monkeypatch.setattr("cops.engagement.goals.validate_engagement_intake", unexpected_validation)
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=changed)
    assert error.value.code == "scope_too_large"


def test_scope_limit_precedes_invalid_exclusion_validation(engagement: dict[str, object], monkeypatch) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["10.0.0.5"] * 1025  # type: ignore[index]
    changed["scope"]["excluded_targets"] = "invalid"  # type: ignore[index]

    def unexpected_validation(_engagement):
        pytest.fail("intake validation ran before the scope-size preflight")

    monkeypatch.setattr("cops.engagement.goals.validate_engagement_intake", unexpected_validation)
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess the selected endpoint.", engagement=changed)
    assert error.value.code == "scope_too_large"


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
def test_goal_rejects_unbound_target_or_instruction(engagement: dict[str, object], goal: str) -> None:
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
def test_negated_assessment_cannot_select_a_target(engagement: dict[str, object], goal: str) -> None:
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
def test_target_mention_without_direct_request_needs_input(engagement: dict[str, object], goal: str) -> None:
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
    ("goal", "code"),
    [
        ("Assess 10.0.0.1.", "excluded_target"),
        ("Assess 10.0.0.5 and api.internal.", "ambiguous_targets"),
        ('Assess the selected endpoint; for example, "10.0.0.5".', "non_authoritative_target"),
    ],
)
def test_goal_scope_error_precedes_stale_selection(engagement: dict[str, object], goal: str, code: str) -> None:
    changed = copy.deepcopy(engagement)
    changed["metadata"]["goal_selection"]["target"] = "stale.internal"  # type: ignore[index]
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=changed)
    assert error.value.code == code


@pytest.mark.parametrize(
    "goal",
    ["Assess 10.0.0.0/24 safely.", "Assess the selected endpoint safely."],
)
def test_goal_rejects_selected_network_overlapping_excluded_host(engagement: dict[str, object], goal: str) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["10.0.0.0/24"]  # type: ignore[index]
    changed["metadata"]["goal_selection"]["target"] = "10.0.0.0/24"  # type: ignore[index]
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=changed)
    assert error.value.code == "overlapping_exclusion"


@pytest.mark.parametrize(
    "goal",
    ["Assess api.corp.internal safely.", "Assess the selected endpoint safely."],
)
@pytest.mark.parametrize("exclusion", ["corp.internal", ".CORP.INTERNAL"])
def test_goal_rejects_selected_subdomain_of_excluded_domain(
    engagement: dict[str, object], goal: str, exclusion: str
) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["api.corp.internal"]  # type: ignore[index]
    changed["scope"]["excluded_targets"] = [exclusion]  # type: ignore[index]
    changed["metadata"]["goal_selection"]["target"] = "api.corp.internal"  # type: ignore[index]
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal=goal, engagement=changed)
    assert error.value.code == "overlapping_exclusion"


def test_goal_rejects_normalized_exact_excluded_domain(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["corp.internal"]  # type: ignore[index]
    changed["scope"]["excluded_targets"] = [".CORP.INTERNAL"]  # type: ignore[index]
    changed["metadata"] = {}
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess corp.internal.", engagement=changed)
    assert error.value.code == "excluded_target"


def test_excluded_domain_does_not_match_unrelated_suffix(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["scope"]["included_targets"] = ["api.notcorp.internal"]  # type: ignore[index]
    changed["scope"]["excluded_targets"] = ["corp.internal"]  # type: ignore[index]
    changed["metadata"] = {}
    result = resolve_engagement_goal(goal="Assess api.notcorp.internal.", engagement=changed)
    assert result["resolution"]["targets"] == ["api.notcorp.internal"]


def test_unsupported_detail_recommends_a_retryable_direct_target(engagement: dict[str, object]) -> None:
    changed = copy.deepcopy(engagement)
    changed["metadata"] = {}
    with pytest.raises(GoalResolutionError) as error:
        resolve_engagement_goal(goal="Assess api.internal quickly.", engagement=changed)
    assert error.value.code == "unsupported_goal_detail"
    assert "Assess api.internal safely." in error.value.next_action
    assert resolve_engagement_goal(goal="Assess api.internal safely.", engagement=changed)["resolution"]["targets"] == [
        "api.internal"
    ]


def test_goal_cli_reports_selection_and_unavailable_execution(engagement: dict[str, object], tmp_path) -> None:
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


def test_goal_cli_reports_precise_next_action_for_ambiguity(engagement: dict[str, object], tmp_path) -> None:
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
    binding = result["engagement_binding"]
    assert binding["engagement_id"] == engagement["engagement_id"]
    assert (
        binding["contract_digest"]
        == resolve_engagement_goal(goal="Assess 10.0.0.5.", engagement=engagement)["resolution"]["engagement_binding"][
            "contract_digest"
        ]
    )


def test_goal_cli_redacts_missing_engagement_path_from_structured_failure(tmp_path) -> None:
    engagement_path = tmp_path / "confidential-customer" / "acme.json"
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
    assert result["error"] == {
        "code": "engagement_not_found",
        "message": "Engagement file was not found.",
    }
    assert str(engagement_path) not in output.getvalue()
    assert result["coverage"]["status"] == "not_assessed"


def test_goal_cli_redacts_os_error_from_unreadable_structured_failure(tmp_path, monkeypatch) -> None:
    engagement_path = tmp_path / "confidential-customer" / "acme.json"
    engagement_path.parent.mkdir()
    engagement_path.write_text("{}", encoding="utf-8")
    os_error_detail = f"permission denied while opening {engagement_path}"

    def deny_open(*_args, **_kwargs):
        raise PermissionError(os_error_detail)

    monkeypatch.setattr(Path, "open", deny_open)
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
    assert result["error"] == {
        "code": "engagement_unreadable",
        "message": "Engagement file could not be read as UTF-8 text.",
    }
    assert os_error_detail not in output.getvalue()
    assert str(engagement_path) not in output.getvalue()
    assert result["coverage"]["status"] == "not_assessed"


def test_goal_cli_redacts_json_decoder_detail_from_structured_failure(tmp_path, monkeypatch) -> None:
    engagement_path = tmp_path / "confidential-customer" / "acme.json"
    engagement_path.parent.mkdir()
    engagement_path.write_text("{}", encoding="utf-8")
    parser_detail = "confidential parser detail"

    def fail_decode(*_args, **_kwargs):
        raise json.JSONDecodeError(parser_detail, '{"schema_version":', 18)

    monkeypatch.setattr("cops.engagement.cli.decode_json", fail_decode)
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
    assert result["error"] == {
        "code": "invalid_engagement_json",
        "message": "Engagement JSON could not be decoded.",
    }
    assert parser_detail not in output.getvalue()
    assert str(engagement_path) not in output.getvalue()
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
    assert "engagement_binding" not in result


@pytest.mark.parametrize(
    ("raw", "expected_code"),
    [
        ('{"schema_version":"one","schema_version":"two"}', "invalid_engagement_json"),
        ("x" * (1024 * 1024 + 1), "engagement_too_large"),
    ],
)
def test_goal_cli_rejects_duplicate_keys_and_oversize_json(tmp_path, raw: str, expected_code: str) -> None:
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(raw, encoding="utf-8")
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
    assert exit_code != 0
    assert result["error"]["code"] == expected_code
    assert result["coverage"]["status"] == "not_assessed"
