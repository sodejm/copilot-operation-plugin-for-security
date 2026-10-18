from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from cops.workflows import WorkflowContractError, WorkflowDefinition
from tests.test_workflow_runtime import workflow_document


def _with_optional_binding(
    *, default: Any = ..., condition_source: str | None = None, operator: str = "exists"
) -> dict[str, Any]:
    document = deepcopy(workflow_document())
    optional: dict[str, Any] = {"type": "string", "required": False}
    if default is not ...:
        optional["default"] = default
    document["inputs"]["optional_query"] = optional
    document["stages"][0]["inputs"]["optional_query"] = {
        "type": "string",
        "source": "workflow.input.optional_query",
    }
    if condition_source is not None:
        condition: dict[str, Any] = {"source": condition_source, "operator": operator}
        if operator != "exists":
            condition["value"] = "enabled"
        document["stages"][0]["condition"] = condition
    return document


@pytest.mark.parametrize(
    "document",
    [
        _with_optional_binding(),
        _with_optional_binding(condition_source="workflow.input.query"),
        _with_optional_binding(condition_source="workflow.input.optional_query", operator="eq"),
        _with_optional_binding(condition_source="workflow.input.optional_query", operator="not_eq"),
    ],
)
def test_optional_direct_binding_requires_exact_exists_guard(document: dict[str, Any]) -> None:
    with pytest.raises(WorkflowContractError, match="unguarded_optional_input_binding"):
        WorkflowDefinition.from_dict(document)


@pytest.mark.parametrize(
    "document",
    [
        workflow_document(),
        _with_optional_binding(default="fallback"),
        _with_optional_binding(condition_source="workflow.input.optional_query"),
    ],
)
def test_required_defaulted_and_exactly_guarded_bindings_remain_valid(document: dict[str, Any]) -> None:
    definition = WorkflowDefinition.from_dict(document)

    assert definition.stage("probe")["inputs"]
