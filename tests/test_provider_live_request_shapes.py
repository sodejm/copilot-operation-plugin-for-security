"""The approved digest cannot carry provider-side tools or hidden options."""

from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from cops.evidence.canonical import canonical
from cops.provider_live import ProviderLiveError, _body

_TEXT = "COPS_SYNTHETIC_CANARY_ONLY"
_MODEL = "test-model"
_LIMIT = 32


def _case(provider: str) -> tuple[dict, dict]:
    target_and_body = {
        "openai": (
            "https://api.openai.test/v1/responses",
            {"model": _MODEL, "input": _TEXT, "max_output_tokens": _LIMIT, "store": False, "stream": False},
        ),
        "azure": (
            "https://azure.example.test/openai/v1/responses",
            {"model": _MODEL, "input": _TEXT, "max_output_tokens": _LIMIT, "store": False, "stream": False},
        ),
        "aws": (
            "https://bedrock.example.test/model/test-model/converse",
            {"messages": [{"role": "user", "content": [{"text": _TEXT}]}], "inferenceConfig": {"maxTokens": _LIMIT}},
        ),
        "gcp": (
            "https://vertex.example.test/v1/projects/test-project/locations/us-east1/publishers/google/models/test-model:generateContent",
            {
                "contents": [{"role": "user", "parts": [{"text": _TEXT}]}],
                "generationConfig": {"maxOutputTokens": _LIMIT},
            },
        ),
    }
    target, body = target_and_body[provider]
    case = {
        "provider": provider,
        "model": _MODEL,
        "account_or_project_kind": "project",
        "account_or_project": "test-project",
        "region": "us-east1",
        "request_target": target,
        "request": {"max_output_tokens": _LIMIT},
    }
    return case, body


def _bind(case: dict, body: dict) -> dict:
    bound = deepcopy(case)
    raw = canonical(body)
    bound["request"].update(
        body_canonical_json=raw.decode(),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        body_size_bytes=len(raw),
    )
    return bound


@pytest.mark.parametrize("provider", ["openai", "azure", "aws", "gcp"])
def test_text_only_request_accepts_exact_provider_envelope(provider: str) -> None:
    case, body = _case(provider)
    assert _body(_bind(case, body)) == canonical(body)


@pytest.mark.parametrize("provider", ["openai", "azure", "aws", "gcp"])
def test_even_approved_digest_cannot_add_provider_tools(provider: str) -> None:
    case, body = _case(provider)
    body["tools"] = [{"type": "remote"}]
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        _body(_bind(case, body))


@pytest.mark.parametrize("provider", ["openai", "azure"])
def test_responses_request_rejects_retention_and_model_drift(provider: str) -> None:
    case, body = _case(provider)
    for key, value in (("store", True), ("model", "other-model"), ("max_output_tokens", _LIMIT + 1)):
        changed = dict(body, **{key: value})
        with pytest.raises(ProviderLiveError, match="dispatch denied"):
            _body(_bind(case, changed))


@pytest.mark.parametrize("provider", ["aws", "gcp"])
def test_provider_path_cannot_move_to_unapproved_model_or_project(provider: str) -> None:
    case, body = _case(provider)
    case["request_target"] = case["request_target"].replace("test-model", "other-model")
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        _body(_bind(case, body))
