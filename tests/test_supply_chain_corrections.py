from __future__ import annotations

import json

import pytest

from cops.assessments import assess

SHA = "a" * 40
HASH = "b" * 64


def report(*artifacts: tuple[str, object]) -> dict:
    return assess(
        "supply_chain",
        [
            {"artifact_id": f"input-{i}", "kind": kind, "content": content}
            for i, (kind, content) in enumerate(artifacts)
        ],
        as_of="2026-10-15T12:00:00Z",
    )


def codes(result: dict) -> set[str]:
    return set(result["finding_codes"].values())


@pytest.mark.parametrize(
    "path,name",
    [
        ("node_modules/demo", "demo"),
        ("node_modules/@example/demo", "@example/demo"),
        ("node_modules/parent/node_modules/demo", "demo"),
    ],
)
def test_npm_advisory_matches_inferred_package_name(path: str, name: str) -> None:
    result = report(
        (
            "package_lock",
            {
                "packages": {
                    path: {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/demo/-/demo.tgz",
                        "integrity": "sha512-synthetic",
                    }
                }
            },
        ),
        ("advisory_fixture", {"advisories": [{"ecosystem": "npm", "package": name, "version": "1.0.0"}]}),
    )
    assert "pinned_advisory_match" in codes(result)


def test_npm_root_and_local_workspace_are_not_registry_packages() -> None:
    result = report(
        (
            "package_lock",
            {
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "node_modules/local": {"resolved": "packages/local", "link": True},
                    "packages/local": {"name": "local", "version": "1.0.0"},
                }
            },
        )
    )
    assert not {"npm_integrity_missing", "npm_registry_resolution"} & codes(result)


@pytest.mark.parametrize(
    "resolved",
    [
        "https://registry.npmjs.org.evil.test/demo.tgz",
        "https://user:synthetic@registry.npmjs.org/demo.tgz",
        "http://registry.npmjs.org/demo.tgz",
    ],
)
def test_registry_identity_is_parsed_without_echoing_url(resolved: str) -> None:
    result = report(
        (
            "package_lock",
            {
                "packages": {
                    "node_modules/demo": {
                        "version": "1.0.0",
                        "resolved": resolved,
                        "integrity": "sha512-synthetic",
                    }
                }
            },
        )
    )
    assert "npm_registry_resolution" in codes(result)
    assert resolved not in json.dumps(result)


def test_multiline_python_hash_lock_matches_normalized_advisory() -> None:
    result = report(
        ("requirements_lock", f"Example_Pkg==1.0.0 \\\n    --hash=sha256:{HASH}  # pinned\n"),
        ("advisory_fixture", {"advisories": [{"ecosystem": "pypi", "package": "example-pkg", "version": "1.0.0"}]}),
    )
    assert "pinned_advisory_match" in codes(result)
    assert "python_dependency_unhashed" not in codes(result)


@pytest.mark.parametrize(
    "entry",
    [
        "demo>=1 --hash=sha256:" + HASH,
        "demo==1 --hash=sha256:not-a-digest",
        "demo==1.* --hash=sha256:" + HASH,
    ],
)
def test_python_exact_hash_pin_is_required(entry: str) -> None:
    assert "python_dependency_unhashed" in codes(report(("requirements_lock", entry)))


def test_ecosystem_prevents_cross_language_advisory_collision() -> None:
    result = report(
        ("requirements_lock", f"demo==1.0.0 --hash=sha256:{HASH}"),
        ("advisory_fixture", {"advisories": [{"ecosystem": "npm", "package": "demo", "version": "1.0.0"}]}),
    )
    assert "pinned_advisory_match" not in codes(result)


def test_python_includes_and_environment_substitution_remain_unknown() -> None:
    result = report(("requirements_lock", "-r hidden.txt\ndemo==${VERSION}\n"))
    assert "python_lock_insufficient_evidence" in codes(result)


def test_quoted_pins_and_local_actions_are_not_false_positives() -> None:
    result = report(
        (
            "github_actions",
            f"""on: push
permissions: read-all
jobs:
  test:
    steps:
      - uses: './.github/actions/check'
      - uses: "actions/checkout@{SHA}"
""",
        )
    )
    assert "action_unpinned" not in codes(result)


@pytest.mark.parametrize("permissions", ["permissions: write-all", "permissions:\n  contents: write"])
def test_workflow_write_permissions_are_reported(permissions: str) -> None:
    result = report(
        (
            "github_actions",
            f"on: push\n{permissions}\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@{SHA}\n",
        )
    )
    assert "workflow_write_permissions" in codes(result)


def test_pull_request_target_with_untrusted_head_checkout_is_reported() -> None:
    result = report(
        (
            "github_actions",
            f"""on: pull_request_target
permissions: read-all
jobs:
  test:
    steps:
      - uses: actions/checkout@{SHA}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
""",
        )
    )
    assert "workflow_untrusted_head" in codes(result)


def test_pull_request_target_default_base_checkout_is_not_untrusted_head() -> None:
    result = report(
        (
            "github_actions",
            f"on: pull_request_target\npermissions: read-all\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{SHA}\n",
        )
    )
    assert "workflow_untrusted_head" not in codes(result)


def test_unsupported_yaml_aliases_cannot_claim_complete_analysis() -> None:
    result = report(("github_actions", "permissions: *inherited\njobs: {}\n"))
    assert "github_actions_insufficient_evidence" in codes(result)


def test_dynamic_action_and_malformed_sbom_remain_partial() -> None:
    action = report(("github_actions", "on: push\njobs:\n  test:\n    steps:\n      - uses: ${{ inputs.action }}\n"))
    sbom = report(("cyclonedx", {"components": ["not-a-component"]}))
    assert "github_actions_insufficient_evidence" in codes(action)
    assert "versioned_sbom_component_insufficient_evidence" in codes(sbom)
