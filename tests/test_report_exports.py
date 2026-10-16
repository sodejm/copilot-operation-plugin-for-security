"""Cross-format report exports preserve COPS evidence conclusions."""

from __future__ import annotations

import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry
from referencing.exceptions import NoSuchResource

from cops.reporting.assessment import build_assessment_report
from cops.reports import (
    ExportError,
    SourceAnchor,
    export_junit,
    export_pr_markdown,
    export_report,
    export_sarif,
    validate_github_sarif_subset,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "cops" / "contracts" / "fixtures"
EXPORT_FIXTURES = ROOT / "tests" / "fixtures" / "report_exports"
TOKEN = "ghp_" + "A" * 36
SARIF_SCHEMA = ROOT / "cops" / "reports" / "schemas" / "sarif-schema-2.1.0.json"


def _refuse_remote_reference(uri: str):
    raise NoSuchResource(ref=uri)


@pytest.fixture(scope="module")
def sarif_validator() -> jsonschema.Draft7Validator:
    schema_bytes = SARIF_SCHEMA.read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == (
        "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
    )
    schema = json.loads(schema_bytes)
    pending = [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "$ref" in node:
                assert node["$ref"].startswith("#/"), "SARIF schema must be self-contained"
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    jsonschema.Draft7Validator.check_schema(schema)
    return jsonschema.Draft7Validator(
        schema,
        registry=Registry(retrieve=_refuse_remote_reference),
        format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER,
    )


def _bundle(verification: str = "verified") -> dict:
    document = json.loads((FIXTURES / "valid_assessment_input.json").read_text(encoding="utf-8"))
    document["findings"][0]["verification"] = verification
    if verification == "contradicted":
        document["findings"][0]["classification"] = "unresolved"
    return document


def _report(verification: str = "verified") -> dict:
    return build_assessment_report(_bundle(verification))


def _revision() -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()


def _anchors(*, replacement: str | None = None) -> list[dict]:
    anchors = json.loads((EXPORT_FIXTURES / "valid_source_anchors.json").read_text(encoding="utf-8"))
    if replacement is not None:
        anchors[0]["replacement"] = replacement
    return anchors


@pytest.mark.parametrize(
    ("verification", "expected_level", "expected_conclusion"),
    [
        ("verified", "warning", "verified"),
        ("unverified", "note", "inconclusive"),
        ("contradicted", "note", "contradicted"),
    ],
)
def test_sarif_preserves_finding_conclusions(
    verification: str,
    expected_level: str,
    expected_conclusion: str,
) -> None:
    sarif = export_sarif(_report(verification))
    result = sarif["runs"][0]["results"][0]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert sarif["version"] == "2.1.0"
    assert result["level"] == expected_level
    assert result["properties"]["copsConclusion"] == expected_conclusion
    assert rule["properties"]["precision"] == ("high" if verification == "verified" else "low")


@pytest.mark.parametrize(
    ("verification", "failures", "skipped", "child"),
    [
        ("verified", "1", "0", "failure"),
        ("unverified", "0", "1", "skipped"),
        ("contradicted", "0", "1", "skipped"),
    ],
)
def test_junit_never_turns_a_finding_into_a_success(
    verification: str,
    failures: str,
    skipped: str,
    child: str,
) -> None:
    suite = ET.fromstring(export_junit(_report(verification)))
    case = suite.find("testcase")

    assert suite.attrib == {
        "name": "COPS assessment findings",
        "id": "report-internal-001",
        "tests": "1",
        "failures": failures,
        "errors": "0",
        "skipped": skipped,
    }
    assert case is not None
    assert case.find(child) is not None


def test_junit_escapes_xml_redacts_credentials_and_keeps_inconclusive_skipped() -> None:
    report = _report("unverified")
    finding = report["findings"][0]
    finding["title"] = 'Route <admin> & "ops"\x01'
    finding["claim"] = f"Observed <script> & token={TOKEN}"
    finding["remediation"] = 'Rotate & quote "credentials".'

    output = export_junit(report)
    suite = ET.fromstring(output)
    case = suite.find("testcase")
    skipped = case.find("skipped") if case is not None else None

    assert "&lt;admin&gt;" in output
    assert "&amp;" in output
    assert "\x01" not in output
    assert TOKEN not in output
    assert "REDACTED:CREDENTIAL" in output
    assert suite.attrib["failures"] == "0"
    assert suite.attrib["skipped"] == "1"
    assert case is not None
    assert case.attrib["name"] == 'find-open-port-http-80: Route <admin> & "ops"'
    assert case.find("failure") is None
    assert skipped is not None
    assert "Observed <script> &" in (skipped.text or "")


def test_pr_markdown_binds_anchor_to_exact_revision_and_lines() -> None:
    revision = _revision()
    markdown = export_pr_markdown(
        _report(),
        repository_root=ROOT,
        revision=revision,
        source_anchors=_anchors(replacement=f"Use TLS. Token={TOKEN}"),
    )
    first_line = (ROOT / "README.md").read_bytes().splitlines(keepends=True)[0]

    assert f"Immutable revision: `{revision}`" in markdown
    assert "Source anchor: `README.md:1`" in markdown
    assert hashlib.sha256(first_line).hexdigest() in markdown
    assert "```suggestion" in markdown
    assert TOKEN not in markdown
    assert "REDACTED:CREDENTIAL" in markdown


@pytest.mark.parametrize(
    ("anchor", "message"),
    [
        ({"finding_id": "find-unknown", "path": "README.md", "start_line": 1}, "unknown finding"),
        ({"finding_id": "find-open-port-http-80", "path": "../README.md", "start_line": 1}, "escapes"),
        ({"finding_id": "find-open-port-http-80", "path": "./README.md", "start_line": 1}, "escapes"),
        ({"finding_id": "find-open-port-http-80", "path": "README.md", "start_line": 999999}, "outside"),
    ],
)
def test_pr_markdown_rejects_invalid_source_anchors(anchor: dict, message: str) -> None:
    with pytest.raises(ExportError, match=message):
        export_pr_markdown(
            _report(),
            repository_root=ROOT,
            revision=_revision(),
            source_anchors=[anchor],
        )


def test_source_anchor_dataclass_is_validated() -> None:
    with pytest.raises(ExportError, match="finding_id"):
        export_pr_markdown(
            _report(),
            repository_root=ROOT,
            revision=_revision(),
            source_anchors=[SourceAnchor(finding_id="", path="README.md", start_line=1)],
        )


def test_pr_markdown_rejects_abbreviated_revision() -> None:
    with pytest.raises(ExportError, match="full immutable"):
        export_pr_markdown(
            _report(),
            repository_root=ROOT,
            revision=_revision()[:12],
        )


def test_all_exports_redact_credential_patterns() -> None:
    report = _report()
    report["findings"][0]["remediation"] = f"Rotate token={TOKEN} before remediation."

    outputs = [
        json.dumps(export_sarif(report)),
        export_junit(report),
        export_pr_markdown(report, repository_root=ROOT, revision=_revision()),
    ]
    assert all(TOKEN not in output for output in outputs)
    assert all("REDACTED:CREDENTIAL" in output for output in outputs)


def test_pr_markdown_neutralizes_untrusted_block_structure() -> None:
    report = _report()
    report["findings"][0]["title"] = "Observed service\n# injected heading"

    markdown = export_pr_markdown(report, repository_root=ROOT, revision=_revision())

    assert "\n# injected heading" not in markdown
    assert "Observed service \\# injected heading" in markdown


def test_export_rejects_semantically_invalid_report() -> None:
    report = _report()
    report["findings"][0]["assessment_status"] = "partial"

    with pytest.raises(ExportError, match="invalid assessment-report contract"):
        export_sarif(report)


def test_dispatcher_serializes_formats_and_rejects_irrelevant_anchor_options() -> None:
    report = _report()

    assert json.loads(export_report(report, format="sarif"))["version"] == "2.1.0"
    assert ET.fromstring(export_report(report, format="junit")).tag == "testsuite"
    assert "# COPS report" in export_report(
        report,
        format="pr-markdown",
        repository_root=ROOT,
        revision=_revision(),
    )
    with pytest.raises(ExportError, match="does not accept"):
        export_report(report, format="junit", repository_root=ROOT)
    with pytest.raises(ExportError, match="unsupported"):
        export_report(report, format="csv")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("verification", "expected_level", "expected_conclusion"),
    [
        pytest.param("verified", "warning", "verified", id="vulnerable"),
        pytest.param("unverified", "note", "inconclusive", id="inconclusive"),
        pytest.param("contradicted", "note", "contradicted", id="contradicted"),
    ],
)
def test_sarif_matches_official_schema_and_github_subset(
    sarif_validator: jsonschema.Draft7Validator,
    verification: str,
    expected_level: str,
    expected_conclusion: str,
) -> None:
    sarif = export_sarif(
        _report(verification),
        repository_root=ROOT,
        revision=_revision(),
        source_anchors=_anchors(),
    )
    sarif_validator.validate(sarif)
    validate_github_sarif_subset(sarif)

    run = sarif["runs"][0]
    result = run["results"][0]
    rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
    location = result["locations"][0]["physicalLocation"]

    assert result["ruleId"] == rule["id"]
    assert result["level"] == expected_level
    assert result["properties"]["copsConclusion"] == expected_conclusion
    assert result["message"]["text"]
    assert result["partialFingerprints"]
    assert location["artifactLocation"]["uri"] == "README.md"
    assert location["region"] == {"startLine": 1, "endLine": 1}


def test_sarif_corrected_report_has_no_results(sarif_validator: jsonschema.Draft7Validator) -> None:
    bundle = _bundle()
    bundle["findings"] = []
    bundle["finding_contexts"] = []
    sarif = export_sarif(build_assessment_report(bundle))
    sarif_validator.validate(sarif)
    validate_github_sarif_subset(sarif)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


@pytest.mark.parametrize("malformation", ["version", "message", "level", "line", "extra-field"])
def test_official_schema_rejects_malformed_exports(
    sarif_validator: jsonschema.Draft7Validator, malformation: str
) -> None:
    sarif = export_sarif(
        _report(), repository_root=ROOT, revision=_revision(), source_anchors=_anchors()
    )
    result = sarif["runs"][0]["results"][0]
    if malformation == "version":
        sarif["version"] = "2.0.0"
    elif malformation == "message":
        del result["message"]
    elif malformation == "level":
        result["level"] = "critical"
    elif malformation == "line":
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = 0
    else:
        result["copsConclusion"] = "verified"
    with pytest.raises(jsonschema.ValidationError):
        sarif_validator.validate(sarif)


def test_github_subset_rejects_schema_valid_mismatched_rule(
    sarif_validator: jsonschema.Draft7Validator,
) -> None:
    sarif = deepcopy(export_sarif(_report()))
    sarif["runs"][0]["results"][0]["ruleId"] = "unregistered-rule"
    sarif_validator.validate(sarif)
    with pytest.raises(ExportError, match="does not match its rule"):
        validate_github_sarif_subset(sarif)


def test_export_option_schemas_are_valid_draft_2020_12() -> None:
    for path in sorted((ROOT / "cops" / "reports" / "schemas").glob("*.schema.json")):
        jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
