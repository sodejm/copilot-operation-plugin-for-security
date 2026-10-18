"""Export validated assessment reports without strengthening their claims."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from cops.contracts.validation import validate_contract
from cops.execution.redaction import StreamRedactor

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
_FORMATS = frozenset({"sarif", "junit", "pr-markdown"})
_FULL_COMMIT = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.5",
}


class ExportError(ValueError):
    """A report or source anchor cannot be exported safely."""


@dataclass(frozen=True, slots=True)
class SourceAnchor:
    """A finding location resolved against one immutable Git commit."""

    finding_id: str
    path: str
    start_line: int
    end_line: int | None = None
    replacement: str | None = None


@dataclass(frozen=True, slots=True)
class _VerifiedAnchor:
    source: SourceAnchor
    end_line: int
    line_sha256: str


def _validated_report(report: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        raise ExportError("report must be an assessment-report object")
    document = dict(report)
    try:
        validate_contract(document, "assessment_report", max_bytes=4 * 1024 * 1024)
    except (KeyError, TypeError, ValueError) as error:
        raise ExportError("invalid assessment-report contract") from error
    return document


def _is_verified(finding: Mapping[str, Any]) -> bool:
    return (
        finding["assessment_status"] == "assessed"
        and finding["verification"] == "verified"
        and finding["evidence_strength"] == "recorded"
    )


def _conclusion(finding: Mapping[str, Any]) -> str:
    if _is_verified(finding):
        return "verified"
    if finding["verification"] == "contradicted":
        return "contradicted"
    return "inconclusive"


def _redactor() -> StreamRedactor:
    return StreamRedactor()


def _clean(text: Any, redactor: StreamRedactor) -> str:
    redacted = _CONTROL.sub("", redactor.redact_string(str(text)))
    return "".join(character for character in redacted if unicodedata.category(character) != "Cf")


def _coerce_anchor(value: SourceAnchor | Mapping[str, Any]) -> SourceAnchor:
    if isinstance(value, SourceAnchor):
        anchor = value
    elif not isinstance(value, Mapping):
        raise ExportError("source anchor must be an object")
    else:
        allowed = {"finding_id", "path", "start_line", "end_line", "replacement"}
        if set(value) - allowed or not {"finding_id", "path", "start_line"} <= set(value):
            raise ExportError("source anchor has missing or unknown fields")
        anchor = SourceAnchor(
            finding_id=value["finding_id"],
            path=value["path"],
            start_line=value["start_line"],
            end_line=value.get("end_line"),
            replacement=value.get("replacement"),
        )
    if not isinstance(anchor.finding_id, str) or not anchor.finding_id:
        raise ExportError("source anchor finding_id must be non-empty text")
    return anchor


def _git(repository_root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository_root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ExportError("unable to verify immutable Git source anchor") from error
    return result.stdout


def _resolve_revision(repository_root: str | Path | None, revision: str | None) -> tuple[Path, str]:
    if repository_root is None or revision is None:
        raise ExportError("source-anchored export requires a repository root and full commit revision")
    if not isinstance(revision, str) or _FULL_COMMIT.fullmatch(revision) is None:
        raise ExportError("revision must be a full immutable Git commit hash")
    root = Path(repository_root).resolve()
    if not root.is_dir():
        raise ExportError("repository root is not a directory")
    resolved = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode("ascii").strip().lower()
    if resolved != revision.lower():
        raise ExportError("revision must identify the exact immutable Git commit")
    return root, resolved


def _verify_anchors(
    findings: Sequence[Mapping[str, Any]],
    anchors: Sequence[SourceAnchor | Mapping[str, Any]],
    *,
    repository_root: Path,
    revision: str,
) -> list[_VerifiedAnchor]:
    finding_ids = {finding["finding_id"] for finding in findings}
    verified: list[_VerifiedAnchor] = []
    seen: set[tuple[str, str, int, int]] = set()
    for raw in anchors:
        anchor = _coerce_anchor(raw)
        if anchor.finding_id not in finding_ids:
            raise ExportError("source anchor references an unknown finding")
        if (
            not isinstance(anchor.path, str)
            or not anchor.path
            or "\\" in anchor.path
            or ":" in anchor.path
            or _CONTROL.search(anchor.path)
        ):
            raise ExportError("source anchor path must be a repository-relative POSIX path")
        if _clean(anchor.path, _redactor()) != anchor.path:
            raise ExportError("source anchor path must not contain credential material")
        path = PurePosixPath(anchor.path)
        if path.is_absolute() or path.as_posix() != anchor.path or any(part in {"", ".", ".."} for part in path.parts):
            raise ExportError("source anchor path escapes the repository")
        if type(anchor.start_line) is not int or anchor.start_line < 1:
            raise ExportError("source anchor start_line must be a positive integer")
        end_line = anchor.start_line if anchor.end_line is None else anchor.end_line
        if type(end_line) is not int or end_line < anchor.start_line:
            raise ExportError("source anchor end_line must not precede start_line")
        if anchor.replacement is not None and not isinstance(anchor.replacement, str):
            raise ExportError("source anchor replacement must be text")
        key = (anchor.finding_id, anchor.path, anchor.start_line, end_line)
        if key in seen:
            raise ExportError("duplicate source anchor")
        seen.add(key)
        blob = _git(repository_root, "show", f"{revision}:{anchor.path}")
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ExportError("source anchor file must be UTF-8 text") from error
        lines = text.splitlines(keepends=True)
        if end_line > len(lines):
            raise ExportError("source anchor line range is outside the committed file")
        selected = "".join(lines[anchor.start_line - 1 : end_line]).encode("utf-8")
        verified.append(
            _VerifiedAnchor(
                source=anchor,
                end_line=end_line,
                line_sha256=hashlib.sha256(selected).hexdigest(),
            )
        )
    return verified


def _rule(finding: Mapping[str, Any], redactor: StreamRedactor) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "tags": ["security", *[_clean(item, redactor) for item in finding["mitre_attack"]]],
        "precision": "high" if _is_verified(finding) else "low",
        "copsConclusion": _conclusion(finding),
    }
    if finding["severity"] in _SECURITY_SEVERITY:
        properties["security-severity"] = _SECURITY_SEVERITY[finding["severity"]]
    return {
        "id": finding["finding_id"],
        "name": finding["finding_id"].replace("-", "_"),
        "shortDescription": {"text": _clean(finding["title"], redactor)},
        "fullDescription": {"text": _clean(finding["claim"], redactor)},
        "help": {"text": _clean(finding["remediation"], redactor)},
        "defaultConfiguration": {"level": _SEVERITY_LEVEL[finding["severity"]] if _is_verified(finding) else "note"},
        "properties": properties,
    }


def export_sarif(
    report: Mapping[str, Any],
    *,
    repository_root: str | Path | None = None,
    revision: str | None = None,
    source_anchors: Sequence[SourceAnchor | Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Return SARIF 2.1.0 while preserving COPS assessment conclusions."""
    document = _validated_report(report)
    redactor = _redactor()
    verified_anchors: list[_VerifiedAnchor] = []
    resolved_revision: str | None = None
    if source_anchors:
        root, resolved_revision = _resolve_revision(repository_root, revision)
        verified_anchors = _verify_anchors(
            document["findings"], source_anchors, repository_root=root, revision=resolved_revision
        )
    anchors_by_finding: dict[str, list[_VerifiedAnchor]] = {}
    for anchor in verified_anchors:
        anchors_by_finding.setdefault(anchor.source.finding_id, []).append(anchor)

    rules = [_rule(finding, redactor) for finding in document["findings"]]
    results: list[dict[str, Any]] = []
    for index, finding in enumerate(document["findings"]):
        conclusion = _conclusion(finding)
        message = (
            f"[{conclusion.upper()}] {_clean(finding['claim'], redactor)} "
            f"Assessment={finding['assessment_status']}; verification={finding['verification']}; "
            f"evidence={finding['evidence_strength']}."
        )
        result: dict[str, Any] = {
            "ruleId": finding["finding_id"],
            "ruleIndex": index,
            "level": _SEVERITY_LEVEL[finding["severity"]] if _is_verified(finding) else "note",
            "message": {"text": message},
            "partialFingerprints": {"copsFindingId": hashlib.sha256(finding["finding_id"].encode("utf-8")).hexdigest()},
            "properties": {
                "copsAssessmentStatus": finding["assessment_status"],
                "copsVerification": finding["verification"],
                "copsEvidenceStrength": finding["evidence_strength"],
                "copsConclusion": conclusion,
                "copsAffectedAssets": [_clean(item, redactor) for item in finding["affected_assets"]],
            },
        }
        locations = []
        for anchor in anchors_by_finding.get(finding["finding_id"], []):
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": anchor.source.path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": anchor.source.start_line, "endLine": anchor.end_line},
                    }
                }
            )
        if locations:
            result["locations"] = locations
            result["partialFingerprints"]["copsAnchorLinesSha256"] = anchors_by_finding[finding["finding_id"]][
                0
            ].line_sha256
        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "COPS Security Findings",
                "informationUri": "https://github.com/sodejm/copilot-operation-plugin-for-security",
                "rules": rules,
            }
        },
        "automationDetails": {"id": document["report_id"]},
        "results": results,
        "properties": {
            "copsSchemaVersion": document["schema_version"],
            "copsEngagementId": document["engagement_id"],
            "copsEvidenceNotice": document["evidence_notice"],
        },
    }
    if resolved_revision is not None:
        run["properties"]["copsRevision"] = resolved_revision
    sarif = {"version": "2.1.0", "$schema": SARIF_SCHEMA, "runs": [run]}
    validate_github_sarif_subset(sarif)
    return sarif


def validate_github_sarif_subset(sarif: Mapping[str, Any]) -> None:
    """Check the fields COPS emits against GitHub's documented SARIF subset."""
    if sarif.get("version") != "2.1.0" or sarif.get("$schema") != SARIF_SCHEMA:
        raise ExportError("SARIF output must identify the official 2.1.0 schema")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ExportError("GitHub SARIF export requires exactly one run")
    driver = runs[0].get("tool", {}).get("driver", {})
    rules = driver.get("rules")
    results = runs[0].get("results")
    if not driver.get("name") or not isinstance(rules, list) or not isinstance(results, list):
        raise ExportError("GitHub SARIF run is missing its driver, rules, or results")
    rule_ids = [rule.get("id") for rule in rules]
    if any(not isinstance(rule_id, str) or not rule_id for rule_id in rule_ids) or len(rule_ids) != len(set(rule_ids)):
        raise ExportError("GitHub SARIF rules require unique non-empty identifiers")
    for result in results:
        index = result.get("ruleIndex")
        if (
            not isinstance(index, int)
            or index < 0
            or index >= len(rules)
            or result.get("ruleId") != rule_ids[index]
            or result.get("level") not in {"none", "note", "warning", "error"}
            or not isinstance(result.get("message", {}).get("text"), str)
        ):
            raise ExportError("GitHub SARIF result does not match its rule or supported fields")
        for location in result.get("locations", []):
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            if (
                not isinstance(artifact.get("uri"), str)
                or not artifact["uri"]
                or not isinstance(region.get("startLine"), int)
                or region["startLine"] < 1
                or not isinstance(region.get("endLine"), int)
                or region["endLine"] < region["startLine"]
            ):
                raise ExportError("GitHub SARIF location is invalid")


def export_junit(report: Mapping[str, Any]) -> str:
    """Return JUnit XML where findings never become successful test cases."""
    document = _validated_report(report)
    redactor = _redactor()
    verified_count = sum(_is_verified(finding) for finding in document["findings"])
    inconclusive_count = len(document["findings"]) - verified_count
    suite = ET.Element(
        "testsuite",
        {
            "name": "COPS assessment findings",
            "id": _clean(document["report_id"], redactor),
            "tests": str(len(document["findings"])),
            "failures": str(verified_count),
            "errors": "0",
            "skipped": str(inconclusive_count),
        },
    )
    properties = ET.SubElement(suite, "properties")
    for name, value in (
        ("cops.schema_version", document["schema_version"]),
        ("cops.engagement_id", document["engagement_id"]),
        ("cops.evidence_notice", document["evidence_notice"]),
    ):
        ET.SubElement(properties, "property", {"name": name, "value": _clean(value, redactor)})
    for finding in document["findings"]:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": _clean(finding["scenario_id"], redactor),
                "name": _clean(f"{finding['finding_id']}: {finding['title']}", redactor),
            },
        )
        details = _clean(
            f"{finding['claim']} Assessment={finding['assessment_status']}; "
            f"verification={finding['verification']}; evidence={finding['evidence_strength']}. "
            f"Remediation: {finding['remediation']}",
            redactor,
        )
        if _is_verified(finding):
            failure = ET.SubElement(
                case,
                "failure",
                {"type": "cops.verified_finding", "message": _clean(finding["severity"], redactor)},
            )
            failure.text = details
        else:
            skipped = ET.SubElement(
                case,
                "skipped",
                {
                    "message": _clean(
                        f"{_conclusion(finding)}: {finding['assessment_status']}/{finding['verification']}", redactor
                    )
                },
            )
            skipped.text = details
    ET.indent(suite, space="  ")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def _markdown(text: Any, redactor: StreamRedactor) -> str:
    value = re.sub(r"\s+", " ", _clean(text, redactor)).strip()
    return re.sub(r"([\\`*_\[\]{}<>#|])", r"\\\1", value)


def _suggestion_fence(replacement: str) -> str:
    runs = [len(match.group(0)) for match in re.finditer(r"`+", replacement)]
    return "`" * max(3, max(runs, default=0) + 1)


def export_pr_markdown(
    report: Mapping[str, Any],
    *,
    repository_root: str | Path,
    revision: str,
    source_anchors: Sequence[SourceAnchor | Mapping[str, Any]] = (),
) -> str:
    """Return local PR-ready Markdown with revision-verified suggestions."""
    document = _validated_report(report)
    root, resolved_revision = _resolve_revision(repository_root, revision)
    verified = _verify_anchors(document["findings"], source_anchors, repository_root=root, revision=resolved_revision)
    anchors_by_finding: dict[str, list[_VerifiedAnchor]] = {}
    for anchor in verified:
        anchors_by_finding.setdefault(anchor.source.finding_id, []).append(anchor)
    redactor = _redactor()
    lines = [
        f"# COPS report {_markdown(document['report_id'], redactor)}",
        "",
        f"Immutable revision: `{resolved_revision}`",
        "",
        f"> {_markdown(document['evidence_notice'], redactor)}",
        "",
    ]
    for finding in document["findings"]:
        conclusion = _conclusion(finding)
        heading = "Verified finding" if conclusion == "verified" else "Inconclusive finding"
        if conclusion == "contradicted":
            heading = "Contradicted finding"
        lines.extend(
            [
                f"## {heading}: {_markdown(finding['title'], redactor)}",
                "",
                f"- Finding: `{_markdown(finding['finding_id'], redactor)}`",
                f"- Severity: **{_markdown(finding['severity'], redactor)}**",
                f"- Status: `{_markdown(finding['assessment_status'], redactor)}` / "
                f"`{_markdown(finding['verification'], redactor)}` / "
                f"`{_markdown(finding['evidence_strength'], redactor)}`",
                "",
                _markdown(finding["claim"], redactor),
                "",
                f"Remediation: {_markdown(finding['remediation'], redactor)}",
                "",
            ]
        )
        limitations = finding["limitations"]
        if limitations:
            lines.extend(["Limitations:", "", *[f"- {_markdown(item, redactor)}" for item in limitations], ""])
        for anchor in anchors_by_finding.get(finding["finding_id"], []):
            source = anchor.source
            location = f"{source.path}:{source.start_line}"
            if anchor.end_line != source.start_line:
                location += f"-{anchor.end_line}"
            lines.extend(
                [
                    f"Source anchor: `{_markdown(location, redactor)}` (lines SHA-256 `{anchor.line_sha256}`)",
                    "",
                ]
            )
            if source.replacement is not None:
                replacement = _clean(source.replacement, redactor)
                fence = _suggestion_fence(replacement)
                lines.extend([f"{fence}suggestion", replacement, fence, ""])
    return "\n".join(lines).rstrip() + "\n"


def export_report(
    report: Mapping[str, Any],
    *,
    format: Literal["sarif", "junit", "pr-markdown"],
    repository_root: str | Path | None = None,
    revision: str | None = None,
    source_anchors: Sequence[SourceAnchor | Mapping[str, Any]] = (),
) -> str:
    """Serialize one supported report format for the parent CLI."""
    if format not in _FORMATS:
        raise ExportError(f"unsupported report format: {format!r}")
    if format == "sarif":
        return (
            json.dumps(
                export_sarif(
                    report,
                    repository_root=repository_root,
                    revision=revision,
                    source_anchors=source_anchors,
                ),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        )
    if format == "junit":
        if source_anchors or repository_root is not None or revision is not None:
            raise ExportError("JUnit export does not accept Git source anchors")
        return export_junit(report)
    if repository_root is None or revision is None:
        raise ExportError("PR Markdown export requires a repository root and full commit revision")
    return export_pr_markdown(
        report,
        repository_root=repository_root,
        revision=revision,
        source_anchors=source_anchors,
    )
