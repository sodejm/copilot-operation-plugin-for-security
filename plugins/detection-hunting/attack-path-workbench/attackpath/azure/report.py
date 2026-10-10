"""Bounded reports and individually re-evaluated entitlement cuts."""

import html
import os
import secrets

from .._runtime.cops.evidence.canonical import canonical
from .input import load
from .model import AzureError, Budget, absolute_parts, stable
from .paths import search

CUT_FAMILIES = {
    "role_assignments",
    "directory_assignments",
    "pim_active",
    "pim_eligible",
    "group_members",
    "owners",
    "federated_credentials",
    "lighthouse_assignments",
}


def signature(path):
    return stable([path["start"], path["target"], [[s["rule"], s["resource"], s["effect"]] for s in path["steps"]]])


def remediation(graph, paths):
    reachable = [p for p in paths if p["classification"] == "modelled_reachable"]
    rows = {r.key: r for r in graph.objects if r.family in CUT_FAMILIES}
    candidates = sorted({cut for p in reachable for cut in p["cuts"] if cut in rows})
    actions = []
    if len(candidates) > 64:
        graph.partial.append("remediation_candidate_limit")
    for cut in candidates[:64]:
        try:
            reduced = graph.without(cut)
            after = [p for p in search(reduced) if p["classification"] == "modelled_reachable"]
            original = {signature(p): p["id"] for p in reachable}
            survivors = {signature(p): p["id"] for p in after}
            row = rows[cut]
            actions.append(
                {
                    "id": stable(["remove", cut]),
                    "operation": "remove_observed_entitlement",
                    "cut": cut,
                    "family": row.family,
                    "tenant": row.tenant,
                    "object_id": row.data["id"],
                    "scope": row.properties.get("scope", row.properties.get("directoryScopeId")),
                    "evidence": row.evidence,
                    "broken_paths": sorted(original[s] for s in original.keys() - survivors.keys()),
                    "surviving_paths": sorted(original[s] for s in original.keys() & survivors.keys()),
                    "alternate_paths": sorted(survivors[s] for s in survivors.keys() - original.keys()),
                    "reachable_after": len(after),
                    "conclusive_within_model": not reduced.partial,
                    "limitations": sorted(set(reduced.partial)),
                    "owner_validation_required": True,
                }
            )
            graph.partial.extend(reduced.partial)
        except Budget as exc:
            graph.partial.append(str(exc))
            break
    return {
        "schema_version": "attackpath.azure.remediation/v1",
        "method": "single scoped entitlement removal and full bounded re-evaluation",
        "global_minimum_claimed": False,
        "actions": actions,
    }


def pseudonymize(value):
    # Deterministic per-report identifiers retain joins. These are pseudonyms,
    # not anonymous identifiers; hashes and topology remain linkable.
    keys = {"tenant", "id", "object_id", "source_id", "acquisition_id", "scope", "resource", "source", "target"}
    opaque = {"id", "source", "target"}

    def token(text):
        return "p-" + stable(["attackpath.azure.pseudonym/v1", text.lower()])[:24]

    def walk(item, key=None):
        if isinstance(item, dict):
            return {k: walk(v, k) for k, v in item.items()}
        if isinstance(item, list):
            return [walk(v, "scope" if key == "scopes" else key) for v in item]
        if isinstance(item, str) and key in keys:
            if key in opaque and (
                len(item) == 64 and all(c in "0123456789abcdef" for c in item) or item.startswith("observation:")
            ):
                return item
            if key in opaque and ":" in item:
                tenant, identity = item.split(":", 1)
                return token(tenant) + ":" + token(identity)
            return token(item)
        return item

    return walk(value)


def build(graph):
    paths = search(graph)
    cuts = remediation(graph, paths)
    export = graph.export()
    ledger = {"schema_version": "attackpath.azure.ledger/v1", "records": graph.ledger}
    for path in paths:
        path["ranking_factors"] = {
            "authorization": path["classification"],
            "steps": len(path["steps"]),
            "scope_depth": len(path["target"]["scope"].strip("/").split("/")),
            "uncertainty_count": len(path["uncertainty"]),
            "evidence_count": len(path["evidence"]),
        }
        path["business_impact"] = graph.scenario.get("business_impact", {}).get(path["target"]["scope"], "not_supplied")
    paths.sort(key=lambda p: (p["rank"], p["ranking_factors"]["steps"], p["id"]))
    report = {
        "schema_version": "attackpath.azure.report/v1",
        "as_of": graph.as_of,
        "rule_version": "azure-entitlements/v1",
        "status": "partial" if graph.partial else "complete_within_model",
        "partial_reasons": sorted(set(graph.partial)),
        "work_units": graph.work,
        "limits": graph.limits,
        "ingestion": getattr(
            graph,
            "ingestion",
            {
                "limits": {
                    key: graph.limits[key]
                    for key in ("file_bytes", "total_bytes", "files", "line_bytes", "records", "json_depth")
                },
                "bytes": 0,
                "files": 0,
                "records": 0,
                "lines": 0,
            },
        ),
        "paths": paths,
        "graph": export,
        "evidence_ledger": ledger,
        "remediation": cuts,
        "limitations": [
            "Offline authorization hypotheses require owner and runtime validation.",
            "Missing, stale, conflicting, conditioned or incomplete evidence cannot establish reachability.",
            "Conditional Access and authentication strengths provide context, not an evaluated policy result.",
            "Single entitlement cuts are bounded simulations, not globally minimal cut sets.",
            "Business impact is supplied by the owner and does not change technical ranking.",
        ],
    }
    if graph.scenario.get("pseudonymize"):
        report = pseudonymize(report)
        report["privacy"] = "deterministic pseudonyms; topology and evidence hashes remain linkable"
        # Owner text is unstructured and can identify a customer.
        for path in report["paths"]:
            path["business_impact"] = "owner_context_withheld"
    report["run_id"] = stable(report)
    return report


def escape(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ").replace("\r", " ")


def markdown(report):
    lines = [
        "# Azure entitlement analysis",
        "",
        "Status: " + report["status"],
        "As of: " + report["as_of"],
        "",
        "Offline hypotheses; authorization and runtime assumptions require validation.",
        "",
        "| Classification | Start | Target | Steps | Owner impact |",
        "|---|---|---|---:|---|",
    ]
    for path in report["paths"]:
        lines.append(
            "| "
            + " | ".join(
                escape(v)
                for v in (
                    path["classification"],
                    path["start"]["id"],
                    path["target"]["scope"],
                    len(path["steps"]),
                    path["business_impact"],
                )
            )
            + " |"
        )
    for path in report["paths"]:
        lines += ["", "## Path " + escape(path["id"]), "", "Classification: " + escape(path["classification"])]
        for index, item in enumerate(path["steps"], 1):
            lines += [
                "",
                str(index)
                + ". "
                + escape(item["rule"])
                + " at "
                + escape(item["resource"])
                + ": "
                + escape(item["effect"]),
            ]
            for requirement in item["prerequisites"]:
                lines.append(
                    "   - "
                    + escape(requirement["decision"])
                    + "; reasons: "
                    + escape(", ".join(requirement["reasons"]) or "none")
                    + "; evidence: "
                    + escape(", ".join(requirement["evidence"]) or "none")
                    + "; assumptions: "
                    + escape(", ".join(requirement["assumptions"]) or "none")
                )
        lines += ["", "Evidence ledger references: " + escape(", ".join(path["evidence"]) or "none")]
    lines += ["", "## Limits and uncertainty", ""] + [
        "- " + escape(v) for v in report["limitations"] + report["partial_reasons"]
    ]
    lines += ["", "## Tested entitlement removals", ""]
    for action in report["remediation"]["actions"]:
        lines.append(
            "- "
            + escape(action["family"])
            + ": "
            + escape(action["object_id"])
            + "; broken paths "
            + str(len(action["broken_paths"]))
            + "; reachable after "
            + str(action["reachable_after"])
            + "; conclusive within model "
            + str(action["conclusive_within_model"])
        )
    return "\n".join(lines) + "\n"


def _path_names_directory(parts, expected):
    """Return whether the requested lexical path still names expected."""
    descriptors = []
    try:
        descriptors.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY))
        for part in parts:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
        actual_stat = os.fstat(descriptors[-1])
        expected_stat = os.fstat(expected)
        return (actual_stat.st_dev, actual_stat.st_ino) == (expected_stat.st_dev, expected_stat.st_ino)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def write_files(output, contents, limit):
    encoded = {
        name: value if isinstance(value, bytes) else canonical(value, max_bytes=limit)
        for name, value in contents.items()
    }
    total = sum(len(v) for v in encoded.values())
    if total > limit:
        raise AzureError("output_byte_limit")
    completion = encoded.pop("completion.json", None)
    parts = absolute_parts(output)
    if (
        not parts
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or (completion is not None and os.link not in os.supports_dir_fd)
    ):
        raise AzureError("unsafe_output")
    descriptors = []
    staging_name = None
    staging_created = False
    completion_published = False
    try:
        descriptors.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY))
        for part in parts[:-1]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
        parent = descriptors[-1]
        os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
        descriptors.append(os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent))
        directory = descriptors[-1]
        try:
            os.fchmod(directory, 0o700)
        except OSError:
            pass
        for name, data in encoded.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise AzureError("output_write_failed")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(directory)
        if not _path_names_directory(parts, directory):
            raise OSError("output path changed during write")

        if completion is not None:
            # Publish the authoritative marker only after the report entries
            # and bytes are durable. A random staging name lets link(2) make
            # publication atomic and no-replace; failure recovery never
            # unlinks a public marker that another invocation may own.
            staging_name = f".completion-{secrets.token_hex(16)}.tmp"
            fd = os.open(
                staging_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            staging_created = True
            try:
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
                view = memoryview(completion)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise AzureError("output_write_failed")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
            if not _path_names_directory(parts, directory):
                raise OSError("output path changed during write")
            os.link(
                staging_name,
                "completion.json",
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            completion_published = True
            os.unlink(staging_name, dir_fd=directory)
            staging_created = False
            os.fsync(directory)
    except (AzureError, OSError) as error:
        # Before publication, remove only the unpredictable staging name that
        # this invocation opened with O_EXCL. Never roll back the public marker:
        # publication is the commit point and its pathname may later be owned
        # by another invocation.
        if staging_created and not completion_published:
            try:
                os.unlink(staging_name, dir_fd=directory)
            except FileNotFoundError:
                pass
            except OSError:
                # The original operation already fails closed. Leaving a
                # non-authoritative staging file is safer than touching a
                # public completion marker whose ownership is uncertain.
                pass
        if isinstance(error, AzureError):
            raise
        raise AzureError("unsafe_or_existing_output") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def analyze(manifest, as_of, output, limits=None):
    graph = load(manifest, as_of, limits)
    report = build(graph)
    contents = {
        "report.json": report,
        "graph.json": report["graph"],
        "evidence-ledger.json": report["evidence_ledger"],
        "remediation.json": report["remediation"],
        "report.md": markdown(report).encode("utf-8"),
    }
    marker = {
        "schema_version": "attackpath.azure.completion/v1",
        "run_id": report["run_id"],
        "status": report["status"],
        "files": {
            name: stable(value) if not isinstance(value, bytes) else __import__("hashlib").sha256(value).hexdigest()
            for name, value in contents.items()
        },
    }
    # This is deliberately last, and is included in the aggregate output cap.
    contents["completion.json"] = marker
    write_files(output, contents, graph.limits["output_bytes"])
    return {"run_id": report["run_id"], "status": report["status"], "paths": len(report["paths"])}
