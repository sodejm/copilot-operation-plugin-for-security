"""Optional product-skill bindings for peers; no agent launch or authority transfer."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from cops._schema_validation import validate

from .catalog import RESULT_SCHEMA
from .contracts import MAX_BYTES, OperationError, decode, encode
from .inventory import package_path
from .runs import digest


def installed_json(root, relative):
    path = Path(root) / relative
    with path.open("rb") as stream:
        return decode(stream.read(MAX_BYTES + 1))


def resolve_binding(root, specialist_id, skill_id, operation_id, service):
    root = Path(root).resolve()
    profiles = installed_json(root, "agents/registry.json")["specialists"]
    profile = next((item for item in profiles if item["id"] == specialist_id), None)
    if profile is None or skill_id not in profile["skills"]:
        raise OperationError("skill_not_declared")
    plugins = installed_json(root, "catalog/plugins.json")["plugins"]
    candidates = []
    for plugin in plugins:
        path = package_path(root, plugin) / "skills" / skill_id / "SKILL.md"
        if path.is_file():
            candidates.append((plugin["id"], path))
    if not candidates:
        path = root / ".agents/skills" / skill_id / "SKILL.md"
        if path.is_file():
            candidates.append(("cops-core", path))
    if len(candidates) != 1:
        raise OperationError("missing_or_ambiguous_skill")
    plugin_id, path = candidates[0]
    if not path.resolve().is_relative_to(root):
        raise OperationError("unsafe_skill_binding")
    with path.open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise OperationError("skill_size_limit")
    text = raw.decode("utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        raise OperationError("invalid_skill_binding")
    frontmatter = lines[1 : lines.index("---", 1)]
    names = [
        line.partition(":")[2].strip().strip("\"'") for line in frontmatter if line.partition(":")[0].strip() == "name"
    ]
    if names != [skill_id]:
        raise OperationError("invalid_skill_binding")
    if operation_id is not None:
        declaration = service._catalog.get(operation_id)
        if (
            declaration is None
            or declaration["owner"] != plugin_id
            or not operation_id.startswith(("cops.work.", "cops.soc.", "cops.assess."))
        ):
            raise OperationError("operation_skill_mismatch")
    return {
        "specialist_id": specialist_id,
        "skill_id": skill_id,
        "plugin_id": plugin_id,
        "implementation": path.relative_to(root).as_posix(),
        "implementation_digest": hashlib.sha256(raw).hexdigest(),
        "operation_id": operation_id,
    }


def process(runtime, action, arguments):
    if action == "prepare":
        specialist, skill = arguments.get("specialist_id"), arguments.get("skill_id")
        if (specialist is None) != (skill is None):
            raise OperationError("incomplete_recipient")
        operation_id = arguments.get("operation_id")
        binding = None
        if specialist is not None:
            binding = resolve_binding(runtime.installed_root, specialist, skill, operation_id, runtime.service)
        elif operation_id is not None:
            raise OperationError("operation_requires_recipient")
        bound = {"task": arguments["task"], "scope_ref": arguments.get("scope_ref"), "binding": binding}
        document = {
            "schema_version": "cops.delegation/v1",
            "delegation_id": "del-" + uuid.uuid4().hex,
            **bound,
            "binding_digest": digest(bound),
            "state": "prepared",
            "peer_response": None,
            "execution_authorized": False,
            "verification": "untrusted_peer_claims_only",
        }
        runtime.store.put_delegation(document)
        return document
    document = runtime.store.get_delegation(arguments["delegation_id"])
    binding = document["binding"]
    if binding is not None:
        current = resolve_binding(
            runtime.installed_root,
            binding["specialist_id"],
            binding["skill_id"],
            binding["operation_id"],
            runtime.service,
        )
        if current != binding:
            raise OperationError("delegation_binding_changed")
    expected = digest({"task": document["task"], "scope_ref": document["scope_ref"], "binding": binding})
    peer = arguments["peer_response"]
    if len(encode({"peer": peer, "reserved": [None] * 256})) > MAX_BYTES // 2:
        raise OperationError("peer_response_limit")
    if not isinstance(peer, dict) or set(peer) - {"binding_digest", "scope_ref", "operation_result", "notes"}:
        raise OperationError("invalid_peer_response")
    if peer.get("binding_digest") != expected or peer.get("scope_ref") != document["scope_ref"]:
        raise OperationError("peer_scope_or_binding_mismatch")
    notes = peer.get("notes", [])
    if (
        not isinstance(notes, list)
        or len(notes) > 32
        or any(not isinstance(note, str) or len(note) > 4096 for note in notes)
    ):
        raise OperationError("invalid_peer_response")
    result = peer.get("operation_result")
    if result is not None:
        if binding is None or binding["operation_id"] is None:
            raise OperationError("unexpected_peer_operation")
        validate(result, RESULT_SCHEMA)
        if result["operation_id"] != binding["operation_id"]:
            raise OperationError("peer_operation_mismatch")
    # Even a schema-valid 'succeeded' peer response is a claim, never authenticated
    # tool execution or approval. The stored verification label remains unchanged.
    return runtime.store.accept_delegation(document["delegation_id"], expected, peer)
