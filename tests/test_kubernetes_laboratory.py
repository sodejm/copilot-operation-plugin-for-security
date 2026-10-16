from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cops.laboratory import kubernetes_lab as lab
from cops.workflows.runtime import compile_action_plan


def configuration() -> dict:
    return {"Image": "sha256:fixture", "HostConfig": {
        "NetworkMode": "none", "Privileged": True, "IpcMode": "private", "PidsLimit": 768,
        "Memory": 3 * 1024**3, "NanoCpus": 2_000_000_000, "Tmpfs": {"/run": "", "/var/run": ""}},
        "Config": {"Labels": {lab._LABEL: "nonce"}, "Entrypoint": ["/bin/sh"],
                   "Cmd": ["-c", lab._bootstrap("docker.io/cops-laboratory/pause:nonce")]},
        "Mounts": [{"Type": "volume", "Name": str(index), "Destination": destination}
                   for index, destination in enumerate(sorted(lab._VOLUMES))]}


def test_node_configuration_and_workflow_contract() -> None:
    lab.inspect_node(configuration(), image="sha256:fixture", nonce="nonce")
    definition = lab.workflow_definition()
    assert tuple(stage["stage_id"] for stage in definition.stages) == lab.STAGES
    assert all(stage["action"]["tool"] == lab.ADAPTER_ID for stage in definition.stages)
    assert all(stage["action"]["limits"]["egress_allowed"] is False for stage in definition.stages)
    assert all(len(images) == 3 and all("@sha256:" in image for image in images) for images in lab.IMAGE_PINS.values())


@pytest.mark.parametrize(("section", "key", "value"), [
    ("HostConfig", "NetworkMode", "host"), ("HostConfig", "Binds", ["/:/host"]),
    ("HostConfig", "PidMode", "host"), ("HostConfig", "IpcMode", "host"),
    ("HostConfig", "PortBindings", {"6443/tcp": [{"HostPort": "6443"}]}),
    ("HostConfig", "Devices", [{"PathOnHost": "/dev/sda"}]),
    ("HostConfig", "Memory", 0), ("HostConfig", "NanoCpus", 0),
    ("HostConfig", "PidsLimit", 0), ("Config", "Cmd", ["-c", "unreviewed"]),
    ("Config", "Labels", {lab._LABEL: "other-owner"}),
])
def test_changed_node_boundary_is_rejected(section: str, key: str, value: object) -> None:
    actual = configuration()
    actual[section][key] = value
    with pytest.raises(ValueError, match="configuration changed"):
        lab.inspect_node(actual, image="sha256:fixture", nonce="nonce")


def test_host_mount_cannot_replace_owned_volume() -> None:
    actual = configuration()
    actual["Mounts"][0]["Type"] = "bind"
    with pytest.raises(ValueError):
        lab.inspect_node(actual, image="sha256:fixture", nonce="nonce")


def event(verb: str, **overrides: object) -> dict:
    return {"auditID": verb, "stageTimestamp": "2026-10-16T00:00:00Z", "stage": "ResponseComplete",
            "verb": verb, "objectRef": {"namespace": "fixture", "resource": "networkpolicies", "name": "containment"},
            "responseStatus": {"code": 201 if verb == "create" else 200},
            "user": {"credential": "must-not-export"}, "requestObject": {"secret": "must-not-export"}, **overrides}


def test_audit_requires_actual_successful_apply_and_cleanup_and_redacts_bodies() -> None:
    raw = "\n".join(json.dumps(record) for record in (event("create"), event("delete"), event("delete", stage="RequestReceived")))
    events = lab.audit_evidence(raw, "fixture")
    lab.verify_audit(events)
    assert len(events) == 2 and all(item["record_sha256"] for item in events)
    assert "must-not-export" not in json.dumps(events)
    assert lab.audit_evidence(raw, "different-namespace") == []
    with pytest.raises(ValueError, match="missing"):
        lab.verify_audit(events[:1])
    events[1]["status"] = 403
    with pytest.raises(ValueError, match="missing"):
        lab.verify_audit(events)
    with pytest.raises(ValueError, match="budget"):
        lab.audit_evidence("x" * (1024 * 1024 + 1), "fixture")


def test_http_evidence_must_match_correlated_successful_requests() -> None:
    request = {"destination": "http://10.42.0.2:8080/run/namespace/required/restored", "status": 200}
    events = [{"path": "/unrelated", "status": 200, "timestamp": "2026-10-16T00:00:00Z"}]
    with pytest.raises(ValueError, match="missing"):
        lab.verify_http(events, {}, [request])
    events[0]["path"] = "/run/namespace/required/restored"
    lab.verify_http(events, {}, [request])
    events[0]["timestamp"] = "2026-10-16T00:00:00"
    with pytest.raises(ValueError, match="timezone"):
        lab.verify_http(events, {}, [request])


@pytest.mark.parametrize("change", ["uid", "input", "prior", "action"])
def test_executor_rejects_scope_or_evidence_change_before_activity(change: str) -> None:
    node = SimpleNamespace(namespace="fixture", read=lambda *_: {"metadata": {"uid": "original"}})
    config = {"namespace_uid": "original", "destination": "http://10.42.0.2:8080"}
    executor = lab._Executor(node, config, "success")
    stage = "snapshot"
    resolved = {"configuration": copy.deepcopy(config)}
    if change == "uid":
        node.read = lambda *_: {"metadata": {"uid": "replaced"}}
    elif change == "input":
        resolved["configuration"]["destination"] = "http://198.51.100.1"
    elif change == "action":
        stage = "review"
        resolved["prior"] = {}
    else:
        executor.executed = ["snapshot"]
        executor.observations = {"snapshot": "bound"}
        stage = "review"
        resolved["prior"] = {"snapshot": "tampered"}
    plan = compile_action_plan(lab.workflow_definition(), "run-fixture", stage, resolved, "2026-10-16T00:00:00Z")
    with pytest.raises(ValueError, match="changed"):
        executor.execute(plan, None, idempotency_key="key")


def test_unavailable_docker_blocks_without_attempting_work(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab.shutil, "which", lambda _: None)
    report = lab.run_kubernetes_laboratory()
    assert report["status"] == "blocked" and report["cases"] == []
    assert report["isolation"]["verified"] is False


@pytest.mark.parametrize("error", [None, "ETIMEDOUT", "ECONNREFUSED", "unknown", True])
def test_egress_requires_definitive_failure_for_both_families(error: object) -> None:
    probes = [{"family": family, "reachable": False, "error": "ENETUNREACH"} for family in ("IPv4", "IPv6")]
    lab.verify_egress(probes)
    probes[1]["error"] = error
    with pytest.raises(ValueError, match="inconclusive"):
        lab.verify_egress(probes)


@pytest.mark.parametrize("probes", [None, [], [None, None],
    [{"family": "IPv4", "reachable": False, "error": "EPERM"}] * 2,
    [{"family": family, "reachable": True, "error": "EPERM"} for family in ("IPv4", "IPv6")]])
def test_egress_rejects_missing_malformed_or_reachable_evidence(probes: object) -> None:
    with pytest.raises(ValueError, match="inconclusive"):
        lab.verify_egress(probes)


@pytest.mark.parametrize("timeout", [True, 179, 601, 180.5])
def test_timeout_budget_is_strict(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout"):
        lab.run_kubernetes_laboratory(timeout=timeout)


def test_cleanup_has_one_shared_deadline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    clock = [100.0]
    monkeypatch.setattr(lab.time, "monotonic", lambda: clock[0])
    node = lab._Node("docker", tmp_path, "fixture", 480)
    node.cleaning = True
    monkeypatch.setattr(lab, "_docker_command", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    node.command("inspect")
    clock[0] = 191.0
    with pytest.raises(TimeoutError):
        node.command("inspect")
