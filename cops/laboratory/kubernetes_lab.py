"""Registered, air-gapped Kubernetes fixture; never uses an ambient kubeconfig.

The privileged node shares the Docker host kernel. This is acceptance machinery
for fixed synthetic pods, not a production worker sandbox or a cluster connector.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import secrets
import shutil
import subprocess
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cops.contracts.models import Engagement
from cops.evidence.canonical import digest
from cops.execution.authorization import AuthorizationSigner, AuthorizationTrustStore, TrustedAuthorizationKey
from cops.execution.store import ApprovalStore
from cops.laboratory.container_runtime import _docker_command
from cops.laboratory.integrated_lab import _IntegratedApprovalControl
from cops.laboratory.workflow_lab import WORKER, _action, _utc
from cops.workflows.contracts import WorkflowDefinition
from cops.workflows.runtime import StageExecutionResult, WorkflowRunner

ADAPTER_ID = "isolated-k3s-containment/v1"
STAGES = ("snapshot", "review", "propose", "lab_apply", "verify")
# Platform-specific manifests, resolved from the publishers' OCI indexes. Pulls
# are an explicit provisioning step; this adapter never pulls or builds images.
IMAGE_PINS = MappingProxyType(
    {
        "arm64": (
            "rancher/k3s@sha256:c20f2c044a28cf217440464a810fb81715a48192716a5bc99eaf2c3113a9cfb4",
            "rancher/mirrored-pause@sha256:a433214620b407678934ebd69690a9ed6066247231eacfba181fab20dbc3dbf1",
            "python:3.14.6-slim@sha256:34bf30c914ac17d2a0f7ecf94866e54380669d618ae4673672445516603ad8d7",
        ),
        "amd64": (
            "rancher/k3s@sha256:b032bfb68a10fee30ab60c160d32a6b3af7ea33620e9f7a29d59890e42ceefed",
            "rancher/mirrored-pause@sha256:412c4a7219cb8a299a37337f3d87810c5340095322e15594a1637785adad0f17",
            "python:3.14.6-slim@sha256:b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967",
        ),
    }
)
_LABEL = "org.cops.kubernetes-laboratory"
_VOLUMES = {"/var/lib/cni", "/var/lib/kubelet", "/var/lib/rancher/k3s", "/var/log"}
_SERVER = """import http.server,json,datetime
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  print(json.dumps({"path":self.path,"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat(),"status":200}),flush=True)
  self.send_response(200); self.end_headers(); self.wfile.write(b"fixture")
 def log_message(self,*args): pass
http.server.HTTPServer(("0.0.0.0",8080),Handler).serve_forever()
"""
_CLIENT = """import json,sys,urllib.request,urllib.error
try:
 r=urllib.request.urlopen(sys.argv[1],timeout=2); print(json.dumps({"status":r.status,"blocked":False}))
except (urllib.error.URLError,TimeoutError,OSError):
 print(json.dumps({"status":None,"blocked":True}))
"""


def containment_policy(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "containment", "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": {"role": "server"}},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [{"podSelector": {"matchLabels": {"role": "required"}}}],
                    "ports": [{"protocol": "TCP", "port": 8080}],
                }
            ],
        },
    }


def verify_egress(probes: object) -> None:
    definitive = {
        "ENETUNREACH",
        "EHOSTUNREACH",
        "ENETDOWN",
        "EADDRNOTAVAIL",
        "EAFNOSUPPORT",
        "EPROTONOSUPPORT",
        "EACCES",
        "EPERM",
    }
    if (
        not isinstance(probes, list)
        or len(probes) != 2
        or any(not isinstance(probe, dict) for probe in probes)
        or {probe.get("family") for probe in probes} != {"IPv4", "IPv6"}
        or any(probe.get("reachable") is not False or probe.get("error") not in definitive for probe in probes)
    ):
        raise ValueError("Kubernetes external connectivity evidence is inconclusive or reachable")


def workflow_definition() -> WorkflowDefinition:
    stages = []
    for index, name in enumerate(STAGES):
        inputs = {"configuration": {"type": "object", "source": "workflow.input.configuration"}}
        if index:
            inputs["prior"] = {"type": "object", "source": "stage." + STAGES[index - 1] + ".output.observations"}
        action = _action(name)
        action.update(
            tool=ADAPTER_ID,
            timeout_seconds=60,
            limits={"max_duration_seconds": 90, "max_output_bytes": 65536, "egress_allowed": False},
            expected_evidence=["kubernetes-audit:" + name, "http:" + name],
        )
        stages.append(
            {
                "stage_id": name,
                "depends_on": list(STAGES[index - 1 : index]) if index else [],
                "inputs": inputs,
                "outputs": {"observations": {"type": "object"}},
                "action": action,
            }
        )
    return WorkflowDefinition.from_dict(
        {
            "schema_version": "cops.workflow-definition/v1",
            "workflow_id": "laboratory-kubernetes-containment",
            "engagement_id": "eng-kubernetes-laboratory",
            "scenario_id": "scen-kubernetes-compromise-containment",
            "inputs": {"configuration": {"type": "object", "required": True}},
            "outputs": {"assessment": {"type": "object", "source": "stage.verify.output.observations"}},
            "budget": {"max_stages": 5, "max_total_attempts": 5, "max_output_bytes": 262144, "max_evidence_refs": 32},
            "stages": stages,
        }
    )


def inspect_node(value: dict[str, Any], *, image: str, nonce: str) -> None:
    host, config, mounts = value["HostConfig"], value["Config"], value["Mounts"]
    if not all(
        (
            value["Image"] == image,
            host["NetworkMode"] == "none",
            host["Privileged"] is True,
            not host.get("PortBindings"),
            not host.get("PublishAllPorts"),
            not host.get("Binds"),
            not host.get("Devices"),
            not host.get("DeviceRequests"),
            host.get("PidMode", "") == "",
            host.get("IpcMode") == "private",
            host.get("PidsLimit") == 768,
            host.get("Memory") == 3 * 1024**3,
            host.get("NanoCpus") == 2_000_000_000,
            set(host.get("Tmpfs", {})) == {"/run", "/var/run"},
            config.get("Labels", {}).get(_LABEL) == nonce,
            config.get("Entrypoint") == ["/bin/sh"],
            config.get("Cmd") == ["-c", _bootstrap("docker.io/cops-laboratory/pause:" + nonce)],
            len(mounts) == len(_VOLUMES),
            {mount["Destination"] for mount in mounts} == _VOLUMES,
            all(mount["Type"] == "volume" and mount.get("Name") for mount in mounts),
        )
    ):
        raise ValueError("Kubernetes node isolation or resource configuration changed")


def audit_evidence(raw: str, namespace: str) -> list[dict[str, Any]]:
    if len(raw.encode()) > 1024 * 1024:
        raise ValueError("Kubernetes audit evidence exceeds its budget")
    events = []
    for line in raw.splitlines():
        event = json.loads(line)
        obj = event.get("objectRef", {})
        if obj.get("namespace") != namespace or event.get("stage") != "ResponseComplete":
            continue
        # Metadata only: never persist request/response bodies, credentials, or users.
        events.append(
            {
                "audit_id": event["auditID"],
                "timestamp": event["stageTimestamp"],
                "verb": event["verb"],
                "resource": obj.get("resource"),
                "name": obj.get("name"),
                "namespace": namespace,
                "status": event.get("responseStatus", {}).get("code"),
                "record_sha256": digest(event),
            }
        )
    if len(events) > 2048:
        raise ValueError("Kubernetes audit record budget exceeded")
    return events


def verify_audit(events: list[dict[str, Any]]) -> None:
    for verb in ("create", "delete"):
        if not any(
            event["resource"] == "networkpolicies"
            and event["name"] == "containment"
            and event["verb"] == verb
            and event["status"] in (200, 201, 202)
            for event in events
        ):
            raise ValueError("required containment audit evidence is missing")


def verify_http(events: list[dict[str, Any]], observations: dict[str, Any], restored: list[dict[str, Any]]) -> None:
    """Require captured server telemetry for each successful correlated request."""
    from urllib.parse import urlsplit

    requests = [*restored]
    for phase in ("baseline", "contained", "verified"):
        requests.extend(observations.get(phase, []))
    for request in requests:
        path = urlsplit(request["destination"]).path
        matches = [event for event in events if event.get("path") == path and event.get("status") == 200]
        if request["status"] == 200 and not matches:
            raise ValueError("correlated Kubernetes HTTP evidence is missing")
        # Convergence retries may legitimately have reached the server before the
        # policy settled. Final blocked requests are established by client probes.
        for event in matches:
            timestamp = datetime.fromisoformat(event["timestamp"])
            if timestamp.tzinfo is None:
                raise ValueError("Kubernetes HTTP evidence lacks a timezone")


class _Node:
    def __init__(self, docker: str, directory: Path, nonce: str, timeout: int) -> None:
        self.docker, self.directory, self.nonce = docker, directory, nonce
        self.name = "cops-kubernetes-" + nonce
        self.deadline = time.monotonic() + timeout
        self.cleaning = False
        self.cleanup_deadline: float | None = None
        self.namespace = ""

    def command(self, *arguments: str, seconds: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
        if self.cleaning and self.cleanup_deadline is None:
            self.cleanup_deadline = time.monotonic() + 90
        remaining = int((self.cleanup_deadline if self.cleaning else self.deadline) - time.monotonic())
        if remaining <= 0:
            raise TimeoutError("Kubernetes laboratory deadline exceeded")
        result = _docker_command(self.docker, list(arguments), seconds=min(seconds, remaining))
        if check and result.returncode:
            raise ValueError("Kubernetes fixture command failed: " + arguments[0])
        return result

    def kube(self, *arguments: str, seconds: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.command(
            "exec", self.name, "kubectl", "--request-timeout=15s", *arguments, seconds=seconds, check=check
        )

    def apply(self, value: dict[str, Any], filename: str) -> None:
        path = self.directory / filename
        path.write_text(json.dumps(value))
        self.command("cp", str(path), self.name + ":/tmp/" + filename)
        self.kube("apply", "-f", "/tmp/" + filename)  # noqa: S108  # Path inside the owned Kubernetes container.

    def read(self, kind: str, name: str) -> dict[str, Any]:
        return json.loads(self.kube("get", kind, name, "-n", self.namespace, "-o", "json").stdout)

    def request(self, role: str, destination: str, phase: str) -> dict[str, Any]:
        url = destination + "/" + self.nonce + "/" + self.namespace + "/" + role + "/" + phase
        result = json.loads(self.kube("exec", "-n", self.namespace, role, "--", "python", "-c", _CLIENT, url).stdout)
        return {"role": role, "phase": phase, "destination": url, **result}

    def restore(self) -> None:
        self.kube("delete", "networkpolicy", "containment", "-n", self.namespace, "--ignore-not-found=true")

    def await_paths(self, destination: str, *, blocked: bool, phase: str) -> list[dict[str, Any]]:
        for _ in range(12):
            results = [self.request(role, destination, phase) for role in ("required", "forbidden")]
            if (
                results[0]["status"] == 200
                and results[1]["blocked"] == blocked
                and (blocked or results[1]["status"] == 200)
            ):
                return results
            time.sleep(1)
        raise ValueError("Kubernetes observed connectivity differs from the expected policy")


class _Executor:
    def __init__(self, node: _Node, configuration: dict[str, Any], mode: str) -> None:
        self.node, self.configuration, self.mode = node, copy.deepcopy(configuration), mode
        self.executed: list[str] = []
        self.observations: dict[str, Any] = {}
        self.cleanup_count = 0

    def execute(self, plan: Any, receipt: Any, *, idempotency_key: str) -> StageExecutionResult:
        operation = plan.to_dict()["operations"][0]
        expected = {"configuration": self.configuration}
        if self.executed:
            expected["prior"] = self.observations
        if (
            len(self.executed) >= len(STAGES)
            or operation["action"] != STAGES[len(self.executed)]
            or operation["arguments"] != expected
        ):
            raise ValueError("Kubernetes action, configuration, or preceding evidence changed")
        # Resolve the live UID again before every stage; names are not identities.
        if self.node.read("namespace", self.node.namespace)["metadata"]["uid"] != self.configuration["namespace_uid"]:
            raise ValueError("Kubernetes namespace identity changed")
        name = operation["action"]
        self.executed.append(name)
        destination = self.configuration["destination"]
        if name == "snapshot":
            self.observations["baseline"] = self.node.await_paths(destination, blocked=False, phase="baseline")
            self.observations["pod_snapshot_sha256"] = digest(self.node.read("pod", "server"))
        elif name == "review":
            pod = self.node.read("pod", "server")
            sa = self.node.read("serviceaccount", "probe")
            self.observations["service_account"] = {
                "uid": sa["metadata"]["uid"],
                "name": sa["metadata"]["name"],
                "token_mounted": pod["spec"].get("automountServiceAccountToken") is not False,
            }
            if self.observations["service_account"]["token_mounted"]:
                raise ValueError("fixture service account unexpectedly exposes a token")
        elif name == "propose":
            self.observations["policy_sha256"] = digest(self.configuration["policy"])
        elif name == "lab_apply":
            self.node.apply(self.configuration["policy"], "containment.json")
            self.observations["contained"] = self.node.await_paths(destination, blocked=True, phase="contained")
            if self.mode == "failure":
                return StageExecutionResult("failed", reason="injected failure after actual policy enforcement")
        elif name == "verify":
            self.observations["verified"] = self.node.await_paths(destination, blocked=True, phase="verified")
        return StageExecutionResult(
            "success",
            outputs={"observations": copy.deepcopy(self.observations)},
            evidence_refs=("kubernetes:" + idempotency_key,),
        )

    def cleanup(self, plan: Any, *, idempotency_key: str) -> None:
        self.cleanup_count += 1
        self.node.restore()


def _run_case(node: _Node, directory: Path, mode: str, images: tuple[str, ...]) -> dict[str, Any]:
    definition = workflow_definition()
    current = datetime.now(UTC).replace(microsecond=0)
    now, start, end = _utc(current), _utc(current - timedelta(minutes=1)), _utc(current + timedelta(minutes=30))
    key = secrets.token_bytes(32)
    signer = AuthorizationSigner("kubernetes-lab-key", "laboratory-operator", key, start, end)
    trust = AuthorizationTrustStore(
        [TrustedAuthorizationKey("kubernetes-lab-key", "laboratory-operator", key, start, end)]
    )
    engagement = Engagement.from_dict(
        {
            "schema_version": "cops.engagement/v1",
            "engagement_id": definition.engagement_id,
            "name": "Isolated Kubernetes fixture",
            "status": "active",
            "scope": {"included_targets": ["laboratory-loopback-services"], "excluded_targets": []},
            "window": {"started_at": start, "authorized_until_utc": end},
            "operator": "laboratory-operator",
            "rules_of_engagement": {
                "max_intensity": "low",
                "allowed_actions": list(STAGES),
                "emergency_contact": "soc@example.test",
                "safe_mode": True,
            },
            "created_at": start,
            "mode": "laboratory",
        }
    )
    pod_ip = str(ipaddress.IPv4Address(node.read("pod", "server")["status"]["podIP"]))
    if ipaddress.ip_address(pod_ip) not in ipaddress.ip_network("10.42.0.0/16"):
        raise ValueError("fixture server escaped the registered pod network")
    configuration = {
        "namespace": node.namespace,
        "namespace_uid": node.read("namespace", node.namespace)["metadata"]["uid"],
        "destination": "http://" + pod_ip + ":8080",
        "images": list(images),
        "policy": containment_policy(node.namespace),
        "node": node.name,
        "adapter": ADAPTER_ID,
    }
    run_id = "kubernetes-" + node.nonce + "-" + mode
    auth_ids = {name: "auth-" + digest({"run_id": run_id, "stage": name})[:24] for name in STAGES}
    store = ApprovalStore(directory / "approvals.sqlite3")
    executor = _Executor(node, configuration, mode)
    approval = _IntegratedApprovalControl(
        store,
        trust,
        engagement,
        now,
        signer=signer,
        authorized_until=end,
        definition=definition,
        run_id=run_id,
        executor=executor,
        authorization_ids=auth_ids,
    )
    runner = WorkflowRunner(directory / "workflow-state", approval, WORKER, executor, clock=lambda: now)
    try:
        result = runner.run(
            definition,
            run_id=run_id,
            inputs={"configuration": configuration},
            authorization_ids=auth_ids,
            cancellation_requested=lambda: mode == "cancellation" and "lab_apply" in executor.executed,
        )
    finally:
        # Also restore after cancellation or an exception outside a stage.
        node.restore()
    restored = node.await_paths(configuration["destination"], blocked=False, phase="restored")
    server_events = [json.loads(line) for line in node.kube("logs", "server", "-n", node.namespace).stdout.splitlines()]
    verify_http(server_events, executor.observations, restored)
    audit = audit_evidence(node.command("exec", node.name, "cat", "/var/log/cops-audit.jsonl").stdout, node.namespace)
    verify_audit(audit)
    expected_status = {"success": "success", "failure": "partial_failure", "cancellation": "cancelled"}[mode]
    if result.status != expected_status or not server_events or (mode == "failure" and executor.cleanup_count != 1):
        raise ValueError("Kubernetes workflow state or cleanup did not match the acceptance case")
    consumed = sum(store.get_authorization(auth_ids[name]).status == "consumed" for name in approval.plan_digests)
    if consumed != len(executor.executed):
        raise ValueError("Kubernetes action approval was not consumed exactly once")
    return {
        "mode": mode,
        "passed": True,
        "workflow_status": result.status,
        "stages": executor.executed,
        "observations": executor.observations,
        "restored": restored,
        "server_events": server_events,
        "audit_events": audit,
        "audit_sha256": digest(audit),
        "namespace_uid": configuration["namespace_uid"],
        "authorization": {"consumed": consumed, "plan_digests": approval.plan_digests},
        "failure_cleanup_count": executor.cleanup_count,
    }


def _bootstrap(pause_tag: str) -> str:
    return (
        "ip link add cops0 type dummy && ip addr add 192.0.2.10/32 dev cops0 && ip link set cops0 up && "
        "exec k3s server --node-ip 192.0.2.10 --advertise-address 192.0.2.10 --bind-address 0.0.0.0 "
        "--flannel-iface cops0 --flannel-backend host-gw --snapshotter overlayfs --pause-image " + pause_tag + " "
        "--disable coredns,traefik,servicelb,metrics-server,local-storage,runtimes "
        "--disable-cloud-controller --disable-helm-controller "
        "--kube-apiserver-arg=audit-policy-file=/tmp/audit.json "
        "--kube-apiserver-arg=audit-log-path=/var/log/cops-audit.jsonl "
        "--kube-apiserver-arg=audit-log-maxsize=1 --kube-apiserver-arg=audit-log-maxbackup=1"
    )


def run_kubernetes_laboratory(*, timeout: int = 480) -> dict[str, Any]:
    """Run all three lifecycle paths against one owned, network-none K3s node."""
    if type(timeout) is not int or not 180 <= timeout <= 600:
        raise ValueError("Kubernetes laboratory timeout must be between 180 and 600 seconds")
    report: dict[str, Any] = {
        "adapter": ADAPTER_ID,
        "status": "blocked",
        "cases": [],
        "failures": [],
        "blockers": [],
        "isolation": {"verified": False},
        "cleanup": {"verified": False},
        "limitations": [
            "privileged fixture node shares the Docker host kernel; use a disposable Docker VM",
            "fixed synthetic pods and ephemeral in-process approvals; no production cluster support",
        ],
    }
    docker = shutil.which("docker")
    if docker is None:
        report["blockers"] = ["Docker CLI is unavailable"]
        return report
    nonce = secrets.token_hex(16)
    probe_tag, pause_tag = ("docker.io/cops-laboratory/" + name + ":" + nonce for name in ("probe", "pause"))
    owned_tags: list[str] = []
    create_attempted = False
    volumes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="cops-kubernetes-") as temporary:
        path = Path(temporary)
        node = _Node(docker, path, nonce, timeout)
        stage = "prerequisites"
        try:
            info = json.loads(node.command("info", "--format", "{{json .}}").stdout)
            architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(
                info.get("Architecture"), info.get("Architecture")
            )
            if info.get("OSType") != "linux" or architecture not in IMAGE_PINS:
                raise ValueError("unsupported Docker server platform")
            images = IMAGE_PINS[architecture]
            inspected_images = [json.loads(node.command("image", "inspect", image).stdout)[0] for image in images]
            if any(image["Os"] != "linux" or image["Architecture"] != architecture for image in inspected_images):
                raise ValueError("pinned image platform does not match Docker")
            report["images"] = list(images)
            report["nonce"] = nonce
            stage = "setup"
            for source, tag in ((images[2], probe_tag), (images[1], pause_tag)):
                owned_tags.append(tag)  # Retain cleanup ownership even after a command timeout.
                node.command("tag", source, tag)
            archive = path / "images.tar"
            node.command("save", "--output", str(archive), probe_tag, pause_tag, seconds=60)
            if not 0 < archive.stat().st_size <= 256 * 1024**2:
                raise ValueError("Kubernetes prerequisite archive exceeds its budget")
            namespaces = ["cops-" + nonce[:16] + "-" + mode for mode in ("success", "failure", "cancellation")]
            audit_policy = {
                "apiVersion": "audit.k8s.io/v1",
                "kind": "Policy",
                "omitStages": ["RequestReceived"],
                "rules": [{"level": "Metadata", "namespaces": namespaces}, {"level": "None"}],
            }
            (path / "audit.json").write_text(json.dumps(audit_policy))
            create_attempted = True
            node.command(
                "create",
                "--name",
                node.name,
                "--label",
                _LABEL + "=" + nonce,
                "--pull",
                "never",
                "--privileged",
                "--network",
                "none",
                "--memory",
                "3g",
                "--cpus",
                "2",
                "--pids-limit",
                "768",
                "--ipc",
                "private",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/var/run",
                "--entrypoint",
                "/bin/sh",
                images[0],
                "-c",
                _bootstrap(pause_tag),
            )
            configuration = json.loads(node.command("inspect", node.name).stdout)[0]
            inspect_node(configuration, image=inspected_images[0]["Id"], nonce=nonce)
            volumes = [mount["Name"] for mount in configuration["Mounts"]]
            node.command("cp", str(archive), node.name + ":/var/lib/rancher/k3s/agent-images.tar", seconds=60)
            node.command("cp", str(path / "audit.json"), node.name + ":/tmp/audit.json")
            node.command("start", node.name)
            node.command(
                "exec",
                node.name,
                "sh",
                "-c",
                "mkdir -p /var/lib/rancher/k3s/agent/images && mv /var/lib/rancher/k3s/agent-images.tar /var/lib/rancher/k3s/agent/images/owned.tar",
            )
            stage = "readiness"
            for _ in range(60):
                ready = node.kube("get", "nodes", "-o", "json", check=False)
                if ready.returncode == 0 and any(
                    condition.get("type") == "Ready" and condition.get("status") == "True"
                    for item in json.loads(ready.stdout)["items"]
                    for condition in item["status"]["conditions"]
                ):
                    break
                time.sleep(2)
            else:
                raise TimeoutError("Kubernetes node did not become ready")
            routes = {
                family: json.loads(node.command("exec", node.name, "ip", family, "-j", "route").stdout)
                for family in ("-4", "-6")
            }
            if any(
                route.get("dst") in ("default", "0.0.0.0/0", "::/0") for entries in routes.values() for route in entries
            ):
                raise ValueError("Kubernetes node has an external default route")
            stage = "containment"
            for mode, namespace in zip(("success", "failure", "cancellation"), namespaces, strict=True):
                node.namespace = namespace
                node.kube("create", "namespace", namespace)
                node.kube("create", "serviceaccount", "probe", "-n", namespace)
                pods = [
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": role, "namespace": namespace, "labels": {"role": role}},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "serviceAccountName": "probe",
                            "containers": [
                                {
                                    "name": "probe",
                                    "image": probe_tag,
                                    "imagePullPolicy": "Never",
                                    "command": [
                                        "python",
                                        "-u",
                                        "-c",
                                        _SERVER if role == "server" else "import time; time.sleep(600)",
                                    ],
                                }
                            ],
                        },
                    }
                    for role in ("server", "required", "forbidden")
                ]
                node.apply({"apiVersion": "v1", "kind": "List", "items": pods}, "pods.json")
                node.kube(
                    "wait", "--for=condition=Ready", "pod", "--all", "-n", namespace, "--timeout=90s", seconds=100
                )
                egress_script = 'import socket,json,errno\nr=[]\nfor f,a,n in ((socket.AF_INET,("198.51.100.1",443),"IPv4"),(socket.AF_INET6,("2001:db8::1",443),"IPv6")):\n s=socket.socket(f); s.settimeout(3)\n try: s.connect(a); r.append({"family":n,"reachable":True})\n except OSError as e: r.append({"family":n,"reachable":False,"error":errno.errorcode.get(e.errno)})\n finally: s.close()\nprint(json.dumps(r))'
                egress = json.loads(
                    node.kube("exec", "-n", namespace, "required", "--", "python", "-c", egress_script).stdout
                )
                verify_egress(egress)
                directory = path / mode
                directory.mkdir(mode=0o700)
                case = _run_case(node, directory, mode, images)
                case["egress_probes"] = egress
                node.kube("delete", "namespace", namespace, "--wait=true", "--timeout=45s", seconds=55)
                remaining = json.loads(node.kube("get", "namespaces", "-o", "json").stdout)
                case["namespace_removed"] = all(item["metadata"]["name"] != namespace for item in remaining["items"])
                if not case["namespace_removed"]:
                    raise ValueError("Kubernetes namespace cleanup could not be verified")
                report["cases"].append(case)
            inspect_node(
                json.loads(node.command("inspect", node.name).stdout)[0], image=inspected_images[0]["Id"], nonce=nonce
            )
            report["isolation"] = {
                "verified": True,
                "mechanism": "docker-network-none",
                "node_routes": routes,
                "host_mounts": False,
                "host_ports": False,
                "configuration_inspected_before_and_after": True,
            }
            report["status"] = "passed"
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError) as exc:
            report["status"] = "blocked" if stage == "prerequisites" else "failed"
            report["blockers" if stage == "prerequisites" else "failures"].append(
                "Kubernetes laboratory " + stage + " failed (" + type(exc).__name__ + "); raw runtime output withheld"
            )
        finally:
            node.cleaning = True
            try:
                if create_attempted:
                    owned = node.command("inspect", node.name, check=False)
                    if owned.returncode == 0:
                        inspected = json.loads(owned.stdout)[0]
                        if inspected.get("Config", {}).get("Labels", {}).get(_LABEL) != nonce:
                            raise ValueError("Kubernetes cleanup ownership changed")
                        node.command("rm", "--force", "--volumes", inspected["Id"])
                    remaining = node.command(
                        "container", "ls", "--all", "--quiet", "--filter", "name=^/" + node.name + "$"
                    )
                    if remaining.stdout.strip():
                        raise ValueError("Kubernetes node still exists")
                    for volume in volumes:
                        existing = node.command("volume", "ls", "--quiet", "--filter", "name=^" + volume + "$")
                        if existing.stdout.strip():
                            raise ValueError("Kubernetes anonymous volume still exists")
                for tag in owned_tags:
                    node.command("image", "rm", tag, check=False)
                    existing = node.command("image", "ls", "--quiet", "--filter", "reference=" + tag)
                    if existing.stdout.strip():
                        raise ValueError("Kubernetes owned image tag still exists")
                report["cleanup"] = {
                    "verified": True,
                    "node_removed": create_attempted,
                    "owned_tags_removed": len(owned_tags),
                }
            except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError):
                report["status"] = "failed"
                report["failures"].append("Kubernetes fixture cleanup could not be verified")
    return report
