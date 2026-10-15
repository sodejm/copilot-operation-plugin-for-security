"""Disposable local services and offline playback for laboratory acceptance."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal

from .network_boundary import inspect_acceptance_boundary
from .service_authentication import run_api_acceptance, run_jwt_acceptance
from .service_boundaries import run_acquisition_acceptance, run_boundary_acceptance
from .service_tls import TLSAcceptanceResult, run_ephemeral_mtls_acceptance
from .source_snapshot import bounded_read

FIXTURE_DIRECTORY = Path(__file__).with_name("service_fixtures")
REPORT_SCHEMA = "cops.service-laboratory-report/v1"


@dataclass(frozen=True)
class IsolationProbe:
    """Readiness evidence; availability alone never claims verified isolation."""

    verified: bool
    mechanism: str
    blocker: str | None
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ServiceLaboratoryReport:
    """Normalized artifact emitted by offline or live process acceptance."""

    run_id: str
    path: Literal["offline-playback", "process-acceptance"]
    service_activity: dict[str, Any]
    detection_counts: dict[str, int]
    tls: dict[str, Any] | None
    restoration: dict[str, bool]
    isolation: IsolationProbe
    fixture_manifest_digest: str
    telemetry_events: tuple[dict[str, Any], ...] = ()
    alert_events: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = ()
    schema_version: str = REPORT_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "path": self.path,
            "service_activity": self.service_activity,
            "detection_counts": self.detection_counts,
            "tls": self.tls,
            "restoration": self.restoration,
            "isolation": self.isolation.to_dict(),
            "fixture_manifest_digest": self.fixture_manifest_digest,
            "telemetry_events": list(self.telemetry_events),
            "alert_events": list(self.alert_events),
            "limitations": list(self.limitations),
        }


@dataclass
class _State:
    profile: str
    tokens: dict[str, bool] = field(default_factory=dict)
    iocs: list[str] = field(default_factory=list)
    contained: list[str] = field(default_factory=list)

    def snapshot(self) -> str:
        payload = json.dumps(
            {"profile": self.profile, "tokens": self.tokens, "iocs": self.iocs, "contained": self.contained},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def restore(self, other: _State) -> None:
        self.profile = other.profile
        self.tokens = dict(other.tokens)
        self.iocs = list(other.iocs)
        self.contained = list(other.contained)

    def copy(self) -> _State:
        return _State(self.profile, dict(self.tokens), list(self.iocs), list(self.contained))


class _Telemetry:
    def __init__(self, path: Path, *, correlation_id: str) -> None:
        self.path = path
        self.correlation_id = correlation_id
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, event: str, *, risk: str, **details: Any) -> None:
        entry = {
            "correlation_id": self.correlation_id,
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "event": event,
            "risk": risk,
            **details,
        }
        with self._lock:
            self.events.append(entry)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def _json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if not 0 <= length <= 64 * 1024:
        raise ValueError("laboratory request exceeds its body budget")
    raw = handler.rfile.read(length)
    body = json.loads(raw or b"{}")
    if not isinstance(body, dict):
        raise ValueError("laboratory request must be an object")
    return body


def _reply(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _quiet(handler: BaseHTTPRequestHandler, _format: str, *_args: object) -> None:
    del handler


class _Service:
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class _Graph:
    """Four actual loopback services sharing only explicit service calls and state."""

    def __init__(self, configuration: dict[str, Any], telemetry: _Telemetry) -> None:
        self.configuration = configuration
        self.state = _State(str(configuration["profile"]))
        self.baseline = self.state.copy()
        self.telemetry = telemetry
        self._lock = threading.Lock()
        self.sink = _Service(self._sink_handler())
        self.identity = _Service(self._identity_handler())
        self.resource = _Service(self._resource_handler())
        self.hunt = _Service(self._hunt_handler())
        self.services = (self.sink, self.identity, self.resource, self.hunt)
        self.final_reset_verified = False

    def _sink_handler(self) -> type[BaseHTTPRequestHandler]:
        telemetry = self.telemetry

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/target":
                    self.send_error(404)
                    return
                telemetry.record("sink_reached", risk="attack")
                _reply(self, 200, {"reached": True})

            log_message = _quiet

        return Handler

    def _identity_handler(self) -> type[BaseHTTPRequestHandler]:
        state, lock, telemetry = self.state, self._lock, self.telemetry

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                data = _json_body(self)
                token = str(data.get("token", ""))
                if self.path == "/issue" and token:
                    with lock:
                        state.tokens[token] = True
                    telemetry.record("credential_issued", risk="benign")
                    _reply(self, 201, {"issued": True})
                    return
                if self.path == "/revoke" and token:
                    with lock:
                        state.tokens[token] = False
                    telemetry.record("credential_revoked", risk="attack")
                    _reply(self, 200, {"revoked": True})
                    return
                self.send_error(404)

            log_message = _quiet

        return Handler

    def _resource_handler(self) -> type[BaseHTTPRequestHandler]:
        state, lock, telemetry, sink = self.state, self._lock, self.telemetry, self.sink
        lateral_access = self.configuration["lateral_access"]

        class Handler(BaseHTTPRequestHandler):
            def _authorized(self) -> bool:
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ")
                with lock:
                    return bool(token and state.tokens.get(token))

            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/protected":
                    self.send_error(404)
                    return
                if not self._authorized():
                    telemetry.record("authenticated_access_rejected", risk="attack")
                    _reply(self, 401, {"authenticated": False})
                    return
                telemetry.record("authenticated_access", risk="benign")
                _reply(self, 200, {"authenticated": True})

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/lateral":
                    self.send_error(404)
                    return
                if not self._authorized():
                    _reply(self, 401, {"allowed": False})
                    return
                if lateral_access != "allow":
                    telemetry.record("lateral_movement_blocked", risk="attack")
                    _reply(self, 403, {"allowed": False})
                    return
                with urllib.request.urlopen(f"{sink.url}/target", timeout=3) as response:  # noqa: S310
                    reached = response.status == 200
                telemetry.record("lateral_movement", risk="attack")
                _reply(self, 200, {"allowed": reached})

            log_message = _quiet

        return Handler

    def _hunt_handler(self) -> type[BaseHTTPRequestHandler]:
        state, lock, telemetry, identity = self.state, self._lock, self.telemetry, self.identity

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != "/hunt":
                    self.send_error(404)
                    return
                value = urllib.parse.parse_qs(parsed.query).get("value", [""])[0]
                with lock:
                    hit = value in state.iocs
                telemetry.record("ioc_hunt", risk="attack" if hit else "benign", hit=hit)
                _reply(self, 200, {"hit": hit})

            def do_POST(self) -> None:  # noqa: N802
                data = _json_body(self)
                if self.path == "/ioc":
                    value = str(data.get("value", ""))
                    with lock:
                        state.iocs.append(value)
                    telemetry.record("ioc_ingested", risk="attack")
                    _reply(self, 201, {"ingested": True})
                    return
                if self.path == "/contain":
                    token = str(data.get("token", ""))
                    _request_json(f"{identity.url}/revoke", method="POST", payload={"token": token})
                    with lock:
                        state.contained.append(token)
                    telemetry.record("containment_applied", risk="attack")
                    _reply(self, 200, {"contained": True})
                    return
                self.send_error(404)

            log_message = _quiet

        return Handler

    def __enter__(self) -> _Graph:
        for service in self.services:
            service.start()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.state.restore(self.baseline)
        self.final_reset_verified = self.state.snapshot() == self.baseline.snapshot()
        for service in reversed(self.services):
            service.stop()


def _request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - local fixture URLs only
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")


def _execute_detection_rules(
    events: list[dict[str, Any]],
) -> tuple[dict[str, int], tuple[dict[str, Any], ...]]:
    counts: Counter[str] = Counter()
    alerts: list[dict[str, Any]] = []
    rule_by_event = {
        "lateral_movement": "lateral-movement",
        "lateral_movement_blocked": "lateral-movement-blocked",
        "credential_revoked": "credential-revocation",
        "authenticated_access_rejected": "post-revocation-auth-failure",
        "ioc_hunt": "ioc-hunt-hit",
        "containment_applied": "ioc-containment",
    }
    for event in events:
        counts[f"class:{event.get('risk', 'unknown')}"] += 1
        if rule := rule_by_event.get(str(event.get("event"))):
            if event.get("event") != "ioc_hunt" or event.get("hit") is True:
                counts[f"rule:{rule}"] += 1
                alerts.append(
                    {
                        "alert": True,
                        "correlation_id": event["correlation_id"],
                        "timestamp": event["timestamp"],
                        "rule_id": rule,
                        "event": event["event"],
                    }
                )
    return dict(sorted(counts.items())), tuple(alerts)


def verify_fixture_manifest(directory: Path = FIXTURE_DIRECTORY) -> str:
    """Verify all fixture checksums and return the manifest digest."""

    manifest_path = directory / "manifest.json"
    raw = bounded_read(manifest_path, 1024 * 1024)
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "cops.service-laboratory-fixtures/v1":
        raise ValueError("unsupported laboratory fixture manifest")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not 1 <= len(fixtures) <= 64:
        raise ValueError("laboratory fixture manifest has an invalid file count")
    expected = {"vulnerable.json", "corrected.json", "entra-grants.jsonl", "entra-signins.jsonl", "kubernetes-audit.jsonl", "sysmon-normalized.jsonl"}
    observed_paths: set[str] = set()
    total = 0
    for item in fixtures:
        if not isinstance(item, dict):
            raise ValueError("invalid laboratory fixture entry")
        name, digest = item.get("path"), item.get("sha256")
        if not isinstance(name, str) or name not in expected or name in observed_paths:
            raise ValueError("invalid or duplicate laboratory fixture path")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid laboratory fixture checksum")
        observed_paths.add(name)
        content = bounded_read(directory / name, 1024 * 1024)
        total += len(content)
        if total > 8 * 1024 * 1024:
            raise ValueError("laboratory fixtures exceed their total budget")
        observed = hashlib.sha256(content).hexdigest()
        if observed != item["sha256"]:
            raise ValueError(f"fixture checksum mismatch: {name}")
    if observed_paths != expected:
        raise ValueError("laboratory fixture manifest is incomplete")
    return hashlib.sha256(raw).hexdigest()


def probe_isolated_runtime() -> IsolationProbe:
    """Report local readiness without treating a CLI or loopback bind as isolation proof."""

    if os.environ.get("COPS_LABORATORY_CONTAINER_NONCE"):
        verified, evidence, blocker = inspect_acceptance_boundary()
        return IsolationProbe(verified, "docker-network-none", blocker, evidence)
    evidence = [f"platform={platform.system().lower()}", f"architecture={platform.machine().lower()}"]
    docker = shutil.which("docker")
    if docker:
        try:
            check = subprocess.run(
                [docker, "info", "--format", "{{.ServerVersion}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            check = None
        if check is None:
            evidence.append("docker_probe=failed")
        elif check.returncode == 0:
            evidence.append(f"docker_server={check.stdout.strip()}")
            return IsolationProbe(
                verified=False,
                mechanism="docker-daemon-available",
                blocker="run the inspected immutable-image acceptance launcher to verify the container boundary",
                evidence=tuple(evidence),
            )
        else:
            evidence.append("docker_daemon=unavailable")
    else:
        evidence.append("docker_cli=missing")
    if platform.system() == "Linux" and shutil.which("unshare"):
        evidence.append("linux_unshare_cli=available")
    return IsolationProbe(
        verified=False,
        mechanism="unavailable",
        blocker="no currently verified network namespace or container boundary is available",
        evidence=tuple(evidence),
    )


class ServiceLaboratory:
    """Runs deterministic playback and disposable process-level service acceptance."""

    def __init__(self, fixture_directory: Path | str = FIXTURE_DIRECTORY) -> None:
        self.fixture_directory = Path(fixture_directory)

    def run_offline_playback(self) -> ServiceLaboratoryReport:
        """Execute detection rules against bundled synthetic fixtures without network activity."""

        digest = verify_fixture_manifest(self.fixture_directory)
        events: list[dict[str, Any]] = []
        alerts: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        dangerous_clients: set[str] = set()
        for name in ("entra-grants.jsonl", "entra-signins.jsonl", "kubernetes-audit.jsonl", "sysmon-normalized.jsonl"):
            for line in (self.fixture_directory / name).read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                correlation_id = str(event.get("id") or event.get("auditID") or uuid.uuid4())
                event["correlation_id"] = correlation_id
                event["timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                events.append(event)
                counts[f"class:{event['risk']}"] += 1
                matched = False
                if name == "entra-grants.jsonl":
                    matched = (event.get("activity") == "consent_to_application"
                               and event.get("consent_type") == "AllPrincipals"
                               and event.get("permission") == "Mail.ReadWrite")
                    if matched and isinstance(event.get("client_id"), str):
                        dangerous_clients.add(event["client_id"])
                elif name == "entra-signins.jsonl":
                    matched = (event.get("activity") == "signin" and event.get("status") == "success"
                               and event.get("app_id") in dangerous_clients)
                elif name == "kubernetes-audit.jsonl":
                    matched = (event.get("stage") == "ResponseComplete" and event.get("verb") in {"get", "list"}
                               and event.get("objectRef", {}).get("resource") == "secrets"
                               and event.get("annotations", {}).get("authorization.k8s.io/decision") == "allow"
                               and event.get("user", {}).get("username", "").startswith("system:serviceaccount:"))
                elif name == "sysmon-normalized.jsonl":
                    matched = (event.get("event_id") == 3 and event.get("image", "").casefold().endswith("powershell.exe")
                               and bool(event.get("source_ip")) and bool(event.get("target_ip"))
                               and event.get("source_ip") != event.get("target_ip"))
                if matched:
                    rule_id = f"{name.removesuffix('.jsonl')}-attack"
                    counts[f"rule:{rule_id}"] += 1
                    alerts.append(
                        {
                            "alert": True,
                            "correlation_id": correlation_id,
                            "timestamp": event["timestamp"],
                            "rule_id": rule_id,
                        }
                    )
        return ServiceLaboratoryReport(
            run_id=str(uuid.uuid4()),
            path="offline-playback",
            service_activity={"fixtures_read": 4, "events_evaluated": len(events)},
            detection_counts=dict(sorted(counts.items())),
            tls=None,
            restoration={"success": True, "failure": True, "cancellation": True},
            isolation=IsolationProbe(
                verified=False,
                mechanism="offline-playback",
                blocker="offline playback performs no runtime isolation measurement",
                evidence=("network_activity=none",),
            ),
            fixture_manifest_digest=digest,
            telemetry_events=tuple(events),
            alert_events=tuple(alerts),
            limitations=(
                "The Sysmon fixture is normalized synthetic JSON, not EVTX.",
                "Authentic EVTX acquisition is unsupported until a harmless EVTX artifact is supplied.",
            ),
        )

    @staticmethod
    def _restoration_proof(graph: _Graph) -> dict[str, bool]:
        original = graph.state.snapshot()

        def exercise(error: BaseException | None) -> bool:
            baseline = graph.state.copy()
            try:
                graph.state.iocs.append("temporary-ioc")
                if error is not None:
                    raise error
            except (RuntimeError, KeyboardInterrupt):
                pass
            finally:
                graph.state.restore(baseline)
            return graph.state.snapshot() == original

        return {
            "success": exercise(None),
            "failure": exercise(RuntimeError("expected acceptance failure")),
            "cancellation": exercise(KeyboardInterrupt()),
        }

    def run_process_acceptance(
        self,
        profile: Literal["vulnerable", "corrected"],
        *,
        telemetry_directory: Path | str | None = None,
    ) -> ServiceLaboratoryReport:
        """Exercise actual local services; this does not claim network isolation."""

        if profile not in ("vulnerable", "corrected"):
            raise ValueError(f"unsupported service profile: {profile}")
        digest = verify_fixture_manifest(self.fixture_directory)
        configuration = json.loads((self.fixture_directory / f"{profile}.json").read_text(encoding="utf-8"))
        if configuration.get("schema_version") != "cops.service-laboratory-profile/v1":
            raise ValueError(f"unsupported service profile schema: {configuration.get('schema_version')}")
        if configuration.get("profile") != profile:
            raise ValueError(f"service profile mismatch: expected {profile}")
        run_id = str(uuid.uuid4())
        with contextlib.ExitStack() as stack:
            if telemetry_directory is None:
                temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix="cops-service-lab-"))
                directory = Path(temporary)
            else:
                directory = Path(telemetry_directory)
                directory.mkdir(parents=True, exist_ok=True)
            telemetry = _Telemetry(directory / "telemetry.jsonl", correlation_id=run_id)
            graph = stack.enter_context(_Graph(configuration, telemetry))
            token = uuid.uuid4().hex
            issue_status, _ = _request_json(
                f"{graph.identity.url}/issue", method="POST", payload={"token": token}
            )
            authenticated_status, _ = _request_json(f"{graph.resource.url}/protected", token=token)
            lateral_status, lateral = _request_json(f"{graph.resource.url}/lateral", method="POST", token=token)
            ioc = "203.0.113.77"
            ioc_status, _ = _request_json(f"{graph.hunt.url}/ioc", method="POST", payload={"value": ioc})
            hunt_status, hunt = _request_json(f"{graph.hunt.url}/hunt?value={urllib.parse.quote(ioc)}")
            contain_status, _ = _request_json(
                f"{graph.hunt.url}/contain", method="POST", payload={"token": token}
            )
            post_revoke_status, _ = _request_json(f"{graph.resource.url}/protected", token=token)
            restoration = self._restoration_proof(graph)
            tls_result: TLSAcceptanceResult = run_ephemeral_mtls_acceptance()
            api_result = run_api_acceptance(profile)
            jwt_result = run_jwt_acceptance()
            boundary_result = run_boundary_acceptance(profile)
            acquisition_result = run_acquisition_acceptance()
            graph_mutated_before_final_reset = graph.state.snapshot() != graph.baseline.snapshot()
            detection_counts, alert_events = _execute_detection_rules(telemetry.events)
        restoration["final_graph_reset"] = graph.final_reset_verified
        return ServiceLaboratoryReport(
            run_id=run_id,
            path="process-acceptance",
            service_activity={
                "profile": profile,
                "identity_issue_status": issue_status,
                "authenticated_status": authenticated_status,
                "lateral_status": lateral_status,
                "lateral_target_reached": bool(lateral.get("allowed")),
                "profile_configuration_verified": (
                    lateral_status == configuration["expected_lateral_status"]
                    and bool(lateral.get("allowed")) == (configuration["lateral_access"] == "allow")
                ),
                "ioc_ingest_status": ioc_status,
                "hunt_status": hunt_status,
                "hunt_hit": bool(hunt.get("hit")),
                "containment_status": contain_status,
                "post_revoke_authenticated_status": post_revoke_status,
                "actual_tcp_services": 4,
                "loopback_bind_verified": _loopback_bind_available(),
                "graph_was_dirty_before_final_reset": graph_mutated_before_final_reset,
                "api": api_result,
                "jwt": jwt_result,
                "boundaries": boundary_result,
                "acquisition": acquisition_result,
            },
            detection_counts=detection_counts,
            tls=tls_result.to_dict(),
            restoration=restoration,
            isolation=probe_isolated_runtime(),
            fixture_manifest_digest=digest,
            telemetry_events=tuple(telemetry.events),
            alert_events=alert_events,
            limitations=(
                "Loopback TCP activity proves service execution but does not prove network namespace isolation.",
                "Use LaboratoryHarness with a signed runtime observation before authorized active operations.",
            ),
        )


def _loopback_bind_available() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return candidate.getsockname()[0] == "127.0.0.1"
