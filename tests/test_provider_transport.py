"""Offline boundary tests: no real provider sockets or credentials."""

import hashlib
import hmac
import io
import json
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from cops.execution import provider_transport as transport
from cops.execution.gateway_credentials import (
    AzureOpenAIResponseCredential,
    BedrockCredential,
    OpenAIResponseCredential,
    VertexCredential,
)
from cops.execution.gateway_dispatch import GatewayDispatchEndpoint, GatewayDispatchError

SECRET = "synthetic-private-canary"
CREDENTIALS = {
    "openai": OpenAIResponseCredential(SECRET),
    "azure_openai": AzureOpenAIResponseCredential(SECRET),
    "bedrock": BedrockCredential("fixture-access-key", SECRET, "fixture-session-token"),
    "vertex": VertexCredential(SECRET),
}
HOSTS = {
    "openai": "api.openai.com",
    "azure_openai": "fixture-resource.openai.azure.com",
    "bedrock": "bedrock-runtime.us-east-1.amazonaws.com",
    "vertex": "us-east1-aiplatform.googleapis.com",
}


def endpoint(provider):
    region = "us-east-1" if provider == "bedrock" else "us-east1"
    paths = {
        "openai": "/v1/responses",
        "azure_openai": "/openai/v1/responses",
        "bedrock": "/model/test-model/converse",
        "vertex": "/v1/projects/test-project/locations/us-east1/publishers/google/models/test-model:generateContent",
    }
    return GatewayDispatchEndpoint(
        gateway_endpoint_id="fixture-endpoint",
        gateway_identity="spiffe://gateway.test/runtime",
        endpoint_origin="https://gateway.test",
        gateway_path="/dispatch",
        provider=provider,
        account_or_project_kind="project",
        account_or_project="test-project",
        region=region,
        model="test-model",
        request_target="https://" + HOSTS[provider] + paths[provider],
    )


def raw_response(provider):
    if provider in {"openai", "azure_openai"}:
        return {
            "id": SECRET,
            "status": "completed",
            "output": [{"type": "message", "id": SECRET, "content": [{"type": "output_text", "text": SECRET}]}],
            "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3, "extra": SECRET},
        }
    if provider == "bedrock":
        return {
            "stopReason": "end_turn",
            "output": {"message": {"content": [{"text": SECRET}]}},
            "usage": {"inputTokens": 1, "outputTokens": 2, "totalTokens": 3},
            "trace": SECRET,
        }
    return {
        "candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": SECRET}]}}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 2, "totalTokenCount": 3},
        "responseId": SECRET,
    }


class FakeSocket:
    def settimeout(self, value):
        self.timeout = value

    def shutdown(self, how):
        self.shutdown_called = True


class FakeResponse:
    status = 200

    def __init__(self, body, headers=None):
        self.stream = io.BytesIO(body)
        self.headers = headers if headers is not None else [("Content-Type", "application/json")]

    def getheaders(self):
        return self.headers

    def read(self, size):
        return self.stream.read(size)


class FakeConnection:
    instances = []
    response = None
    failure = None

    def __init__(self, host, **kwargs):
        self.host, self.options = host, kwargs
        self.sock = FakeSocket()
        self.closed = False
        self.requests = []
        self.instances.append(self)

    def connect(self):
        if self.failure == "connect":
            raise OSError(SECRET)

    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))
        if self.failure == "send":
            raise OSError(SECRET)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


@pytest.fixture
def network(monkeypatch):
    FakeConnection.instances = []
    FakeConnection.failure = None
    monkeypatch.setattr(transport, "_DirectHTTPSConnection", FakeConnection)
    return FakeConnection


@pytest.mark.parametrize("provider", CREDENTIALS)
def test_registered_adapter_authenticates_once_and_redacts(provider, network, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-must-not-be-used")
    network.response = FakeResponse(json.dumps(raw_response(provider)).encode())
    adapters = transport.registered_provider_transports()
    with pytest.raises(TypeError):
        adapters[provider] = None
    response = adapters[provider](endpoint(provider), b'{"fixture":true}', CREDENTIALS[provider])
    assert response.status_code == 200
    assert SECRET.encode() not in response.body
    assert b"fixture-session-token" not in response.body
    connection = network.instances[0]
    assert connection.host == HOSTS[provider]
    assert connection.closed and len(connection.requests) == 1
    args, kwargs = connection.requests[0]
    assert args == ("POST", endpoint(provider).request_target.removeprefix("https://" + HOSTS[provider]))
    assert kwargs["body"] == b'{"fixture":true}'
    headers = kwargs["headers"]
    if provider in {"openai", "vertex"}:
        assert headers["Authorization"] == f"Bearer {SECRET}"
    elif provider == "azure_openai":
        assert headers["api-key"] == SECRET and "Authorization" not in headers
    else:
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=fixture-access-key/")
        assert headers["x-amz-security-token"] == "fixture-session-token"
    assert connection.options["context"].check_hostname
    assert connection.options["context"].verify_mode == transport.ssl.CERT_REQUIRED


@pytest.mark.parametrize("provider", CREDENTIALS)
def test_wrong_or_ambient_credential_never_opens_connection(provider, network):
    for credential in (SECRET, SECRET.encode(), CREDENTIALS["vertex" if provider != "vertex" else "openai"]):
        with pytest.raises(transport.ProviderTransportError) as error:
            transport.GatewayProviderTransport(provider)(endpoint(provider), b"{}", credential)
        assert error.value.send_state == "not_sent"
    assert not network.instances


@pytest.mark.parametrize("path", ["/v1/other", "/v1/responses/extra", "/v1/%72esponses", "/v1/../responses"])
def test_exact_path_is_required_before_network(path, network):
    target = replace(endpoint("openai"), request_target="https://api.openai.com" + path)
    with pytest.raises(transport.ProviderTransportError):
        transport.GatewayProviderTransport("openai")(target, b"{}", CREDENTIALS["openai"])
    assert not network.instances


@pytest.mark.parametrize(
    ("provider", "host"),
    [
        ("openai", "api.openai.com.evil.test"),
        ("azure_openai", "openai.azure.com"),
        ("azure_openai", "fixture-resource.openai.azure.com.evil.test"),
        ("azure_openai", "fixture-resource.other.azure.com"),
        ("bedrock", "bedrock-runtime.us-west-2.amazonaws.com"),
        ("bedrock", "bedrock-runtime.us-east-1.amazonaws.com.evil.test"),
        ("vertex", "europe-west1-aiplatform.googleapis.com"),
        ("vertex", "us-east1-aiplatform.googleapis.com.evil.test"),
    ],
)
def test_exact_provider_host_is_required_before_network(provider, host, network):
    target = endpoint(provider)
    scoped = replace(target, request_target=target.request_target.replace(HOSTS[provider], host, 1))
    with pytest.raises(transport.ProviderTransportError) as error:
        transport.GatewayProviderTransport(provider)(scoped, b"{}", CREDENTIALS[provider])
    assert error.value.send_state == "not_sent"
    assert not network.instances


@pytest.mark.parametrize("failure,state,attempts", [("connect", "not_sent", 0), ("send", "uncertain", 1)])
def test_failure_is_sanitized_and_never_retried(failure, state, attempts, network):
    network.failure = failure
    with pytest.raises(transport.ProviderTransportError) as error:
        transport.GatewayProviderTransport("openai")(endpoint("openai"), b"{}", CREDENTIALS["openai"])
    assert error.value.send_state == state and SECRET not in str(error.value)
    assert error.value.__context__ is None
    assert len(network.instances) == 1 and len(network.instances[0].requests) == attempts
    assert network.instances[0].closed


@pytest.mark.parametrize(
    "body,headers,status",
    [
        (b"{}", [("Content-Type", "text/html")], 200),
        (b"{}", [("Content-Type", "application/json"), ("Content-Type", "application/json")], 200),
        (b"{}", [("Content-Type", "application/json"), ("Content-Encoding", "gzip")], 200),
        (b"{}", [("Content-Type", "application/json"), ("Content-Length", "2"), ("Transfer-Encoding", "chunked")], 200),
        (b"{}", [("Content-Type", "application/json"), ("Content-Length", "100")], 200),
        (b'{"status":"completed","status":"incomplete"}', None, 200),
        (b'{"status":NaN}', None, 200),
        (b"\xff", None, 200),
        (b"{}", None, 302),
        (b"{}", None, 401),
        (b"x" * (transport.MAX_RESPONSE_BYTES + 1), None, 200),
    ],
)
def test_untrusted_response_fails_closed(body, headers, status, network):
    network.response = FakeResponse(body, headers)
    network.response.status = status
    with pytest.raises(transport.ProviderTransportError) as error:
        transport.GatewayProviderTransport("openai")(endpoint("openai"), b"{}", CREDENTIALS["openai"])
    assert error.value.send_state == "uncertain"
    assert len(network.instances[0].requests) == 1


@pytest.mark.parametrize("provider", CREDENTIALS)
def test_tool_calls_fail_closed(provider, network):
    body = raw_response(provider)
    if provider in {"openai", "azure_openai"}:
        body["output"] = [{"type": "function_call", "name": SECRET, "arguments": SECRET}]
    elif provider == "bedrock":
        body["stopReason"] = "tool_use"
        body["output"]["message"]["content"] = [{"toolUse": {"name": SECRET}}]
    else:
        body["candidates"][0]["content"]["parts"] = [{"functionCall": {"name": SECRET}}]
    network.response = FakeResponse(json.dumps(body).encode())
    with pytest.raises(transport.ProviderTransportError):
        transport.GatewayProviderTransport(provider)(endpoint(provider), b"{}", CREDENTIALS[provider])


def test_sigv4_signature_matches_independent_canonical_request(monkeypatch):
    class FixedClock:
        @staticmethod
        def now(zone):
            assert zone == UTC
            return datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

    monkeypatch.setattr(transport, "datetime", FixedClock)
    body = b'{"messages":[]}'
    credential = BedrockCredential("fixture-id", "fixture-secret")
    headers = transport._headers("bedrock", endpoint("bedrock"), body, credential)
    digest = hashlib.sha256(body).hexdigest()
    names = "content-type;host;x-amz-content-sha256;x-amz-date"
    request = (
        "POST\n/model/test-model/converse\n\ncontent-type:application/json\n"
        "host:bedrock-runtime.us-east-1.amazonaws.com\n"
        f"x-amz-content-sha256:{digest}\nx-amz-date:20260102T030405Z\n\n{names}\n{digest}"
    )
    scope = "20260102/us-east-1/bedrock/aws4_request"
    signing = f"AWS4-HMAC-SHA256\n20260102T030405Z\n{scope}\n{hashlib.sha256(request.encode()).hexdigest()}"
    key = b"AWS4fixture-secret"
    for value in ("20260102", "us-east-1", "bedrock", "aws4_request"):
        key = hmac.digest(key, value.encode(), "sha256")
    expected = hmac.digest(key, signing.encode(), "sha256").hex()
    assert headers["Authorization"] == (
        f"AWS4-HMAC-SHA256 Credential=fixture-id/{scope}, SignedHeaders={names}, Signature={expected}"
    )


@pytest.mark.parametrize(
    "constructor,args",
    [
        (OpenAIResponseCredential, ("bad\r\nheader",)),
        (AzureOpenAIResponseCredential, ("",)),
        (BedrockCredential, ("id", "secret", "bad token")),
        (VertexCredential, ("bad\nvalue",)),
    ],
)
def test_credential_validation_and_secret_repr(constructor, args):
    with pytest.raises(GatewayDispatchError):
        constructor(*args)
    assert all(SECRET not in repr(value) for value in CREDENTIALS.values())


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "224.0.0.1", "0.0.0.0", "::1"])
def test_direct_connection_rejects_nonpublic_dns_before_socket(address, monkeypatch):
    monkeypatch.setattr(
        transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(transport.socket.AF_INET, transport.socket.SOCK_STREAM, 6, "", (address, 443))],
    )
    opened = []
    monkeypatch.setattr(transport.socket, "socket", lambda *args: opened.append(args))
    connection = transport._DirectHTTPSConnection("provider.test")
    with pytest.raises(OSError):
        connection.connect()
    assert opened == []


def test_direct_connection_pins_peer_and_never_reconnects(monkeypatch):
    class Socket(FakeSocket):
        def connect(self, address):
            self.address = address

        def getpeername(self):
            return self.address

        def do_handshake(self):
            self.handshake = True

    selected = Socket()
    monkeypatch.setattr(
        transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (transport.socket.AF_INET, transport.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (transport.socket.AF_INET, transport.socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        ],
    )
    attempts = []

    def new_socket(*args):
        attempts.append(args)
        return selected

    monkeypatch.setattr(transport.socket, "socket", new_socket)
    connection = transport._DirectHTTPSConnection("provider.test")
    tls = []

    def wrap(sock, **kwargs):
        tls.append(kwargs)
        return sock

    connection._context = SimpleNamespace(wrap_socket=wrap)
    connection.connect()
    assert selected.address == ("8.8.8.8", 443) and selected.handshake
    assert tls == [{"server_hostname": "provider.test", "do_handshake_on_connect": False}]
    with pytest.raises(OSError):
        connection.connect()
    assert len(attempts) == 1


def test_direct_connection_rejects_peer_mismatch(monkeypatch):
    selected = SimpleNamespace(
        settimeout=lambda value: None, connect=lambda address: None, getpeername=lambda: ("1.1.1.1", 443)
    )
    monkeypatch.setattr(
        transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(transport.socket.AF_INET, transport.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    monkeypatch.setattr(transport.socket, "socket", lambda *args: selected)
    connection = transport._DirectHTTPSConnection("provider.test")
    with pytest.raises(OSError, match="peer unavailable"):
        connection.connect()


def test_total_deadline_closes_detached_response_socket(network, monkeypatch):
    callbacks = []

    class Timer:
        def __init__(self, seconds, callback):
            assert seconds == transport.TOTAL_TIMEOUT_SECONDS
            callbacks.append(callback)

        def start(self):
            pass

        def cancel(self):
            pass

    class SlowResponse(FakeResponse):
        def read(self, size):
            # HTTPConnection detaches its socket for Connection: close. The
            # watchdog must retain and close the socket underlying the body.
            network.instances[0].sock = None
            callbacks[0]()
            return super().read(size)

    monkeypatch.setattr(transport.threading, "Timer", Timer)
    network.response = SlowResponse(json.dumps(raw_response("openai")).encode())
    with pytest.raises(transport.ProviderTransportError) as error:
        transport.GatewayProviderTransport("openai")(endpoint("openai"), b"{}", CREDENTIALS["openai"])
    assert error.value.send_state == "uncertain"
    assert network.instances[0].closed


@pytest.mark.parametrize("provider", CREDENTIALS)
def test_usage_cannot_inject_fields_or_impossible_counts(provider):
    body = raw_response(provider)
    key = "usageMetadata" if provider == "vertex" else "usage"
    names = tuple(body[key])
    body[key][names[0]] = True
    with pytest.raises(ValueError):
        transport._project(provider, json.dumps(body).encode())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_response_bytes": 0},
        {"max_response_bytes": transport.MAX_RESPONSE_BYTES + 1},
        {"max_response_bytes": True},
        {"max_elapsed_ms": 0},
        {"max_elapsed_ms": 30001},
        {"max_elapsed_ms": True},
    ],
)
def test_constructor_limits_cannot_exceed_hard_caps(kwargs):
    with pytest.raises(GatewayDispatchError):
        transport.registered_provider_transports(**kwargs)


def test_grant_bound_response_limit_and_deadline_are_propagated(network, monkeypatch):
    times = []

    class Timer:
        def __init__(self, seconds, callback):
            times.append(seconds)

        def start(self):
            pass

        def cancel(self):
            pass

    monkeypatch.setattr(transport.threading, "Timer", Timer)
    network.response = FakeResponse(b"x" * 101)
    adapter = transport.registered_provider_transports(max_response_bytes=100, max_elapsed_ms=1234)["openai"]
    with pytest.raises(transport.ProviderTransportError):
        adapter(endpoint("openai"), b"{}", CREDENTIALS["openai"])
    assert times == [1.234]
    assert network.instances[0].deadline > 0
