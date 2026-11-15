"""Gateway-local credential scope and provider transport boundary.

Install handlers only behind a dispatcher that verifies and consumes signed
grants. The emulator remains supported for explicitly supplied fake transports;
production transport registration requires a production dispatcher. No resolver,
provider transport, or credential is supplied by default.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .gateway_dispatch import (
    GatewayDispatchEndpoint,
    GatewayDispatchError,
    GatewayDispatchGrant,
    GatewayDispatchInvocation,
    GatewayDispatchResponse,
    GatewayProductionEndpoint,
    GatewayProductionInvocation,
)

SUPPORTED_GATEWAY_PROVIDERS = frozenset({"openai", "azure_openai", "bedrock", "vertex"})
LIVE_PROVIDER_TRANSPORT = MappingProxyType(
    {
        "openai": "openai",
        "azure": "azure_openai",
        "aws": "bedrock",
        "gcp": "vertex",
        "azure_openai": "azure_openai",
        "bedrock": "bedrock",
        "vertex": "vertex",
    }
)


@dataclass(frozen=True)
class GatewayCredentialBinding:
    """An opaque credential reference pinned to one configured endpoint scope."""

    endpoint: GatewayDispatchEndpoint
    credential_ref: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, GatewayDispatchEndpoint):
            raise GatewayDispatchError("gateway credential binding is invalid")
        if self.endpoint.provider not in LIVE_PROVIDER_TRANSPORT:
            raise GatewayDispatchError("gateway credential binding is invalid")
        if (
            not isinstance(self.credential_ref, str)
            or not self.credential_ref
            or len(self.credential_ref) > 256
            or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in self.credential_ref)
        ):
            raise GatewayDispatchError("gateway credential binding is invalid")


def _credential_value(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value)
    ):
        raise GatewayDispatchError("gateway credential is invalid")


@dataclass(frozen=True)
class OpenAIResponseCredential:
    api_key: str = field(repr=False)

    def __post_init__(self) -> None:
        _credential_value(self.api_key)


@dataclass(frozen=True)
class AzureOpenAIResponseCredential:
    api_key: str = field(repr=False)

    def __post_init__(self) -> None:
        _credential_value(self.api_key)


@dataclass(frozen=True)
class BedrockCredential:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _credential_value(self.access_key_id)
        _credential_value(self.secret_access_key)
        if self.session_token is not None:
            _credential_value(self.session_token)


@dataclass(frozen=True)
class VertexCredential:
    access_token: str = field(repr=False)

    def __post_init__(self) -> None:
        _credential_value(self.access_token)


GatewayCredential = OpenAIResponseCredential | AzureOpenAIResponseCredential | BedrockCredential | VertexCredential
ResolvedCredential = GatewayCredential | str | bytes
ProviderTransport = Callable[[GatewayDispatchEndpoint, bytes, ResolvedCredential], GatewayDispatchResponse]
CredentialResolver = Callable[[str], ResolvedCredential | None]


class GatewayScopedProviderHandler:
    """Resolve a gateway-owned credential only for an already verified scope.

    The caller must install this handler behind a verifying dispatcher. A
    transport is operator supplied and may use only the endpoint and credential
    passed here. Production TLS, provider IAM, and retention need separate
    operational verification.
    """

    def __init__(
        self,
        *,
        bindings: Mapping[str, GatewayCredentialBinding],
        credential_resolver: CredentialResolver,
        transports: Mapping[str, ProviderTransport],
    ) -> None:
        if not isinstance(bindings, Mapping) or not bindings or not callable(credential_resolver):
            raise GatewayDispatchError("gateway credential configuration is invalid")
        if not isinstance(transports, Mapping) or not transports:
            raise GatewayDispatchError("gateway credential configuration is invalid")
        checked_bindings: dict[str, GatewayCredentialBinding] = {}
        for endpoint_id, binding in bindings.items():
            if not isinstance(binding, GatewayCredentialBinding) or endpoint_id != binding.endpoint.gateway_endpoint_id:
                raise GatewayDispatchError("gateway credential configuration is invalid")
            checked_bindings[endpoint_id] = binding
        checked_transports: dict[str, ProviderTransport] = {}
        for provider, transport in transports.items():
            if (
                provider not in SUPPORTED_GATEWAY_PROVIDERS
                or not callable(transport)
                or getattr(transport, "production_only", False)
            ):
                raise GatewayDispatchError("gateway credential configuration is invalid")
            checked_transports[provider] = transport
        self._bindings = MappingProxyType(checked_bindings)
        self._credential_resolver = credential_resolver
        self._transports = MappingProxyType(checked_transports)

    def __call__(self, invocation: GatewayDispatchInvocation) -> GatewayDispatchResponse:
        if not isinstance(invocation, GatewayDispatchInvocation) or isinstance(invocation, GatewayProductionInvocation):
            raise GatewayDispatchError("gateway credential scope unavailable")
        binding = self._bindings.get(invocation.gateway_endpoint_id)
        if (
            binding is None
            or binding.endpoint != invocation.endpoint
            or invocation.gateway_identity != binding.endpoint.gateway_identity
        ):
            raise GatewayDispatchError("gateway credential scope unavailable")
        transport = self._transports.get(LIVE_PROVIDER_TRANSPORT[binding.endpoint.provider])
        if transport is None:
            raise GatewayDispatchError("gateway provider transport unavailable")

        credential: ResolvedCredential | None = None
        resolution_failed = False
        try:
            credential = self._credential_resolver(binding.credential_ref)
        except Exception:
            resolution_failed = True
        if (
            resolution_failed
            or not isinstance(
                credential,
                (
                    str,
                    bytes,
                    OpenAIResponseCredential,
                    AzureOpenAIResponseCredential,
                    BedrockCredential,
                    VertexCredential,
                ),
            )
            or not credential
        ):
            raise GatewayDispatchError("gateway credential unavailable")

        response: GatewayDispatchResponse | None = None
        transport_failed = False
        try:
            response = transport(binding.endpoint, invocation.body, credential)
        except Exception:
            transport_failed = True
        if transport_failed or not isinstance(response, GatewayDispatchResponse):
            raise GatewayDispatchError("gateway provider transport failed")
        return response


class GatewayProductionProviderHandler:
    """Gateway-owned registry with typed credentials and immutable v3 bindings.

    Install only in GatewayProductionDispatcher. The dispatcher consumes the
    signed one-use grant before this handler may resolve its opaque reference.
    """

    production_only = True

    def __init__(
        self,
        *,
        bindings: Mapping[str, GatewayCredentialBinding],
        credential_resolver: CredentialResolver,
    ) -> None:
        if not isinstance(bindings, Mapping) or not bindings or not callable(credential_resolver):
            raise GatewayDispatchError("gateway credential configuration is invalid")
        checked = {}
        for endpoint_id, binding in bindings.items():
            if (
                not isinstance(binding, GatewayCredentialBinding)
                or not isinstance(binding.endpoint, GatewayProductionEndpoint)
                or endpoint_id != binding.endpoint.gateway_endpoint_id
                or binding.credential_ref != binding.endpoint.credential_reference_id
            ):
                raise GatewayDispatchError("gateway credential configuration is invalid")
            checked[endpoint_id] = binding
        self._bindings = MappingProxyType(checked)
        self._credential_resolver = credential_resolver

    def preflight(self, endpoint: GatewayProductionEndpoint, grant: GatewayDispatchGrant) -> None:
        binding = self._bindings.get(endpoint.gateway_endpoint_id)
        if binding is None or binding.endpoint != endpoint or binding.credential_ref != grant.credential_reference_id:
            raise GatewayDispatchError("gateway credential scope unavailable")
        self._transport(endpoint)

    @staticmethod
    def _transport(endpoint: GatewayProductionEndpoint) -> ProviderTransport:
        from .provider_transport import registered_provider_transports

        transport = registered_provider_transports(
            max_response_bytes=endpoint.max_response_bytes,
            max_elapsed_ms=endpoint.max_elapsed_ms,
        ).get(LIVE_PROVIDER_TRANSPORT[endpoint.provider])
        validate = getattr(transport, "validate_endpoint", None)
        if (
            not callable(transport)
            or getattr(transport, "production_only", False) is not True
            or getattr(transport, "transport_version", None) != endpoint.transport_version
            or not callable(validate)
        ):
            raise GatewayDispatchError("gateway provider transport unavailable")
        failed = False
        try:
            validate(endpoint)
        except Exception:
            failed = True
        if failed:
            raise GatewayDispatchError("gateway provider endpoint unavailable")
        return transport

    def __call__(self, invocation: GatewayDispatchInvocation) -> GatewayDispatchResponse:
        if not isinstance(invocation, GatewayProductionInvocation):
            raise GatewayDispatchError("gateway credential scope unavailable")
        binding = self._bindings.get(invocation.gateway_endpoint_id)
        if (
            binding is None
            or binding.endpoint != invocation.endpoint
            or invocation.gateway_identity != binding.endpoint.gateway_identity
        ):
            raise GatewayDispatchError("gateway credential scope unavailable")
        endpoint = binding.endpoint
        for name in (
            "auth_profile_id",
            "credential_reference_id",
            "transport_version",
            "endpoint_policy_digest",
            "worker_evidence_digest",
            "max_output_tokens",
            "max_response_bytes",
            "max_elapsed_ms",
        ):
            if getattr(invocation, name) != getattr(endpoint, name):
                raise GatewayDispatchError("gateway credential scope unavailable")
        transport = self._transport(endpoint)
        provider = LIVE_PROVIDER_TRANSPORT[endpoint.provider]
        credential = None
        failed = False
        try:
            credential = self._credential_resolver(binding.credential_ref)
        except Exception:
            failed = True
        expected = {
            "openai": OpenAIResponseCredential,
            "azure_openai": AzureOpenAIResponseCredential,
            "bedrock": BedrockCredential,
            "vertex": VertexCredential,
        }[provider]
        if failed or type(credential) is not expected:
            raise GatewayDispatchError("gateway credential unavailable")
        response = None
        failed = False
        try:
            response = transport(endpoint, invocation.body, credential)
        except Exception:
            failed = True
        if (
            failed
            or not isinstance(response, GatewayDispatchResponse)
            or len(response.body) > invocation.max_response_bytes
        ):
            raise GatewayDispatchError("gateway provider transport failed")
        return response
