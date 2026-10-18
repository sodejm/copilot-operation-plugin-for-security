"""Gateway-local credential scope and provider transport boundary.

Only a handler installed behind GatewayDispatchEmulator may use this module.
The emulator verifies and consumes a signed grant before invoking the handler.
No resolver, provider transport, or credential is supplied by default.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .gateway_dispatch import (
    GatewayDispatchEndpoint,
    GatewayDispatchError,
    GatewayDispatchInvocation,
    GatewayDispatchResponse,
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


ProviderTransport = Callable[[GatewayDispatchEndpoint, bytes, str | bytes], GatewayDispatchResponse]
CredentialResolver = Callable[[str], str | bytes | None]


class GatewayScopedProviderHandler:
    """Resolve a gateway-owned credential only for an already verified scope.

    The caller must install this handler behind GatewayDispatchEmulator. A
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
            if provider not in SUPPORTED_GATEWAY_PROVIDERS or not callable(transport):
                raise GatewayDispatchError("gateway credential configuration is invalid")
            checked_transports[provider] = transport
        self._bindings = MappingProxyType(checked_bindings)
        self._credential_resolver = credential_resolver
        self._transports = MappingProxyType(checked_transports)

    def __call__(self, invocation: GatewayDispatchInvocation) -> GatewayDispatchResponse:
        if not isinstance(invocation, GatewayDispatchInvocation):
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

        credential: str | bytes | None = None
        resolution_failed = False
        try:
            credential = self._credential_resolver(binding.credential_ref)
        except Exception:
            resolution_failed = True
        if resolution_failed or not isinstance(credential, (str, bytes)) or not credential:
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
