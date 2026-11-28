"""Ephemeral transport values are deliberately excluded from representations."""
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Request:
    method: str
    url: str = field(repr=False)
    body: bytes | None = field(default=None, repr=False)
    headers: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = field(repr=False)
    retry_after: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Page:
    records: Iterable[dict] = field(repr=False)
    cursor: str | None = field(default=None, repr=False)
    reason: str | None = None


@dataclass(frozen=True)
class Result:
    records: list = field(repr=False)
    receipt: dict


class CredentialProvider(Protocol):
    def headers(self, *, refresh: bool = False) -> dict: ...


class Transport(Protocol):
    def send(self, request: Request, headers: dict, *, timeout: float, max_bytes: int) -> Response: ...


class Adapter(Protocol):
    name: str
    version: str
    product: str
    api: str
    tenant: str
    scope: list[str]
    origin: str
    path: str
    method: str

    def request(self, cursor: str | None = None) -> Request: ...
    def validate_request(self, request: Request) -> None: ...
    def parse(self, data: dict, *, retried: bool = False) -> Page: ...
