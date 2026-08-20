"""Owns the connector contract: the Transport protocol, response/error types, and
the stream descriptor connectors use to describe what they sync.

Transports do I/O and nothing else. Extractors are pure functions over the JSON a
transport returned. The ingest pipeline is the only place the two meet.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class TransportError(Exception):
    """Base for anything a transport can raise."""


class TransportHTTPError(TransportError):
    def __init__(self, status: int, *, retry_after: float | None = None, detail: str = "") -> None:
        super().__init__(f"HTTP {status}{f': {detail}' if detail else ''}")
        self.status = status
        self.retry_after = retry_after

    @property
    def retryable(self) -> bool:
        return self.status in (429, 500, 502, 503, 504)


class TransportConnectionError(TransportError):
    """Connection reset / refused / dropped mid-body."""


@dataclass(frozen=True)
class TransportResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        """Parse the body. Truncated or garbage bodies raise ValueError, which the
        sync engine treats as a retryable page failure."""
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"undecodable response body: {exc}") from exc


class Transport(Protocol):  # pragma: no cover - structural declaration, never executed
    async def request(
        self,
        method: str,
        path: str,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> TransportResponse: ...

    async def get(
        self, path: str, params: Mapping[str, str] | None = None
    ) -> TransportResponse: ...


class TransportBase:
    """Shared convenience methods; concrete transports implement request()."""

    async def request(
        self,
        method: str,
        path: str,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> TransportResponse:
        raise NotImplementedError

    async def get(self, path: str, params: Mapping[str, str] | None = None) -> TransportResponse:
        return await self.request("GET", path, params)


@dataclass(frozen=True)
class StreamPage:
    """One extracted page plus the cursor that should be persisted after it."""

    payload: dict[str, Any]
    next_cursor: str | None


@dataclass(frozen=True)
class StreamSpec:
    """How to walk one paginated endpoint of an app.

    `cursor_param` is the query parameter carrying the cursor; `start_cursor` is
    what to send on a fresh sync (None means omit the parameter).
    """

    name: str
    method: str
    path: str
    cursor_param: str = "cursor"
    static_params: Mapping[str, str] = field(default_factory=dict)

    def params_for(self, cursor: str | None) -> dict[str, str]:
        params = dict(self.static_params)
        if cursor:
            params[self.cursor_param] = cursor
        return params
