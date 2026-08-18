"""Owns the three transport implementations.

- HttpTransport: real I/O over httpx. Only used in `live` mode; nothing in the
  test suite constructs one against a SaaS API.
- FixtureTransport: replays committed JSON from tests/fixtures/<app>/, driven by
  a routes.json manifest so fixtures look exactly like recorded HTTP responses.
- ChaosTransport: wraps another transport and injects failures deterministically
  from a seed: 429s with Retry-After, 5xx, connection resets, truncated JSON,
  empty pages, repeated cursors, out-of-order pages, and skewed timestamps.
"""

import json
import random
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from reachset.connectors.base import (
    TransportBase,
    TransportConnectionError,
    TransportHTTPError,
    TransportResponse,
)

# ------------------------------------------------------------------------------- http


class HttpTransport(TransportBase):
    """Real HTTP. Base URL + static headers; raises TransportHTTPError on >=400."""

    def __init__(
        self,
        base_url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url, headers=dict(headers or {}), timeout=timeout
        )

    async def request(
        self,
        method: str,
        path: str,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> TransportResponse:
        try:
            resp = await self._client.request(
                method, path, params=dict(params or {}), json=json_body
            )
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            raise TransportConnectionError(str(exc)) from exc
        if resp.status_code >= 400:
            retry_after: float | None = None
            raw = resp.headers.get("Retry-After")
            if raw is not None:
                try:
                    retry_after = float(raw)
                except ValueError:
                    retry_after = None  # HTTP-date form; let backoff decide
            raise TransportHTTPError(
                resp.status_code, retry_after=retry_after, detail=resp.text[:200]
            )
        return TransportResponse(
            status=resp.status_code, body=resp.content, headers=dict(resp.headers)
        )

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------- fixture


@dataclass(frozen=True)
class _Route:
    method: str
    path: str
    params: Mapping[str, str]
    json_body: Mapping[str, Any] | None
    status: int
    headers: Mapping[str, str]
    body: bytes


class FixtureRouteNotFound(TransportConnectionError):
    """A request no fixture covers: fail loudly, never fabricate a response."""


class FixtureTransport(TransportBase):
    """Replays a routes.json manifest.

    Manifest shape (one entry per request the connector is expected to make):
        [{"method": "GET", "path": "/v1/sys/auth", "params": {"cursor": "p2"},
          "status": 200, "body_file": "sys_auth.json"}, ...]
    Params match exactly (after dropping empty values) so a pagination bug in a
    connector shows up as FixtureRouteNotFound instead of silently looping.
    """

    def __init__(self, fixture_dir: Path) -> None:
        self._dir = fixture_dir
        manifest = json.loads((fixture_dir / "routes.json").read_text())
        self._routes: list[_Route] = []
        for entry in manifest:
            if "body_file" in entry:
                body = (fixture_dir / entry["body_file"]).read_bytes()
            else:
                body = json.dumps(entry.get("body", {})).encode()
            self._routes.append(
                _Route(
                    method=entry.get("method", "GET").upper(),
                    path=entry["path"],
                    params={k: str(v) for k, v in entry.get("params", {}).items()},
                    json_body=entry.get("json"),
                    status=int(entry.get("status", 200)),
                    headers=entry.get("headers", {}),
                    body=body,
                )
            )
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    async def request(
        self,
        method: str,
        path: str,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> TransportResponse:
        wanted = {k: v for k, v in dict(params or {}).items() if v != ""}
        self.calls.append((method.upper(), path, wanted))
        for route in self._routes:
            if (
                route.method == method.upper()
                and route.path == path
                and dict(route.params) == wanted
                and (route.json_body is None or route.json_body == json_body)
            ):
                if route.status >= 400:
                    raise TransportHTTPError(route.status, detail="fixture error route")
                return TransportResponse(
                    status=route.status, body=route.body, headers=route.headers
                )
        raise FixtureRouteNotFound(f"no fixture for {method} {path} params={wanted}")


# ------------------------------------------------------------------------------ chaos


@dataclass(frozen=True)
class PageSchema:
    """Where items and the next-page cursor live in a paginated response body.

    Key paths are dotted (e.g. "data.keys"). ChaosTransport needs this to mangle
    pages structurally instead of just byte-mangling them.
    """

    items_path: str
    cursor_path: str | None = None
    cursor_param: str = "cursor"
    timestamp_keys: frozenset[str] = frozenset(
        {"ts", "time", "creation_time", "last_used_at", "issued_at", "created_at", "updated_at"}
    )


@dataclass
class ChaosProfile:
    """Per-fault rates in [0, 1]. All faults are off by default; tests switch on
    exactly what they mean to test."""

    http_429: float = 0.0
    http_500: float = 0.0
    http_503: float = 0.0
    conn_reset: float = 0.0
    truncate_body: float = 0.0
    empty_page: float = 0.0
    repeat_cursor: float = 0.0
    out_of_order: float = 0.0
    skew_timestamps: float = 0.0
    retry_after_seconds: float = 0.05
    skew_seconds: int = 3600
    # Faults only fire on the first `budget` opportunities, so a storm always
    # ends and the sync can eventually finish.
    budget: int = 50


def _get_path(body: dict[str, Any], dotted: str) -> Any:
    node: Any = body
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _set_path(body: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node: Any = body
    for part in parts[:-1]:
        if not isinstance(node.get(part), dict):
            node[part] = {}
        node = node[part]
    node[parts[-1]] = value


class ChaosTransport(TransportBase):
    """Deterministic failure injection around any other transport.

    Reproducibility: same seed + same request sequence => same faults. The seed
    goes in the test, so a chaos failure is a plain red test you can rerun.
    """

    def __init__(
        self,
        wrapped: TransportBase,
        *,
        seed: int,
        profile: ChaosProfile,
        page_schema: PageSchema | None = None,
    ) -> None:
        self._wrapped = wrapped
        self._rng = random.Random(seed)
        self._profile = profile
        self._schema = page_schema
        self._faults_fired = 0
        self._last_page: dict[str, Any] | None = None
        # cursor value -> page body to serve when that cursor is requested,
        # used by the out-of-order fault to re-chain a deferred page.
        self._deferred: dict[str, dict[str, Any]] = {}
        self.fault_log: list[str] = []

    def _fire(self, rate: float) -> bool:
        if self._faults_fired >= self._profile.budget:
            return False
        # Draw unconditionally so the fault sequence is stable even when rates
        # change between runs of the same seed.
        draw = self._rng.random()
        if rate > 0.0 and draw < rate:
            self._faults_fired += 1
            return True
        return False

    async def request(
        self,
        method: str,
        path: str,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> TransportResponse:
        if self._fire(self._profile.http_429):
            self.fault_log.append("http_429")
            raise TransportHTTPError(429, retry_after=self._profile.retry_after_seconds)
        if self._fire(self._profile.http_500):
            self.fault_log.append("http_500")
            raise TransportHTTPError(500)
        if self._fire(self._profile.http_503):
            self.fault_log.append("http_503")
            raise TransportHTTPError(503)
        if self._fire(self._profile.conn_reset):
            self.fault_log.append("conn_reset")
            raise TransportConnectionError("connection reset by chaos")

        requested_cursor = dict(params or {}).get(
            self._schema.cursor_param if self._schema else "cursor"
        )
        if requested_cursor and requested_cursor in self._deferred:
            # An earlier out-of-order fault re-chained this page to be served now.
            body = self._deferred.pop(requested_cursor)
            return TransportResponse(status=200, body=json.dumps(body).encode(), headers={})

        resp = await self._wrapped.request(method, path, params, json_body)

        if self._fire(self._profile.truncate_body) and len(resp.body) > 2:
            self.fault_log.append("truncate_body")
            cut = self._rng.randint(1, len(resp.body) - 1)
            return TransportResponse(status=resp.status, body=resp.body[:cut], headers=resp.headers)

        if self._schema is not None:
            body = json.loads(resp.body)
            if isinstance(body, dict):
                mangled = await self._mangle_page(method, path, params, requested_cursor, body)
                if mangled is not None:
                    return TransportResponse(
                        status=resp.status, body=json.dumps(mangled).encode(), headers=resp.headers
                    )
                self._last_page = body
        return resp

    async def _mangle_page(
        self,
        method: str,
        path: str,
        params: Mapping[str, str] | None,
        requested_cursor: str | None,
        body: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Structural page faults. Every fault preserves eventual delivery of all
        real items — chaos may delay, repeat, or disorder data, never destroy it;
        losing data is the pipeline's failure mode to prevent, not the mock's."""
        assert self._schema is not None
        schema = self._schema
        if self._fire(self._profile.empty_page):
            # A transient empty page: no items, cursor pointing back at the same
            # request, so the next attempt sees the real page.
            self.fault_log.append("empty_page")
            mangled: dict[str, Any] = json.loads(json.dumps(body))
            items = _get_path(mangled, schema.items_path)
            _set_path(mangled, schema.items_path, [] if isinstance(items, list) else {})
            if schema.cursor_path is not None:
                _set_path(mangled, schema.cursor_path, requested_cursor or "")
            return mangled
        if self._last_page is not None and self._fire(self._profile.repeat_cursor):
            # Serve the previous page again, cursor and all: a pagination loop.
            self.fault_log.append("repeat_cursor")
            return self._last_page
        if (
            schema.cursor_path is not None
            and self._fire(self._profile.out_of_order)
            and isinstance(_get_path(body, schema.cursor_path), str)
        ):
            # Serve the *next* page now and re-chain this one after it, so pages
            # arrive out of order but all of them still arrive.
            next_cursor = _get_path(body, schema.cursor_path)
            next_params = dict(params or {})
            next_params[schema.cursor_param] = next_cursor
            ahead: dict[str, Any] = json.loads(
                (await self._wrapped.request(method, path, next_params)).body
            )
            ahead_next = _get_path(ahead, schema.cursor_path)
            if isinstance(ahead_next, str) and ahead_next and ahead_next not in self._deferred:
                self.fault_log.append("out_of_order")
                self._deferred[ahead_next] = body
                return ahead
        if self._fire(self._profile.skew_timestamps):
            self.fault_log.append("skew_timestamps")
            skewed: dict[str, Any] = json.loads(json.dumps(body))
            direction = self._rng.choice([-1, 1])
            self._skew(skewed, direction * self._profile.skew_seconds)
            return skewed
        return None

    def _skew(self, node: Any, delta_seconds: int) -> None:
        from datetime import datetime, timedelta

        assert self._schema is not None
        if isinstance(node, dict):
            for key, value in node.items():
                if key in self._schema.timestamp_keys and isinstance(value, str):
                    try:
                        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    node[key] = (ts + timedelta(seconds=delta_seconds)).isoformat()
                else:
                    self._skew(value, delta_seconds)
        elif isinstance(node, list):
            for item in node:
                self._skew(item, delta_seconds)


@dataclass(frozen=True)
class FaultSummary:
    """What a chaos run actually injected; tests assert on this so a run with
    zero faults can't silently pass as a chaos test."""

    counts: Mapping[str, int] = field(default_factory=dict)

    @staticmethod
    def from_log(log: list[str]) -> "FaultSummary":
        counts: dict[str, int] = {}
        for fault in log:
            counts[fault] = counts.get(fault, 0) + 1
        return FaultSummary(counts=counts)
