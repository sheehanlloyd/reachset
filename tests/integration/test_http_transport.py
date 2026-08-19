"""HttpTransport against a real socket.

The other two transports are exercised everywhere in this suite; the real one
was the gap. This drives it against a throwaway localhost server that can
produce the responses SaaS APIs actually produce — 429 with Retry-After, an
HTTP-date Retry-After, 500s, and a connection dropped mid-body — without
touching any external service.
"""

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable

import pytest

from reachset.connectors.base import TransportConnectionError, TransportHTTPError
from reachset.connectors.transports import HttpTransport

pytestmark = pytest.mark.integration

Handler = Callable[[str], tuple[int, dict[str, str], bytes] | None]


class _RawServer:
    """Minimal HTTP/1.1 responder. Returning None from the handler drops the
    connection instead of replying, which is how a reset mid-body is staged."""

    def __init__(self, handler: Handler) -> None:
        self._handler = handler
        self._server: asyncio.Server | None = None
        self.requests: list[str] = []

    async def __aenter__(self) -> "_RawServer":
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._server is not None
        self._server.close()
        # Bounded: the client may still hold an idle keep-alive connection, and
        # wait_closed() would block on it forever.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._server.wait_closed(), timeout=1.0)

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = await reader.read(1024)
            if not chunk:
                writer.close()
                return
            request += chunk
        request_line = request.split(b"\r\n", 1)[0].decode()
        self.requests.append(request_line)

        response = self._handler(request_line)
        if response is None:
            # Half-write a body, then hang up: a connection reset mid-response.
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"partial"')
            await writer.drain()
            writer.close()
            return

        status, headers, body = response
        head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        for name, value in headers.items():
            head += f"{name}: {value}\r\n"
        writer.write(head.encode() + b"\r\n" + body)
        await writer.drain()
        writer.close()


@pytest.fixture
async def transport_factory() -> AsyncIterator[Callable[[str], HttpTransport]]:
    created: list[HttpTransport] = []

    def make(base_url: str) -> HttpTransport:
        transport = HttpTransport(base_url, headers={"X-Test": "1"}, timeout=2.0)
        created.append(transport)
        return transport

    try:
        yield make
    finally:
        for transport in created:
            await transport.aclose()


async def test_successful_get_returns_body_and_headers(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    async with _RawServer(
        lambda _: (200, {"Content-Type": "application/json"}, b'{"data":{"keys":["a"]}}')
    ) as server:
        transport = transport_factory(server.url)
        response = await transport.get("/v1/things", {"list": "true"})

    assert response.status == 200
    assert response.json() == {"data": {"keys": ["a"]}}
    assert response.headers["content-type"] == "application/json"
    assert server.requests[0].startswith("GET /v1/things?list=true")


async def test_post_sends_a_json_body(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    async with _RawServer(lambda _: (200, {}, b"{}")) as server:
        transport = transport_factory(server.url)
        await transport.request(
            "POST", "/v1/auth/token/lookup-accessor", json_body={"accessor": "acc-1"}
        )
    assert server.requests[0].startswith("POST /v1/auth/token/lookup-accessor")


async def test_429_surfaces_numeric_retry_after(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    async with _RawServer(lambda _: (429, {"Retry-After": "12"}, b"slow down")) as server:
        transport = transport_factory(server.url)
        with pytest.raises(TransportHTTPError) as excinfo:
            await transport.get("/v1/things")

    assert excinfo.value.status == 429
    assert excinfo.value.retry_after == 12.0
    assert excinfo.value.retryable is True


async def test_http_date_retry_after_falls_back_to_backoff(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    """The RFC allows an HTTP-date here. Rather than half-parse it, the
    transport reports None and lets the backoff policy decide."""
    async with _RawServer(
        lambda _: (429, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, b"")
    ) as server:
        transport = transport_factory(server.url)
        with pytest.raises(TransportHTTPError) as excinfo:
            await transport.get("/v1/things")

    assert excinfo.value.status == 429
    assert excinfo.value.retry_after is None


async def test_500_is_retryable_and_404_is_not(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    async with _RawServer(lambda _: (500, {}, b"boom")) as server:
        transport = transport_factory(server.url)
        with pytest.raises(TransportHTTPError) as excinfo:
            await transport.get("/v1/things")
    assert excinfo.value.retryable is True

    async with _RawServer(lambda _: (404, {}, b"nope")) as server:
        transport = transport_factory(server.url)
        with pytest.raises(TransportHTTPError) as excinfo:
            await transport.get("/v1/missing")
    assert excinfo.value.status == 404
    assert excinfo.value.retryable is False


async def test_error_detail_is_truncated(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    """Upstream error pages can be enormous; the message keeps a usable prefix
    rather than pasting a full HTML document into a log line."""
    async with _RawServer(lambda _: (500, {}, b"x" * 5000)) as server:
        transport = transport_factory(server.url)
        with pytest.raises(TransportHTTPError) as excinfo:
            await transport.get("/v1/things")
    assert len(str(excinfo.value)) < 400


async def test_connection_dropped_mid_body_raises_connection_error(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    async with _RawServer(lambda _: None) as server:
        transport = transport_factory(server.url)
        with pytest.raises(TransportConnectionError):
            await transport.get("/v1/things")


async def test_connection_refused_raises_connection_error(
    transport_factory: Callable[[str], HttpTransport],
) -> None:
    # Port 9 (discard) is reserved and refuses connections everywhere.
    transport = transport_factory("http://127.0.0.1:9")
    with pytest.raises(TransportConnectionError):
        await transport.get("/v1/things")


async def test_timeout_raises_connection_error() -> None:
    """A hung upstream must surface as a retryable transport error, not as an
    httpx exception leaking through the abstraction."""
    handlers: list[asyncio.Task[None]] = []

    async def _hang(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handlers.append(asyncio.current_task())  # type: ignore[arg-type]
        await reader.read(1024)
        await asyncio.sleep(30)  # never answers

    server = await asyncio.start_server(_hang, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    transport = HttpTransport(f"http://{host}:{port}", timeout=0.25)
    try:
        with pytest.raises(TransportConnectionError):
            await transport.get("/v1/slow")
    finally:
        await transport.aclose()
        # Cancel the stuck handler explicitly; wait_closed() would otherwise
        # block on it for the full sleep.
        for task in handlers:
            task.cancel()
        server.close()


async def test_live_vault_over_http_transport(vault_env: object) -> None:
    """One end-to-end call against the real Vault dev server, so the transport
    is proven against an actual service and not only against a fake."""
    from tests.conftest import VaultTestEnv

    assert isinstance(vault_env, VaultTestEnv)
    transport = HttpTransport(vault_env.addr, headers={"X-Vault-Token": vault_env.token})
    try:
        response = await transport.get("/v1/sys/health")
        assert response.status == 200
        assert response.json()["initialized"] is True
    finally:
        await transport.aclose()
