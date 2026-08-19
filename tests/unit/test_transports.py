"""FixtureTransport routing and ChaosTransport determinism/faults."""

import json
from pathlib import Path

import pytest

from reachset.connectors.base import (
    TransportBase,
    TransportConnectionError,
    TransportHTTPError,
    TransportResponse,
)
from reachset.connectors.transports import (
    ChaosProfile,
    ChaosTransport,
    FaultSummary,
    FixtureRouteNotFound,
    FixtureTransport,
    PageSchema,
)

VAULT_FIXTURES = Path(__file__).parent.parent / "fixtures" / "vault"


async def test_fixture_transport_serves_committed_json() -> None:
    transport = FixtureTransport(VAULT_FIXTURES)
    resp = await transport.get("/v1/sys/auth")
    assert resp.status == 200
    assert "token/" in resp.json()["data"]


async def test_fixture_transport_matches_params_exactly() -> None:
    transport = FixtureTransport(VAULT_FIXTURES)
    listed = await transport.request("GET", "/v1/sys/policies/acl", {"list": "true"})
    assert "ci-deploy" in listed.json()["data"]["keys"]
    with pytest.raises(FixtureRouteNotFound):
        await transport.request("GET", "/v1/sys/policies/acl", {"list": "maybe"})


async def test_fixture_transport_matches_json_body() -> None:
    transport = FixtureTransport(VAULT_FIXTURES)
    resp = await transport.request(
        "POST", "/v1/auth/token/lookup-accessor", json_body={"accessor": "acc-ci-deploy-01"}
    )
    assert resp.json()["data"]["accessor"] == "acc-ci-deploy-01"
    with pytest.raises(FixtureRouteNotFound):
        await transport.request(
            "POST", "/v1/auth/token/lookup-accessor", json_body={"accessor": "acc-nope"}
        )


class _PagedStub(TransportBase):
    """Three-page in-memory endpoint for chaos tests."""

    def __init__(self) -> None:
        self.pages = {
            None: {"items": [{"id": "a"}, {"id": "b"}], "next": "c2"},
            "c2": {"items": [{"id": "c"}], "next": "c3"},
            "c3": {"items": [{"id": "d"}, {"id": "e"}], "next": None},
        }

    async def request(self, method, path, params=None, json_body=None):  # type: ignore[no-untyped-def]  # test stub
        cursor = (params or {}).get("cursor")
        return TransportResponse(status=200, body=json.dumps(self.pages[cursor]).encode())


SCHEMA = PageSchema(items_path="items", cursor_path="next", cursor_param="cursor")


async def _drain(transport: TransportBase) -> list[str]:
    """Walk pagination like the sync engine does; returns item ids in order."""
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(30):
        try:
            resp = await transport.request("GET", "/items", {"cursor": cursor} if cursor else {})
            body = resp.json()
        except (TransportHTTPError, TransportConnectionError, ValueError):
            continue  # retry same cursor
        seen.extend(item["id"] for item in body["items"])
        cursor = body.get("next")
        if cursor is None:
            break
    return seen


async def test_chaos_is_deterministic_per_seed() -> None:
    logs = []
    for _ in range(2):
        chaos = ChaosTransport(
            _PagedStub(),
            seed=1234,
            profile=ChaosProfile(http_429=0.3, conn_reset=0.2, truncate_body=0.2),
            page_schema=SCHEMA,
        )
        await _drain(chaos)
        logs.append(list(chaos.fault_log))
    assert logs[0] == logs[1]
    assert logs[0], "seed 1234 must actually inject faults for this test to mean anything"


async def test_chaos_429_carries_retry_after() -> None:
    chaos = ChaosTransport(
        _PagedStub(), seed=7, profile=ChaosProfile(http_429=1.0, retry_after_seconds=9.5)
    )
    with pytest.raises(TransportHTTPError) as excinfo:
        await chaos.request("GET", "/items", {})
    assert excinfo.value.status == 429
    assert excinfo.value.retry_after == 9.5


async def test_chaos_truncated_body_is_undecodable() -> None:
    chaos = ChaosTransport(_PagedStub(), seed=3, profile=ChaosProfile(truncate_body=1.0))
    resp = await chaos.request("GET", "/items", {})
    with pytest.raises(ValueError, match="undecodable"):
        resp.json()


async def test_chaos_empty_page_points_back_at_same_cursor() -> None:
    stub = _PagedStub()
    chaos = ChaosTransport(
        stub, seed=5, profile=ChaosProfile(empty_page=1.0, budget=1), page_schema=SCHEMA
    )
    first = (await chaos.request("GET", "/items", {})).json()
    assert first["items"] == []
    assert first["next"] == ""  # "retry page one"
    replay = (await chaos.request("GET", "/items", {})).json()
    assert [i["id"] for i in replay["items"]] == ["a", "b"]


async def test_chaos_out_of_order_still_delivers_everything() -> None:
    chaos = ChaosTransport(
        _PagedStub(), seed=11, profile=ChaosProfile(out_of_order=1.0, budget=1), page_schema=SCHEMA
    )
    seen = await _drain(chaos)
    assert "out_of_order" in chaos.fault_log
    assert set(seen) == {"a", "b", "c", "d", "e"}
    assert seen != ["a", "b", "c", "d", "e"]  # order actually got disturbed


async def test_chaos_repeat_cursor_loops_then_recovers() -> None:
    chaos = ChaosTransport(
        _PagedStub(),
        seed=2,
        profile=ChaosProfile(repeat_cursor=0.6, budget=2),
        page_schema=SCHEMA,
    )
    seen = await _drain(chaos)
    assert "repeat_cursor" in chaos.fault_log
    assert set(seen) == {"a", "b", "c", "d", "e"}  # dups possible, loss not


async def test_chaos_timestamp_skew_both_directions() -> None:
    class _TsStub(TransportBase):
        async def request(self, method, path, params=None, json_body=None):  # type: ignore[no-untyped-def]  # test stub
            return TransportResponse(
                status=200,
                body=json.dumps(
                    {
                        "items": [{"id": "x", "created_at": "2026-06-01T00:00:00+00:00"}],
                        "next": None,
                    }
                ).encode(),
            )

    directions = set()
    for seed in range(20):
        chaos = ChaosTransport(
            _TsStub(),
            seed=seed,
            profile=ChaosProfile(skew_timestamps=1.0, skew_seconds=3600, budget=1),
            page_schema=SCHEMA,
        )
        body = (await chaos.request("GET", "/items", {})).json()
        ts = body["items"][0]["created_at"]
        directions.add(ts)
    assert "2026-06-01T01:00:00+00:00" in directions
    assert "2026-05-31T23:00:00+00:00" in directions


def test_fault_summary_counts() -> None:
    summary = FaultSummary.from_log(["http_429", "http_429", "conn_reset"])
    assert summary.counts == {"http_429": 2, "conn_reset": 1}


async def test_fixture_error_routes_raise_rather_than_return(tmp_path: Path) -> None:
    """A fixture can stage an error response; it must surface as the same
    exception a real transport would raise."""
    (tmp_path / "routes.json").write_text(
        json.dumps([{"path": "/boom", "status": 503, "body": {}}])
    )
    transport = FixtureTransport(tmp_path)
    with pytest.raises(TransportHTTPError) as excinfo:
        await transport.get("/boom")
    assert excinfo.value.status == 503


def test_dotted_path_helpers() -> None:
    from reachset.connectors.transports import _get_path, _set_path

    body = {"a": {"b": [1, 2]}}
    assert _get_path(body, "a.b") == [1, 2]
    assert _get_path(body, "a.missing") is None
    assert _get_path(body, "a.b.c") is None  # traverses into a non-dict

    # _set_path builds intermediate objects rather than raising.
    target: dict[str, object] = {}
    _set_path(target, "x.y.z", 7)
    assert target == {"x": {"y": {"z": 7}}}
    # and replaces a non-dict standing where an object is needed
    clobber: dict[str, object] = {"x": "scalar"}
    _set_path(clobber, "x.y", 1)
    assert clobber == {"x": {"y": 1}}


async def test_timestamp_skew_leaves_unparseable_values_alone() -> None:
    """Skew must not corrupt a field that only looks like a timestamp."""

    class _JunkTsStub(TransportBase):
        async def request(self, method, path, params=None, json_body=None):  # type: ignore[no-untyped-def]  # test stub
            return TransportResponse(
                status=200,
                body=json.dumps({"items": [{"created_at": "not-a-date"}], "next": None}).encode(),
            )

    chaos = ChaosTransport(
        _JunkTsStub(),
        seed=1,
        profile=ChaosProfile(skew_timestamps=1.0, budget=1),
        page_schema=SCHEMA,
    )
    body = (await chaos.request("GET", "/items", {})).json()
    assert body["items"][0]["created_at"] == "not-a-date"


def test_set_path_walks_through_existing_objects() -> None:
    from reachset.connectors.transports import _set_path

    body: dict[str, object] = {"x": {"y": {"keep": 1}}}
    _set_path(body, "x.y.z", 2)
    assert body == {"x": {"y": {"keep": 1, "z": 2}}}


async def test_chaos_without_a_page_schema_only_injects_transport_faults() -> None:
    """Structural page faults need a schema; without one the wrapper still
    passes bodies through untouched."""
    chaos = ChaosTransport(_PagedStub(), seed=0, profile=ChaosProfile())
    body = (await chaos.request("GET", "/items", {})).json()
    assert [item["id"] for item in body["items"]] == ["a", "b"]
    assert chaos.fault_log == []


async def test_chaos_leaves_non_object_bodies_alone() -> None:
    """A list-shaped page has no cursor to mangle; it must pass through rather
    than crash the fault injector."""

    class _ArrayStub(TransportBase):
        async def request(self, method, path, params=None, json_body=None):  # type: ignore[no-untyped-def]  # test stub
            return TransportResponse(status=200, body=b"[1, 2, 3]")

    chaos = ChaosTransport(
        _ArrayStub(), seed=0, profile=ChaosProfile(empty_page=1.0), page_schema=SCHEMA
    )
    assert (await chaos.request("GET", "/items", {})).json() == [1, 2, 3]


async def test_out_of_order_needs_a_cursor_path_to_reorder_anything() -> None:
    """With no cursor in the schema there is no next page to fetch ahead, so
    the fault cannot fire and the page is served unchanged."""
    schema = PageSchema(items_path="items", cursor_path=None)
    chaos = ChaosTransport(
        _PagedStub(), seed=0, profile=ChaosProfile(out_of_order=1.0), page_schema=schema
    )
    await chaos.request("GET", "/items", {})
    body = (await chaos.request("GET", "/items", {"cursor": "c2"})).json()
    assert "out_of_order" not in chaos.fault_log
    assert [item["id"] for item in body["items"]] == ["c"]


async def test_out_of_order_declines_when_the_page_ahead_is_the_last_one() -> None:
    """Re-chaining requires a cursor to hang the deferred page on; the final
    page has none, so the fault backs off instead of losing it."""
    chaos = ChaosTransport(
        _PagedStub(),
        seed=0,
        profile=ChaosProfile(out_of_order=1.0, budget=50),
        page_schema=SCHEMA,
    )
    # From c2 the page ahead is c3, and c3 is the last page (next is None):
    # there is no cursor left to re-chain c2 onto, so the fault declines.
    body = (await chaos.request("GET", "/items", {"cursor": "c2"})).json()
    assert [item["id"] for item in body["items"]] == ["c"]
    assert "out_of_order" not in chaos.fault_log


async def test_empty_page_fault_without_a_cursor_path_just_empties_the_page() -> None:
    """Some endpoints are not cursor-paginated at all; the empty-page fault has
    no cursor to point back at, so it only blanks the items."""
    schema = PageSchema(items_path="items", cursor_path=None)
    chaos = ChaosTransport(
        _PagedStub(), seed=0, profile=ChaosProfile(empty_page=1.0, budget=1), page_schema=schema
    )
    body = (await chaos.request("GET", "/items", {})).json()
    assert body["items"] == []
    assert body["next"] == "c2"  # untouched, because the schema names no cursor
