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
