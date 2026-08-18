"""Chaos tests: the sync engine under 429/500 storms, resets, truncation, and
pagination pathologies must end up with exactly the same rows as a clean run —
no loss, no duplicates. These asserts are the point of the whole transport split.
"""

import json
import random
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.connectors.base import StreamSpec, TransportBase, TransportResponse
from reachset.connectors.transports import ChaosProfile, ChaosTransport, PageSchema
from reachset.ingest.engine import PageResult, StreamSyncer
from reachset.ingest.ratelimit import BackoffPolicy, BucketRegistry
from reachset.models import DeadLetter, Event, Principal, SyncWatermark
from reachset.records import EventRecord, ExtractBatch, PrincipalRecord

pytestmark = pytest.mark.integration

# A five-page synthetic stream: principals plus their audit events, so both
# UPDATE-style and INSERT-only tables are exercised.
_PAGES: dict[str | None, dict[str, Any]] = {
    None: {
        "items": [
            {"id": "svc-1", "name": "loader", "event": "ev-001", "ts": "2026-07-01T00:00:00Z"},
            {"id": "svc-2", "name": "mailer", "event": "ev-002", "ts": "2026-07-01T01:00:00Z"},
        ],
        "next": "c2",
    },
    "c2": {
        "items": [
            {"id": "svc-3", "name": "reaper", "event": "ev-003", "ts": "2026-07-01T02:00:00Z"}
        ],
        "next": "c3",
    },
    "c3": {
        "items": [
            {"id": "svc-4", "name": "archiver", "event": "ev-004", "ts": "2026-07-01T03:00:00Z"},
            {"id": "svc-5", "name": "backfill", "event": "ev-005", "ts": "2026-07-01T04:00:00Z"},
        ],
        "next": "c4",
    },
    "c4": {"items": [], "next": "c5"},  # a legitimately empty page
    "c5": {
        "items": [
            {"id": "svc-6", "name": "janitor", "event": "ev-006", "ts": "2026-07-01T05:00:00Z"}
        ],
        "next": None,
    },
}

EXPECTED_PRINCIPALS = {"svc-1", "svc-2", "svc-3", "svc-4", "svc-5", "svc-6"}
EXPECTED_EVENTS = {"ev-001", "ev-002", "ev-003", "ev-004", "ev-005", "ev-006"}

SPEC = StreamSpec(name="things", method="GET", path="/things", cursor_param="cursor")
SCHEMA = PageSchema(items_path="items", cursor_path="next", cursor_param="cursor")


class _PagedStub(TransportBase):
    async def request(self, method, path, params=None, json_body=None):  # type: ignore[no-untyped-def]  # test stub
        cursor = (params or {}).get("cursor")
        return TransportResponse(status=200, body=json.dumps(_PAGES[cursor]).encode())


def _extract(payload: dict[str, Any]) -> PageResult:
    from datetime import datetime

    principals = [
        PrincipalRecord(external_id=item["id"], kind="service", display_name=item["name"])
        for item in payload["items"]
    ]
    events = [
        EventRecord(
            raw_ref=item["event"],
            action="thing.seen",
            ts=datetime.fromisoformat(item["ts"].replace("Z", "+00:00")),
            provenance="audit_log",
            actor_external_id=item["id"],
        )
        for item in payload["items"]
    ]
    return PageResult(
        batch=ExtractBatch(principals=principals, events=events),
        next_cursor=payload.get("next"),
    )


class _InstantSleep:
    """Deterministic zero-cost sleeper that still records what it was asked."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _syncer(
    session_factory: async_sessionmaker[AsyncSession], transport: TransportBase
) -> tuple[StreamSyncer, _InstantSleep]:
    sleeper = _InstantSleep()
    return (
        StreamSyncer(
            session_factory=session_factory,
            transport=transport,
            limiter=BucketRegistry(10_000.0, 10_000.0, sleeper=sleeper),
            # 8 attempts: a 60%-fault storm can produce 5-in-a-row streaks, and
            # surviving the storm (not the dead-letter path) is what's under
            # test here. The dead-letter path has its own dedicated test below.
            backoff=BackoffPolicy(base_seconds=0.001, cap_seconds=0.01, max_attempts=8),
            sleeper=sleeper,
            rng=random.Random(0),
        ),
        sleeper,
    )


async def _rows(db: AsyncSession, tenant: str) -> tuple[set[str], set[str], int, int]:
    principals = (
        (await db.execute(select(Principal.external_id).where(Principal.tenant_id == tenant)))
        .scalars()
        .all()
    )
    events = (
        (await db.execute(select(Event.raw_ref).where(Event.tenant_id == tenant))).scalars().all()
    )
    return set(principals), set(events), len(principals), len(events)


async def test_clean_run_baseline(
    session_factory: async_sessionmaker[AsyncSession], db: AsyncSession, tenant: str
) -> None:
    syncer, _ = _syncer(session_factory, _PagedStub())
    outcome = await syncer.sync_stream(tenant, "chaosapp", SPEC, _extract)
    assert outcome.pages == 5
    assert not outcome.dead_lettered
    p_set, e_set, p_n, e_n = await _rows(db, tenant)
    assert p_set == EXPECTED_PRINCIPALS and p_n == 6
    assert e_set == EXPECTED_EVENTS and e_n == 6


@pytest.mark.parametrize("seed", [1, 7, 42, 1337])
async def test_429_500_storm_no_loss_no_duplicates(
    session_factory: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    tenant: str,
    seed: int,
) -> None:
    chaos = ChaosTransport(
        _PagedStub(),
        seed=seed,
        profile=ChaosProfile(
            http_429=0.25,
            http_500=0.15,
            http_503=0.10,
            conn_reset=0.10,
            truncate_body=0.10,
            retry_after_seconds=0.002,
            budget=30,
        ),
        page_schema=SCHEMA,
    )
    syncer, sleeper = _syncer(session_factory, chaos)
    outcome = await syncer.sync_stream(tenant, "chaosapp", SPEC, _extract)

    assert not outcome.dead_lettered, chaos.fault_log
    assert chaos.fault_log, "storm test must actually inject faults"
    p_set, e_set, p_n, e_n = await _rows(db, tenant)
    assert p_set == EXPECTED_PRINCIPALS and p_n == 6, chaos.fault_log
    assert e_set == EXPECTED_EVENTS and e_n == 6, chaos.fault_log
    if any(f == "http_429" for f in chaos.fault_log):
        assert sleeper.calls, "429s must have triggered backoff sleeps"


@pytest.mark.parametrize("seed", [3, 9, 11])
async def test_pagination_pathologies_no_loss_no_duplicates(
    session_factory: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    tenant: str,
    seed: int,
) -> None:
    chaos = ChaosTransport(
        _PagedStub(),
        seed=seed,
        profile=ChaosProfile(
            empty_page=0.2,
            repeat_cursor=0.2,
            out_of_order=0.2,
            skew_timestamps=0.2,
            budget=12,
        ),
        page_schema=SCHEMA,
    )
    syncer, _ = _syncer(session_factory, chaos)
    outcome = await syncer.sync_stream(tenant, "chaosapp", SPEC, _extract)

    assert not outcome.dead_lettered, chaos.fault_log
    assert chaos.fault_log
    p_set, _, p_n, _ = await _rows(db, tenant)
    assert p_set == EXPECTED_PRINCIPALS and p_n == 6, chaos.fault_log
    # Events: timestamp skew changes ts but raw_ref stays stable, so replays of
    # a skewed page cannot double-insert.
    _, e_set, _, e_n = await _rows(db, tenant)
    assert e_set == EXPECTED_EVENTS and e_n == 6, chaos.fault_log


async def test_unbroken_429_wall_dead_letters_without_advancing(
    session_factory: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    tenant: str,
) -> None:
    chaos = ChaosTransport(
        _PagedStub(),
        seed=0,
        profile=ChaosProfile(http_429=1.0, retry_after_seconds=0.001, budget=10_000),
        page_schema=SCHEMA,
    )
    syncer, _ = _syncer(session_factory, chaos)
    outcome = await syncer.sync_stream(tenant, "chaosapp", SPEC, _extract)

    assert outcome.dead_lettered
    assert outcome.pages == 0
    letter = (
        (await db.execute(select(DeadLetter).where(DeadLetter.tenant_id == tenant))).scalars().one()
    )
    assert letter.stream == "things"
    watermark = (
        (await db.execute(select(SyncWatermark).where(SyncWatermark.tenant_id == tenant)))
        .scalars()
        .one()
    )
    assert watermark.cursor is None  # never advanced past unfetched data
    assert watermark.consecutive_failures == 1
    p_set, e_set, _, _ = await _rows(db, tenant)
    assert p_set == set() and e_set == set()


async def test_resume_after_dead_letter_recovers_everything(
    session_factory: async_sessionmaker[AsyncSession],
    db: AsyncSession,
    tenant: str,
) -> None:
    """A run that dies mid-stream resumes from the watermark and ends complete."""

    class _DiesAtC3(TransportBase):
        async def request(self, method, path, params=None, json_body=None):  # type: ignore[no-untyped-def]  # test stub
            cursor = (params or {}).get("cursor")
            if cursor == "c3":
                from reachset.connectors.base import TransportHTTPError

                raise TransportHTTPError(503)
            return TransportResponse(status=200, body=json.dumps(_PAGES[cursor]).encode())

    syncer, _ = _syncer(session_factory, _DiesAtC3())
    outcome = await syncer.sync_stream(tenant, "chaosapp", SPEC, _extract)
    assert outcome.dead_lettered
    assert outcome.pages == 2  # pages 1 and 2 landed, watermark at c3

    watermark = (
        (await db.execute(select(SyncWatermark).where(SyncWatermark.tenant_id == tenant)))
        .scalars()
        .one()
    )
    assert watermark.cursor == "c3"

    healthy, _ = _syncer(session_factory, _PagedStub())
    outcome2 = await healthy.sync_stream(tenant, "chaosapp", SPEC, _extract)
    assert not outcome2.dead_lettered
    p_set, e_set, p_n, e_n = await _rows(db, tenant)
    assert p_set == EXPECTED_PRINCIPALS and p_n == 6
    assert e_set == EXPECTED_EVENTS and e_n == 6
