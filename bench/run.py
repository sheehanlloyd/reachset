"""Benchmark harness: writes measured numbers to bench/results.json.

Every figure in the README's benchmark table comes from this file, run on the
machine named in the output. Scales are configurable; the JSON records the
scale that actually ran, so a small local run can never masquerade as a big one.

    make bench                       # default scale
    BENCH_SCALE=large make bench     # bigger synthetic tenants (see _SCALES)

The harness talks to REACHSET_DATABASE_URL. Tenants it creates are prefixed
`bench-` and dropped at the end.
"""

import asyncio
import json
import os
import platform
import resource
import statistics
import subprocess
import time
import tracemalloc
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from reachset.config import load_settings
from reachset.db import make_engine, make_session_factory
from reachset.ingest.pipeline import upsert_batch
from reachset.logging import configure_logging, get_logger
from reachset.reach.engine import compute_reach, materialize
from reachset.records import EventRecord, ExtractBatch
from reachset.synth.generator import SynthConfig, generate

log = get_logger(__name__)
RESULTS_PATH = Path(__file__).parent / "results.json"

# principals / grants / events per synthetic tenant, and reach-tenant sizes.
_SCALES: dict[str, dict[str, Any]] = {
    "small": {
        "ingest_events": 20_000,
        "reach_tenants": [
            {"principals": 500, "grants": 2_000},
            {"principals": 1_500, "grants": 6_000},
        ],
        "latency_queries": 200,
    },
    "medium": {
        "ingest_events": 50_000,
        "reach_tenants": [
            {"principals": 500, "grants": 2_000},
            {"principals": 1_500, "grants": 6_000},
            {"principals": 5_000, "grants": 20_000},
        ],
        "latency_queries": 300,
    },
    "large": {
        "ingest_events": 200_000,
        "reach_tenants": [
            {"principals": 5_000, "grants": 20_000},
            {"principals": 15_000, "grants": 60_000},
            {"principals": 50_000, "grants": 200_000},
        ],
        "latency_queries": 500,
    },
}


def _machine_spec() -> dict[str, Any]:
    spec: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    if platform.system() == "Darwin":
        try:
            spec["cpu"] = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            spec["memory_gb"] = round(
                int(
                    subprocess.run(
                        ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=True
                    ).stdout.strip()
                )
                / 2**30
            )
        except (subprocess.CalledProcessError, ValueError):
            pass
    return spec


def _percentiles(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def pct(p: float) -> float:
        index = min(len(ordered) - 1, round(p * (len(ordered) - 1)))
        return ordered[index]

    return {
        "p50_ms": round(pct(0.50) * 1000, 3),
        "p95_ms": round(pct(0.95) * 1000, 3),
        "p99_ms": round(pct(0.99) * 1000, 3),
        "mean_ms": round(statistics.mean(ordered) * 1000, 3),
    }


def _event_batches(total: int, batch_size: int = 500) -> list[ExtractBatch]:
    base = datetime(2026, 7, 1, tzinfo=UTC)
    batches = []
    for start in range(0, total, batch_size):
        events = [
            EventRecord(
                raw_ref=f"bench-{i:010d}",
                action="bench.read",
                ts=base,
                provenance="audit_log",
            )
            for i in range(start, min(start + batch_size, total))
        ]
        batches.append(ExtractBatch(events=events))
    return batches


async def bench_ingest(
    factory: async_sessionmaker[AsyncSession], total_events: int
) -> dict[str, Any]:
    """Events/second upserted at 1/2/4/8 concurrent workers.

    Workers are asyncio tasks sharing one process and one connection pool —
    the shape of the real worker deployment (one container per worker would
    add process isolation but the DB is the bottleneck either way)."""
    results = {}
    for workers in (1, 2, 4, 8):
        tenant = f"bench-ingest-{workers}-{uuid.uuid4().hex[:6]}"
        batches = _event_batches(total_events)
        queue: asyncio.Queue[ExtractBatch] = asyncio.Queue()
        for batch in batches:
            queue.put_nowait(batch)

        async def worker(queue: asyncio.Queue[ExtractBatch] = queue, tenant: str = tenant) -> None:
            while True:
                try:
                    batch = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                async with factory() as session:
                    await upsert_batch(session, tenant, "bench", batch)
                    await session.commit()

        tracemalloc.start()
        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(workers)))
        elapsed = time.perf_counter() - started
        _, mem_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        results[str(workers)] = {
            "events": total_events,
            "seconds": round(elapsed, 3),
            "events_per_sec": round(total_events / elapsed),
            "python_heap_peak_mb": round(mem_peak / 2**20, 1),
        }
        log.info("bench_ingest_done", workers=workers, **results[str(workers)])
    return results


async def bench_reach(
    factory: async_sessionmaker[AsyncSession],
    tenants: list[dict[str, int]],
    latency_queries: int,
) -> list[dict[str, Any]]:
    """Materialized edge counts, full vs incremental recompute, and single-origin
    query latency percentiles, per synthetic tenant size."""
    out = []
    for sizes in tenants:
        tenant = f"bench-reach-{uuid.uuid4().hex[:6]}"
        async with factory() as session:
            await generate(
                session,
                SynthConfig(
                    tenant_id=tenant,
                    principals=sizes["principals"],
                    grants=sizes["grants"],
                    events=0,
                ),
            )

        async with factory() as session:
            started = time.perf_counter()
            edge_count = await materialize(session, tenant)
            await session.commit()
            full_seconds = time.perf_counter() - started

            principal_ids = [
                row[0]
                for row in (
                    await session.execute(
                        text(
                            "SELECT id FROM principals WHERE tenant_id = :tenant "
                            "ORDER BY external_id LIMIT :n"
                        ),
                        {"tenant": tenant, "n": max(50, latency_queries // 4)},
                    )
                ).all()
            ]

            started = time.perf_counter()
            await materialize(session, tenant, origins=principal_ids[:50])
            await session.commit()
            incremental_seconds = time.perf_counter() - started

            samples = []
            for i in range(latency_queries):
                origin = principal_ids[i % len(principal_ids)]
                started = time.perf_counter()
                await compute_reach(session, tenant, origin=origin)
                samples.append(time.perf_counter() - started)

        out.append(
            {
                "tenant_scale": sizes,
                "materialized_edges": edge_count,
                "full_recompute_seconds": round(full_seconds, 3),
                "incremental_recompute_50_origins_seconds": round(incremental_seconds, 3),
                "single_origin_query": _percentiles(samples),
                "latency_queries": latency_queries,
            }
        )
        log.info("bench_reach_done", tenant=tenant, edges=edge_count)
    return out


async def _cleanup(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for table in (
            "reach_edges",
            "identity_links",
            "events",
            "grants",
            "credentials",
            "resources",
            "principals",
            "sync_watermarks",
            "dead_letters",
        ):
            await conn.execute(text(f"DELETE FROM {table} WHERE tenant_id LIKE 'bench-%'"))


async def main() -> None:
    settings = load_settings()
    configure_logging(settings.log_level)
    scale_name = os.environ.get("BENCH_SCALE", "small")
    scale = _SCALES[scale_name]

    engine = make_engine(settings.database_url, pool_size=10)
    factory = make_session_factory(engine)
    try:
        started_at = datetime.now(UTC)
        ingest = await bench_ingest(factory, scale["ingest_events"])
        reach = await bench_reach(factory, scale["reach_tenants"], scale["latency_queries"])
        results = {
            "generated_at": started_at.isoformat(),
            "machine": _machine_spec(),
            "scale_profile": scale_name,
            "note": (
                "measured by `make bench` on the machine above; scales are what "
                "actually ran, not targets. See bench/run.py."
            ),
            "ingest_throughput_by_workers": ingest,
            "reachability": reach,
            "process_peak_rss_mb": round(
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                / (2**20 if platform.system() == "Darwin" else 2**10),
                1,
            ),
        }
        RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(results, indent=2))
    finally:
        await _cleanup(engine)
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
