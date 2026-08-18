"""Owns the synthetic tenant generator.

Configurable up to 50k principals / 200k grants / 5M events. Distributions aim
for realism, not convenience:
- principal mix skews human, with a service/agent tail;
- activity is long-tailed: ~10% of principals produce ~90% of events, and most
  principals are inert;
- events follow a diurnal curve in each principal's own home timezone offset.

Everything is seeded; the same (seed, sizes) always produces the same tenant.
"""

import argparse
import asyncio
import math
import random
import uuid
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from reachset.config import load_settings
from reachset.db import make_engine, make_session_factory
from reachset.logging import configure_logging, get_logger

log = get_logger(__name__)

APPS = ("vault", "github", "salesforce")
CAP_SETS: tuple[tuple[str, ...], ...] = (
    ("read",),
    ("read",),
    ("read",),  # reads dominate
    ("read", "write"),
    ("read", "write", "delete"),
    ("read", "write", "delete", "admin"),
)


@dataclass(frozen=True)
class SynthConfig:
    tenant_id: str
    principals: int = 1000
    grants: int = 4000
    events: int = 50_000
    resources: int | None = None  # default: principals // 2, min 50
    seed: int = 20260818
    end: datetime = datetime(2026, 8, 18, tzinfo=UTC)
    days: int = 60
    impersonation_fraction: float = 0.01

    @property
    def resource_count(self) -> int:
        return self.resources if self.resources is not None else max(50, self.principals // 2)


def _principal_kind(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.70:
        return "human"
    if roll < 0.94:
        return "service"
    if roll < 0.99:
        return "agent"
    return "app"


def _zipf_weights(n: int, exponent: float = 1.1) -> list[float]:
    return [1.0 / (rank**exponent) for rank in range(1, n + 1)]


async def generate(session: AsyncSession, config: SynthConfig) -> dict[str, int]:
    """Insert one synthetic tenant. Returns row counts by table."""
    from sqlalchemy import text

    # Tenant id is folded into the seed so two tenants generated with the same
    # numeric seed still get disjoint row ids.
    rng = random.Random(f"{config.seed}:{config.tenant_id}")

    principal_rows = []
    for i in range(config.principals):
        app = APPS[i % len(APPS)]
        kind = _principal_kind(rng)
        principal_rows.append(
            {
                "id": uuid.UUID(int=rng.getrandbits(128), version=4),
                "tenant": config.tenant_id,
                "app": app,
                "external_id": f"{app}-{kind}-{i:06d}",
                "kind": kind,
                "name": f"{kind}-{i:06d}",
                "created_at": config.end - timedelta(days=rng.uniform(30, 900)),
            }
        )

    resource_rows = []
    for i in range(config.resource_count):
        app = APPS[i % len(APPS)]
        sensitivity = rng.choices([0, 1, 2, 3], weights=[30, 40, 20, 10])[0]
        kind = {"vault": "secret_path", "github": "repo", "salesforce": "sobject"}[app]
        path = {
            "vault": f"secret/data/team{i % 40}/svc{i:05d}",
            "github": f"acme/repo-{i:05d}",
            "salesforce": f"sobject/Custom{i:05d}",
        }[app]
        resource_rows.append(
            {
                "id": uuid.UUID(int=rng.getrandbits(128), version=4),
                "tenant": config.tenant_id,
                "app": app,
                "external_id": path,
                "kind": kind,
                "path": path,
                "sensitivity": sensitivity,
            }
        )

    grant_rows = []
    resources_by_app: dict[str, list[dict[str, object]]] = {}
    for row in resource_rows:
        resources_by_app.setdefault(str(row["app"]), []).append(row)
    principal_weights = _zipf_weights(len(principal_rows), 0.8)
    granted = rng.choices(principal_rows, weights=principal_weights, k=config.grants)
    for i, principal in enumerate(granted):
        app = str(principal["app"])
        pool = resources_by_app.get(app, resource_rows)
        if rng.random() < config.impersonation_fraction:
            target = rng.choice(principal_rows)
            selector = f"principal:{target['external_id']}"
            caps = ["impersonate"]
        elif rng.random() < 0.15:
            # glob over a team prefix
            sample = rng.choice(pool)
            prefix = str(sample["path"]).rsplit("/", 1)[0]
            selector = f"{prefix}/*"
            caps = list(rng.choice(CAP_SETS))
        else:
            selector = str(rng.choice(pool)["path"])
            caps = list(rng.choice(CAP_SETS))
        grant_rows.append(
            {
                "id": uuid.UUID(int=rng.getrandbits(128), version=4),
                "tenant": config.tenant_id,
                "pid": principal["id"],
                "selector": selector,
                "scope": f"syn-scope-{i:06d}",
                "caps": caps,
                "app": app,
                "key": f"synth-{config.seed}-{i:08d}",
            }
        )

    # Long-tail actors: only ~a quarter of principals ever act at all, and a
    # zipf head inside that pool produces most of the traffic. Most principals
    # are inert, which is what real tenants look like.
    actor_pool = principal_rows[: max(1, len(principal_rows) // 4)]
    actor_weights = _zipf_weights(len(actor_pool), 1.3)
    actors = rng.choices(actor_pool, weights=actor_weights, k=config.events)
    event_rows = []
    for i, actor in enumerate(actors):
        # zlib.crc32, not hash(): the builtin is salted per process and would
        # break the "same seed, same tenant" guarantee.
        home_offset = zlib.crc32(str(actor["external_id"]).encode()) % 24
        day = rng.uniform(0, config.days)
        # diurnal curve centered on the actor's home offset
        hour = (home_offset + rng.gauss(4, 2.5)) % 24
        ts = config.end - timedelta(days=day)
        ts = ts.replace(hour=int(hour), minute=rng.randrange(60), second=rng.randrange(60))
        app = str(actor["app"])
        action = rng.choices(
            [f"{app}.read", f"{app}.list", f"{app}.write", f"{app}.login"],
            weights=[70, 15, 10, 5],
        )[0]
        event_rows.append(
            {
                "tenant": config.tenant_id,
                "app": app,
                "actor": actor["id"],
                "action": action,
                "ts": ts,
                "raw_ref": f"synth-{config.seed}-{i:09d}",
            }
        )

    async def _copy(sql: str, rows: list[dict[str, object]], chunk: int = 5000) -> None:
        for start in range(0, len(rows), chunk):
            await session.execute(text(sql), rows[start : start + chunk])

    await _copy(
        "INSERT INTO principals (id, tenant_id, app_id, external_id, kind, status, "
        "display_name, created_at, first_seen_at) "
        "VALUES (:id, :tenant, :app, :external_id, :kind, 'active', :name, :created_at, "
        ":created_at)",
        principal_rows,
    )
    await _copy(
        "INSERT INTO resources (id, tenant_id, app_id, external_id, kind, path, sensitivity) "
        "VALUES (:id, :tenant, :app, :external_id, :kind, :path, :sensitivity)",
        resource_rows,
    )
    await _copy(
        "INSERT INTO grants (id, tenant_id, principal_id, resource_selector, scope_raw, "
        "capabilities, source_app_id, dedupe_key) "
        "VALUES (:id, :tenant, :pid, :selector, :scope, :caps, :app, :key)",
        grant_rows,
    )
    await _copy(
        "INSERT INTO events (tenant_id, app_id, actor_principal_id, action, ts, raw_ref, "
        "provenance) VALUES (:tenant, :app, :actor, :action, :ts, :raw_ref, 'audit_log')",
        event_rows,
    )
    await session.commit()
    counts = {
        "principals": len(principal_rows),
        "resources": len(resource_rows),
        "grants": len(grant_rows),
        "events": len(event_rows),
    }
    log.info("synthetic_tenant_generated", tenant=config.tenant_id, **counts)
    return counts


async def _main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic tenant")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--principals", type=int, default=1000)
    parser.add_argument("--grants", type=int, default=4000)
    parser.add_argument("--events", type=int, default=50_000)
    parser.add_argument("--seed", type=int, default=20260818)
    args = parser.parse_args(argv)

    settings = load_settings()
    configure_logging(settings.log_level)
    engine: AsyncEngine = make_engine(settings.database_url)
    factory: async_sessionmaker[AsyncSession] = make_session_factory(engine)
    try:
        async with factory() as session:
            await generate(
                session,
                SynthConfig(
                    tenant_id=args.tenant,
                    principals=args.principals,
                    grants=args.grants,
                    events=args.events,
                    seed=args.seed,
                ),
            )
    finally:
        await engine.dispose()


def estimate_batches(total: int, chunk: int = 5000) -> int:
    """Exposed for tests; mirrors _copy's chunking."""
    return math.ceil(total / chunk) if total else 0


if __name__ == "__main__":
    asyncio.run(_main())
