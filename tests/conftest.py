"""Shared test infrastructure.

Integration tests get Postgres/Redis/Vault from REACHSET_TEST_* env vars when set
(CI provides service containers), otherwise from testcontainers started lazily on
first use. Unit tests never touch any of this.
"""

import os
import subprocess
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from redis.asyncio import Redis
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from reachset.db import make_engine, make_session_factory

REPO_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- postgres


@pytest.fixture(scope="session")
def pg_url() -> Iterator[str]:
    env_url = os.environ.get("REACHSET_TEST_DATABASE_URL")
    if env_url:
        yield env_url
        return
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest.fixture(scope="session")
def migrated_pg_url(pg_url: str) -> str:
    """Run alembic upgrade head once per session, over a sync connection."""
    env = os.environ | {"REACHSET_DATABASE_URL": pg_url}
    subprocess.run(["uv", "run", "alembic", "upgrade", "head"], cwd=REPO_ROOT, env=env, check=True)
    return pg_url


TRUNCATE_SQL = """
TRUNCATE TABLE reach_edges, identity_links, events, grants, credentials, resources,
    principals, sync_watermarks, dead_letters RESTART IDENTITY CASCADE
"""


@pytest.fixture
def sync_conn_url(migrated_pg_url: str) -> str:
    return migrated_pg_url.replace("+asyncpg", "+psycopg")


@pytest.fixture
async def pg_engine(migrated_pg_url: str, sync_conn_url: str) -> AsyncIterator[AsyncEngine]:
    """Function-scoped engine so connections always live on the test's event loop.
    Tables are truncated at setup so a crashed previous run can't leak state."""
    sync_engine = create_engine(sync_conn_url)
    with sync_engine.begin() as conn:
        conn.execute(text(TRUNCATE_SQL))
    sync_engine.dispose()
    engine = make_engine(migrated_pg_url, pool_size=4)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
def session_factory(pg_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return make_session_factory(pg_engine)


@pytest.fixture
async def db(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session


@pytest.fixture
def tenant() -> str:
    """Unique tenant per test; belt and braces on top of truncation."""
    return f"t-{uuid.uuid4().hex[:12]}"


# ----------------------------------------------------------------------------- redis


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    env_url = os.environ.get("REACHSET_TEST_REDIS_URL")
    if env_url:
        yield env_url
        return
    from testcontainers.redis import RedisContainer

    with RedisContainer("redis:7-alpine") as rc:
        host = rc.get_container_host_ip()
        port = rc.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"


@pytest.fixture
async def redis_client(redis_url: str) -> AsyncIterator[Redis]:
    client: Redis = Redis.from_url(redis_url)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.aclose()


# ----------------------------------------------------------------------------- vault


@dataclass
class VaultTestEnv:
    addr: str
    token: str
    # Returns the raw audit log contents for a device enabled at
    # `{audit_mount}/audit.log`. Env mode reads the host-mounted dir; container
    # mode execs into the vault container.
    read_audit: Callable[[], str]
    audit_mount: str


@pytest.fixture(scope="session")
def vault_env() -> Iterator[VaultTestEnv]:
    env_addr = os.environ.get("REACHSET_TEST_VAULT_ADDR")
    if env_addr:
        audit_mount = os.environ.get("REACHSET_TEST_VAULT_AUDIT_MOUNT", "/vault/logs")
        audit_dir = os.environ.get("REACHSET_TEST_VAULT_AUDIT_DIR")
        audit_cmd = os.environ.get("REACHSET_TEST_VAULT_AUDIT_CMD")

        def _read_from_dir() -> str:
            assert audit_dir is not None
            path = Path(audit_dir) / "audit.log"
            return path.read_text() if path.exists() else ""

        def _read_from_cmd() -> str:
            assert audit_cmd is not None
            result = subprocess.run(
                audit_cmd, shell=True, capture_output=True, text=True, cwd=REPO_ROOT
            )
            return result.stdout if result.returncode == 0 else ""

        if audit_dir is None and audit_cmd is None:
            raise RuntimeError(
                "REACHSET_TEST_VAULT_ADDR is set but neither REACHSET_TEST_VAULT_AUDIT_DIR "
                "nor REACHSET_TEST_VAULT_AUDIT_CMD is; the audit test needs one of them"
            )

        yield VaultTestEnv(
            addr=env_addr,
            token=os.environ["REACHSET_TEST_VAULT_TOKEN"],
            read_audit=_read_from_dir if audit_dir else _read_from_cmd,
            audit_mount=audit_mount,
        )
        return

    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_utils import wait_for_logs

    token = f"test-root-{uuid.uuid4().hex[:8]}"
    container = (
        DockerContainer("hashicorp/vault:1.17")
        .with_env("VAULT_DEV_ROOT_TOKEN_ID", token)
        .with_env("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .with_kwargs(cap_add=["IPC_LOCK"])
        .with_exposed_ports(8200)
    )
    with container:
        wait_for_logs(container, "Development mode", timeout=30)
        host = container.get_container_host_ip()
        port = container.get_exposed_port(8200)

        def _read_from_container() -> str:
            code, output = container.exec(["cat", "/vault/logs/audit.log"])
            return output.decode() if code == 0 else ""

        yield VaultTestEnv(
            addr=f"http://{host}:{port}",
            token=token,
            read_audit=_read_from_container,
            audit_mount="/vault/logs",
        )
