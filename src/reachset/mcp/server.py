"""Owns the MCP server wrapper. Thin by design: every tool is a one-session
call into reachset.mcp.tools, which is where the logic and the tests live.

Run with:  uv run python -m reachset.mcp.server  (stdio transport)
"""

import uuid
from typing import Any

from mcp.server.mcpserver import MCPServer

from reachset.config import load_settings
from reachset.db import make_engine, make_session_factory
from reachset.mcp import tools

server = MCPServer("reachset")
_settings = load_settings()
_engine = make_engine(_settings.database_url)
_factory = make_session_factory(_engine)


@server.tool()
async def assess_principal(tenant_id: str, principal_id: str) -> dict[str, Any]:
    """Reach summary, top risks, and evidence references for one principal.
    Returns conclusions sized for a context window, never raw edge dumps."""
    async with _factory() as session:
        return await tools.assess_principal(session, tenant_id, uuid.UUID(principal_id))


@server.tool()
async def find_risky_principals(tenant_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """Non-human identities ranked by privileged reach onto sensitive resources."""
    async with _factory() as session:
        return await tools.find_risky_principals(session, tenant_id, limit=limit)


@server.tool()
async def explain_edge(
    tenant_id: str, principal_id: str, resource_path: str, capability: str
) -> dict[str, Any]:
    """Full derivation path for one reach edge: why can X touch Y."""
    async with _factory() as session:
        return await tools.explain_edge(
            session, tenant_id, uuid.UUID(principal_id), resource_path, capability
        )


if __name__ == "__main__":
    server.run()
