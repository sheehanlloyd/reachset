"""The MCP wrapper registers exactly the tools the docs promise."""

from reachset.mcp.server import server


async def test_registered_tools() -> None:
    tools = await server.list_tools()
    names = {tool.name for tool in tools}
    assert names == {"assess_principal", "find_risky_principals", "explain_edge"}
    for tool in tools:
        assert tool.description, f"{tool.name} has no description"
