"""The MCP wrapper registers exactly the tools the docs promise."""

import pytest

from reachset.mcp.server import server


async def test_registered_tools() -> None:
    tools = await server.list_tools()
    names = {tool.name for tool in tools}
    assert names == {"assess_principal", "find_risky_principals", "explain_edge"}
    for tool in tools:
        assert tool.description, f"{tool.name} has no description"


async def test_tools_delegate_to_the_library(monkeypatch: "pytest.MonkeyPatch") -> None:
    """The server layer is deliberately thin: assert it forwards arguments and
    returns what the library gives it, and nothing more."""
    import uuid as _uuid

    from reachset.mcp import server as server_module

    calls: list[tuple[str, tuple[object, ...]]] = []

    class _FakeSession:
        async def __aenter__(self) -> "_FakeSession":
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(server_module, "_factory", lambda: _FakeSession())

    async def _assess(session, tenant, principal_id):  # type: ignore[no-untyped-def]  # test double
        calls.append(("assess", (tenant, principal_id)))
        return {"ok": "assess"}

    async def _risky(session, tenant, *, limit):  # type: ignore[no-untyped-def]  # test double
        calls.append(("risky", (tenant, limit)))
        return [{"ok": "risky"}]

    async def _explain(session, tenant, principal_id, path, capability):  # type: ignore[no-untyped-def]  # test double
        calls.append(("explain", (tenant, principal_id, path, capability)))
        return {"ok": "explain"}

    monkeypatch.setattr(server_module.tools, "assess_principal", _assess)
    monkeypatch.setattr(server_module.tools, "find_risky_principals", _risky)
    monkeypatch.setattr(server_module.tools, "explain_edge", _explain)

    principal_id = _uuid.uuid4()
    assert await server_module.assess_principal("t1", str(principal_id)) == {"ok": "assess"}
    assert await server_module.find_risky_principals("t1", limit=3) == [{"ok": "risky"}]
    assert await server_module.explain_edge("t1", str(principal_id), "secret/x", "read") == {
        "ok": "explain"
    }

    assert calls == [
        ("assess", ("t1", principal_id)),
        ("risky", ("t1", 3)),
        ("explain", ("t1", principal_id, "secret/x", "read")),
    ]
