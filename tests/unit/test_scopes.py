"""The scope-mapping completeness contract: every scope string our fixtures can
produce maps to capabilities, and anything else fails loudly — never `read`."""

import json
import re
from pathlib import Path

import pytest

from reachset.models import Capability
from reachset.scopes import registry

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_unknown_scope_fails_loudly_not_read() -> None:
    with pytest.raises(registry.UnknownScopeError) as excinfo:
        registry.capabilities_for("vault", "osmose")
    assert "refusing to guess" in str(excinfo.value)


def test_unknown_app_fails() -> None:
    with pytest.raises(KeyError):
        registry.table_for("faxmachine")


def test_every_vault_fixture_capability_string_maps() -> None:
    caps_re = re.compile(r"capabilities\s*=\s*\[([^\]]*)\]")
    seen: set[str] = set()
    for doc in (FIXTURES / "vault").glob("policy_*.json"):
        policy = json.loads(doc.read_text())["data"]["policy"]
        for match in caps_re.finditer(policy):
            seen.update(s.strip().strip('"') for s in match.group(1).split(",") if s.strip())
    assert seen, "no capability strings found in vault fixtures"
    for scope in seen:
        registry.capabilities_for("vault", scope)  # must not raise


def test_every_github_fixture_scope_maps() -> None:
    seen: set[str] = set()
    github_dir = FIXTURES / "github"
    for doc in github_dir.glob("*.json"):
        if doc.name == "routes.json":
            continue
        payload = json.loads(doc.read_text())
        _collect_scope_strings(payload, seen)
    assert seen, "no scope strings found in github fixtures"
    for scope in seen:
        registry.capabilities_for("github", scope)  # must not raise


def _collect_scope_strings(node: object, out: set[str]) -> None:
    """Fixture-wide sweep: every `scopes` list, permission map, and deploy-key
    flag in the GitHub fixtures ends up asserted against the table."""
    if isinstance(node, dict):
        scopes = node.get("scopes")
        if isinstance(scopes, list):
            out.update(s for s in scopes if isinstance(s, str))
        perms = node.get("permissions")
        if isinstance(perms, dict):
            for subject, level in perms.items():
                if isinstance(level, str):
                    out.add(f"{subject}:{level}")
                elif level is True:
                    out.add(f"permission:{subject}")
        if node.get("read_only") is True:
            out.add("deploy_key:ro")
        elif node.get("read_only") is False:
            out.add("deploy_key:rw")
        role = node.get("role_name")
        if isinstance(role, str):
            out.add(f"permission:{role}")
        for value in node.values():
            _collect_scope_strings(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_scope_strings(item, out)


def test_deny_maps_to_no_capabilities() -> None:
    assert registry.capabilities_for("vault", "deny") == frozenset()


def test_sudo_includes_impersonate() -> None:
    assert Capability.IMPERSONATE in registry.capabilities_for("vault", "sudo")


def test_tables_are_versioned() -> None:
    for app in ("vault", "github"):
        assert registry.table_for(app).version


def test_prefix_rules_match_by_prefix() -> None:
    """Exact entries cover every scope our connectors emit today; the prefix
    mechanism exists for apps whose scope strings are open-ended."""
    table = registry.ScopeTable(
        app_id="demo",
        version="test",
        exact={"exact:thing": frozenset({Capability.READ})},
        prefixes={"custom.": frozenset({Capability.READ, Capability.WRITE})},
    )
    assert table.capabilities_for("exact:thing") == frozenset({Capability.READ})
    assert table.capabilities_for("custom.anything") == frozenset(
        {Capability.READ, Capability.WRITE}
    )
    with pytest.raises(registry.UnknownScopeError):
        table.capabilities_for("unmatched.scope")
