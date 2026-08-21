"""Vault extractor over hand-authored fixtures, including the ugly cases:
null display names, unicode/injection text, unknown policies, malformed audit."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reachset.connectors.vault import extractor
from reachset.models import Capability, CredentialKind, PrincipalKind
from reachset.scopes.registry import UnknownScopeError

FIXTURES = Path(__file__).parent.parent / "fixtures" / "vault"


def _load(name: str) -> dict:  # type: ignore[type-arg]  # test helper, payload shape varies
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def policy_rules() -> dict[str, list[tuple[str, frozenset[Capability]]]]:
    docs = {
        name: _load(f"policy_{name.replace('-', '_')}.json")["data"]["policy"]
        for name in ("default", "ci-deploy", "admin-sudo", "agent-scoped")
    }
    return extractor.extract_policies(_load("policies_list.json"), docs)


def test_policy_parsing_capabilities(policy_rules: dict) -> None:  # type: ignore[type-arg]
    ci = dict(policy_rules["ci-deploy"])
    assert ci["secret/data/prod/*"] == frozenset({Capability.READ})
    # Vault's `+` single-segment wildcard is stored verbatim, not widened.
    assert "secret/data/ci/scratch/+/state" in ci
    assert Capability.DELETE in ci["secret/data/ci/scratch/+/state"]

    # deny paths are dropped, not mapped
    agent = dict(policy_rules["agent-scoped"])
    assert "secret/data/shared/raw-dumps/*" not in agent

    # root is synthesized as sudo-everything
    root = dict(policy_rules["root"])
    assert root["*"] == frozenset(Capability)


def test_unknown_policy_capability_fails_loudly() -> None:
    hcl = 'path "secret/*" {\n  capabilities = ["read", "transmute"]\n}\n'
    with pytest.raises(UnknownScopeError, match="transmute"):
        extractor.parse_policy_document("weird", hcl)


def test_policy_block_without_capabilities_is_an_error() -> None:
    with pytest.raises(ValueError, match="without capabilities"):
        extractor.parse_policy_document("broken", 'path "secret/*" {\n}\n')


def test_token_extraction_happy_path(policy_rules: dict) -> None:  # type: ignore[type-arg]
    principal, credential, grants = extractor.extract_token(
        "acc-ci-deploy-01", _load("lookup_ci_deploy.json"), policy_rules
    )
    assert principal.external_id == "token:acc-ci-deploy-01"  # no entity -> token identity
    assert principal.kind is PrincipalKind.SERVICE
    assert credential.kind is CredentialKind.VAULT_TOKEN
    assert credential.issued_at == datetime(2025, 5, 15, 9, 46, 40, tzinfo=UTC)
    selectors = {g.resource_selector for g in grants}
    assert "secret/data/prod/*" in selectors
    assert "auth/token/lookup-self" in selectors  # default policy came along


def test_token_with_entity_uses_entity_identity(policy_rules: dict) -> None:  # type: ignore[type-arg]
    principal, credential, _ = extractor.extract_token(
        "acc-agent-mcp-7", _load("lookup_agent_mcp.json"), policy_rules
    )
    assert principal.external_id == "entity-9a8b7c6d"
    assert principal.kind is PrincipalKind.AGENT
    assert credential.principal_external_id == "entity-9a8b7c6d"
    assert credential.expires_at is not None


def test_token_null_display_name(policy_rules: dict) -> None:  # type: ignore[type-arg]
    principal, credential, grants = extractor.extract_token(
        "acc-null-display", _load("lookup_null_display.json"), policy_rules
    )
    assert principal.display_name is None
    assert credential.issued_at == datetime.fromtimestamp(1719222000, tz=UTC)
    # admin-sudo grants sudo over * -> impersonate capability present
    caps = {c for g in grants for c in g.capabilities}
    assert Capability.IMPERSONATE in caps


def test_unicode_and_injection_display_name_passes_through(policy_rules: dict) -> None:  # type: ignore[type-arg]
    principal, _, _ = extractor.extract_token(
        "acc-unicode-name", _load("lookup_unicode.json"), policy_rules
    )
    assert principal.display_name is not None
    assert "DROP TABLE" in principal.display_name  # stored as data, nothing more
    assert principal.kind is PrincipalKind.AGENT  # "bot" in the name


def test_token_referencing_unknown_policy_raises(policy_rules: dict) -> None:  # type: ignore[type-arg]
    payload = _load("lookup_ci_deploy.json")
    payload["data"]["policies"] = ["ci-deploy", "ghost-policy"]
    with pytest.raises(ValueError, match="ghost-policy"):
        extractor.extract_token("acc-ci-deploy-01", payload, policy_rules)


def test_auth_methods_become_high_sensitivity_resources() -> None:
    records = extractor.extract_auth_methods(_load("sys_auth.json"))
    paths = {r.path for r in records}
    assert paths == {"auth/token", "auth/approle"}
    assert all(r.sensitivity == 3 for r in records)


def test_secret_path_sensitivity_heuristic() -> None:
    records = extractor.extract_secret_paths(
        ["secret/data/prod/db", "secret/data/dev/scratch", "secret/data/prod/db"]
    )
    by_path = {r.path: r.sensitivity for r in records}
    assert by_path == {"secret/data/prod/db": 3, "secret/data/dev/scratch": 1}
    assert len(records) == 2  # dedup


def test_audit_events_extraction() -> None:
    lines = (FIXTURES / "audit_sample.jsonl").read_text().splitlines()
    events = extractor.extract_audit_events(lines)
    # 5 lines, 1 is a request entry -> 4 events
    assert len(events) == 4
    read = next(
        e
        for e in events
        if e.action == "vault.read" and "prod/db" in (e.target_resource_external_id or "")
    )
    assert read.actor_external_id == "token:hmac-sha256:9be2"  # accessor hmac'd, still stable
    agent_read = next(
        e for e in events if e.actor_external_id == "entity-9a8b7c6d" and e.action == "vault.read"
    )
    assert agent_read.ip == "10.4.9.3"
    # idempotency: raw_ref is a stable content hash
    assert len({e.raw_ref for e in events}) == 4
    assert extractor.extract_audit_events(lines)[0].raw_ref == events[0].raw_ref


def test_audit_malformed_line_raises() -> None:
    with pytest.raises(ValueError, match="unparseable audit line"):
        extractor.extract_audit_events(['{"type": "response", "time": "2026-01-01T00:00:00Z"', ""])


def test_parse_ts_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        extractor._parse_ts("not-a-date")
    assert extractor._parse_ts(None) is None
    assert extractor._parse_ts("") is None
    assert extractor._parse_ts(0) is None


# --- malformed-payload paths -------------------------------------------------


def test_policy_list_without_keys_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"missing data\.keys"):
        extractor.extract_policies({"data": {}}, {})


def test_policy_listed_without_a_document_is_rejected() -> None:
    """Vault listed a policy we never fetched: proceeding would silently drop
    whatever that policy grants."""
    with pytest.raises(ValueError, match="listed but no document supplied"):
        extractor.extract_policies({"data": {"keys": ["ghost"]}}, {})


def test_auth_payload_without_data_is_rejected() -> None:
    with pytest.raises(ValueError, match="sys/auth payload missing data"):
        extractor.extract_auth_methods({"request_id": "x"})


def test_auth_payload_ignores_non_mount_metadata_keys() -> None:
    """Vault mixes request metadata in alongside the mounts; only entries that
    look like mounts (they carry a type) are resources."""
    records = extractor.extract_auth_methods(
        {"data": {"token/": {"type": "token"}, "request_id": "not-a-mount"}}
    )
    assert [r.path for r in records] == ["auth/token"]


def test_lookup_payload_without_data_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing data"):
        extractor.extract_token("acc-x", {"request_id": "y"}, {})


def test_token_without_a_policies_list_is_rejected() -> None:
    with pytest.raises(ValueError, match="has no policies list"):
        extractor.extract_token("acc-x", {"data": {"accessor": "acc-x"}}, {})


def test_policy_granting_nothing_produces_no_grant() -> None:
    """A deny-only policy is real and must not become a phantom grant."""
    _, _, grants = extractor.extract_token(
        "acc-x",
        {"data": {"accessor": "acc-x", "policies": ["deny-only"], "creation_time": 0}},
        {"deny-only": [("secret/*", frozenset())]},
    )
    assert grants == []


def test_accessor_list_without_keys_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"token accessors payload missing data\.keys"):
        extractor.extract_accessor_list({"data": {}})


def test_accessor_list_skips_non_string_entries() -> None:
    assert extractor.extract_accessor_list({"data": {"keys": ["ok", 42, None]}}) == ["ok"]


def test_audit_entry_without_a_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="audit entry missing time"):
        extractor.extract_audit_events(['{"type": "response", "request": {"path": "x"}}'])


def test_audit_skips_blank_lines() -> None:
    lines = (FIXTURES / "audit_sample.jsonl").read_text().splitlines()
    assert extractor.extract_audit_events([*lines, "", "   "]) == extractor.extract_audit_events(
        lines
    )


def test_sys_and_auth_paths_are_top_sensitivity() -> None:
    records = extractor.extract_secret_paths(["sys/policies/acl", "auth/token/create"])
    assert {r.sensitivity for r in records} == {3}


def test_timestamp_of_an_unexpected_type_is_rejected() -> None:
    """A list where a timestamp belongs means the payload shape changed; that
    is worth failing on rather than coercing."""
    with pytest.raises(ValueError, match="unparseable vault timestamp"):
        extractor._parse_ts(["2026-01-01"])
