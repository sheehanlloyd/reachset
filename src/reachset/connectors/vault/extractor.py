"""Owns pure extraction from Vault API JSON to canonical records.

No I/O, no clock, no randomness. Every function takes payloads the transport
already fetched and returns records. Malformed input raises ValueError with
context rather than producing half-records.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from reachset.models import (
    Capability,
    CredentialKind,
    PrincipalKind,
    Provenance,
    ResourceKind,
)
from reachset.records import (
    CredentialRecord,
    EventRecord,
    GrantRecord,
    PrincipalRecord,
    ResourceRecord,
)
from reachset.scopes.registry import capabilities_for

_POLICY_PATH_RE = re.compile(
    r'path\s+"(?P<path>[^"]+)"\s*\{(?P<body>[^}]*)\}', re.MULTILINE | re.DOTALL
)
_CAPS_RE = re.compile(r"capabilities\s*=\s*\[(?P<caps>[^\]]*)\]")


def _parse_ts(value: Any) -> datetime | None:
    """Vault mixes epoch ints, ISO strings, empty strings, and nulls."""
    if value in (None, "", 0):
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        try:
            ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"unparseable vault timestamp {value!r}") from exc
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    raise ValueError(f"unparseable vault timestamp {value!r}")


def _sensitivity_for_path(path: str) -> int:
    # Declared heuristic, not a claim: prod-ish paths are 3, everything else 2
    # for auth/identity config and 1 for plain secret paths.
    if path.startswith(("sys/", "auth/")):
        return 3
    if "prod" in path:
        return 3
    return 1


def parse_policy_document(name: str, hcl: str) -> list[tuple[str, frozenset[Capability]]]:
    """Parse the path rules out of an ACL policy document.

    Vault policies are HCL; dev-authored policies use the plain
    `path "..." { capabilities = [...] }` form, which is what this parses.
    `deny` wins over everything else on the same path, per Vault semantics.
    """
    rules: list[tuple[str, frozenset[Capability]]] = []
    for match in _POLICY_PATH_RE.finditer(hcl):
        caps_match = _CAPS_RE.search(match.group("body"))
        if caps_match is None:
            raise ValueError(f"policy {name!r}: path block without capabilities list")
        scope_strings = [
            s.strip().strip('"') for s in caps_match.group("caps").split(",") if s.strip()
        ]
        if "deny" in scope_strings:
            continue
        caps: set[Capability] = set()
        for scope in scope_strings:
            caps |= capabilities_for("vault", scope)
        # Vault's `+` matches exactly one path segment; our selector language has
        # only `*`/`?`, so `+` widens to `*` (documented in NOTES.md).
        selector = match.group("path").replace("+", "*")
        rules.append((selector, frozenset(caps)))
    return rules


def extract_policies(
    list_payload: dict[str, Any], docs: dict[str, str]
) -> dict[str, list[tuple[str, frozenset[Capability]]]]:
    """Combine LIST /sys/policies/acl with each policy body into parsed rules.

    `root` has no document: it is synthesized as sudo over everything.
    """
    names = list_payload.get("data", {}).get("keys")
    if not isinstance(names, list):
        raise ValueError("sys/policies/acl list payload missing data.keys")
    parsed: dict[str, list[tuple[str, frozenset[Capability]]]] = {}
    for name in names:
        if name == "root":
            parsed[name] = [("*", capabilities_for("vault", "policy:root"))]
            continue
        if name not in docs:
            raise ValueError(f"policy {name!r} listed but no document supplied")
        parsed[name] = parse_policy_document(name, docs[name])
    # Vault implicitly attaches `default` even when the operator never wrote it.
    parsed.setdefault("default", [])
    return parsed


def extract_auth_methods(payload: dict[str, Any]) -> list[ResourceRecord]:
    """Each enabled auth method becomes an `auth/<mount>` resource so that
    sudo-over-sys policies visibly reach identity configuration."""
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("sys/auth payload missing data")
    records = []
    for mount, config in sorted(data.items()):
        if not isinstance(config, dict) or "type" not in config:
            continue  # request metadata keys live alongside mounts in this payload
        path = f"auth/{mount.rstrip('/')}"
        records.append(
            ResourceRecord(
                external_id=path,
                kind=ResourceKind.SECRET_PATH,
                path=path,
                sensitivity=3,
            )
        )
    return records


def extract_secret_paths(paths: list[str]) -> list[ResourceRecord]:
    """KV v2 metadata listings, already flattened to full `secret/data/...` paths."""
    records = []
    for path in sorted(set(paths)):
        records.append(
            ResourceRecord(
                external_id=path,
                kind=ResourceKind.SECRET_PATH,
                path=path,
                sensitivity=_sensitivity_for_path(path),
            )
        )
    return records


def extract_token(
    accessor: str,
    lookup_payload: dict[str, Any],
    policy_rules: dict[str, list[tuple[str, frozenset[Capability]]]],
) -> tuple[PrincipalRecord, CredentialRecord, list[GrantRecord]]:
    """One token accessor + its lookup into principal, credential, and grants.

    The principal is the token's entity when one exists, else the token itself
    (root/orphan tokens have no entity). Tokens are service identities unless the
    display name marks them as an agent.
    """
    data = lookup_payload.get("data")
    if not isinstance(data, dict):
        raise ValueError(f"lookup-accessor payload for {accessor!r} missing data")

    display_name = data.get("display_name") or None
    entity_id = data.get("entity_id") or None
    principal_external = entity_id or f"token:{accessor}"
    name_l = (display_name or "").lower()
    if "agent" in name_l or "mcp" in name_l or "bot" in name_l:
        kind = PrincipalKind.AGENT
    else:
        kind = PrincipalKind.SERVICE

    principal = PrincipalRecord(
        external_id=principal_external,
        kind=kind,
        display_name=display_name,
        created_at=_parse_ts(data.get("creation_time")),
        last_active_at=_parse_ts(data.get("last_renewal_time")),
    )
    credential = CredentialRecord(
        external_id=accessor,
        kind=CredentialKind.VAULT_TOKEN,
        principal_external_id=principal_external,
        issued_at=_parse_ts(data.get("issue_time") or data.get("creation_time")),
        last_used_at=_parse_ts(data.get("last_renewal_time")),
        expires_at=_parse_ts(data.get("expire_time")),
    )

    grants: list[GrantRecord] = []
    policies = data.get("policies")
    if not isinstance(policies, list):
        raise ValueError(f"token {accessor!r} lookup has no policies list")
    for policy in policies:
        rules = policy_rules.get(policy)
        if rules is None:
            raise ValueError(f"token {accessor!r} references unknown policy {policy!r}")
        for selector, caps in rules:
            if not caps:
                continue
            grants.append(
                GrantRecord(
                    principal_external_id=principal_external,
                    credential_external_id=accessor,
                    resource_selector=selector,
                    scope_raw=f"policy:{policy}",
                    capabilities=caps,
                    granted_at=_parse_ts(data.get("creation_time")),
                )
            )
    return principal, credential, grants


def extract_accessor_list(payload: dict[str, Any]) -> list[str]:
    keys = payload.get("data", {}).get("keys")
    if not isinstance(keys, list):
        raise ValueError("token accessors payload missing data.keys")
    return [k for k in keys if isinstance(k, str)]


def extract_audit_events(lines: list[str]) -> list[EventRecord]:
    """File audit device output: one JSON object per line, request+response pairs.

    Only `response` entries become events (they mark the operation actually
    happened). raw_ref is a content hash, which is what makes audit re-reads
    idempotent. Unparseable lines raise: an audit log we cannot read end-to-end
    is a finding, not something to skip over.
    """
    events: list[EventRecord] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"unparseable audit line: {line[:80]!r}") from exc
        if entry.get("type") != "response":
            continue
        request = entry.get("request", {})
        auth = entry.get("auth", {})
        ts = _parse_ts(entry.get("time"))
        if ts is None:
            raise ValueError("audit entry missing time")
        path = request.get("path", "")
        events.append(
            EventRecord(
                raw_ref=hashlib.sha256(line.encode()).hexdigest(),
                action=f"vault.{request.get('operation', 'unknown')}",
                ts=ts,
                provenance=Provenance.AUDIT_LOG,
                actor_external_id=(auth.get("entity_id") or None)
                or (f"token:{auth['accessor']}" if auth.get("accessor") else None),
                target_resource_external_id=f"secret/{path.removeprefix('secret/')}"
                if path.startswith("secret/")
                else path or None,
                ip=request.get("remote_address") or None,
            )
        )
    return events
