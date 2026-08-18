"""Owns pure extraction from GitHub org API JSON to canonical records.

Fixture-verified only: shapes come from public REST API docs, and every
behavioral assumption that hasn't met a live tenant is listed in NOTES.md.
"""

import hashlib
import json
from datetime import datetime
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


def _ts(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, int | float):  # audit log uses epoch millis
        from datetime import UTC

        return datetime.fromtimestamp(float(value) / 1000.0, tz=UTC)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    raise ValueError(f"unparseable github timestamp {value!r}")


def _user_kind(user: dict[str, Any]) -> PrincipalKind:
    if user.get("type") == "Bot" or user.get("login", "").endswith("[bot]"):
        return PrincipalKind.AGENT
    return PrincipalKind.HUMAN


def extract_members(payload: list[dict[str, Any]]) -> list[PrincipalRecord]:
    records = []
    for user in payload:
        if "login" not in user:
            raise ValueError(f"member entry without login: {json.dumps(user)[:120]}")
        records.append(
            PrincipalRecord(
                external_id=f"user:{user['id']}" if "id" in user else f"user:{user['login']}",
                kind=_user_kind(user),
                display_name=user.get("name") or user["login"],
                email=user.get("email") or None,
                created_at=_ts(user.get("created_at")),
            )
        )
    return records


def extract_repos(payload: list[dict[str, Any]]) -> list[ResourceRecord]:
    records = []
    for repo in payload:
        if "full_name" not in repo:
            raise ValueError("repo entry without full_name")
        private = bool(repo.get("private", False))
        name = repo["full_name"].lower()
        if any(hint in name for hint in ("prod", "infra", "secrets", "payments")):
            sensitivity = 3
        elif private:
            sensitivity = 2
        else:
            sensitivity = 1
        records.append(
            ResourceRecord(
                external_id=f"repo:{repo['id']}" if "id" in repo else repo["full_name"],
                kind=ResourceKind.REPO,
                path=repo["full_name"],
                sensitivity=sensitivity,
            )
        )
    return records


def _caps_for_permission_map(perms: dict[str, Any]) -> frozenset[Capability]:
    """App-installation / fine-grained-PAT permission maps: {"contents": "read"}."""
    caps: set[Capability] = set()
    for subject, level in sorted(perms.items()):
        if not isinstance(level, str):
            continue
        caps |= capabilities_for("github", f"{subject}:{level}")
    return frozenset(caps)


def extract_installations(
    payload: dict[str, Any],
) -> tuple[list[PrincipalRecord], list[GrantRecord]]:
    """Org app installations: each is an `app` principal with grants over either
    every repo in the org or an explicit repo list (resolved by the connector)."""
    installations = payload.get("installations")
    if not isinstance(installations, list):
        raise ValueError("installations payload missing 'installations'")
    principals = []
    grants = []
    for inst in installations:
        app_slug = inst.get("app_slug")
        if not app_slug:
            raise ValueError("installation without app_slug")
        external_id = f"installation:{inst['id']}"
        principals.append(
            PrincipalRecord(
                external_id=external_id,
                kind=PrincipalKind.APP,
                display_name=app_slug,
                created_at=_ts(inst.get("created_at")),
                last_active_at=_ts(inst.get("updated_at")),
            )
        )
        caps = _caps_for_permission_map(inst.get("permissions", {}))
        if not caps:
            continue
        scope_raw = "installation:" + ",".join(
            f"{k}={v}" for k, v in sorted(inst.get("permissions", {}).items())
        )
        if inst.get("repository_selection") == "all":
            selector = f"{payload.get('org', '*')}/*"
        else:
            # Connector resolves the selected repo list into explicit selectors;
            # the extractor records a marker the connector replaces.
            selector = "__selected__"
        grants.append(
            GrantRecord(
                principal_external_id=external_id,
                resource_selector=selector,
                scope_raw=scope_raw,
                capabilities=caps,
                granted_at=_ts(inst.get("created_at")),
            )
        )
    return principals, grants


def expand_selected_grant(template: GrantRecord, repos: list[dict[str, Any]]) -> list[GrantRecord]:
    """Expand a selected-repos grant (installation or fine-grained PAT) into one
    grant per explicitly-selected repository."""
    for repo in repos:
        if "full_name" not in repo:
            raise ValueError("selected repository without full_name")
    return [
        GrantRecord(
            principal_external_id=template.principal_external_id,
            credential_external_id=template.credential_external_id,
            resource_selector=repo["full_name"],
            scope_raw=template.scope_raw,
            capabilities=template.capabilities,
            granted_at=template.granted_at,
        )
        for repo in repos
    ]


def extract_pat_grants(
    payload: list[dict[str, Any]],
) -> tuple[list[PrincipalRecord], list[CredentialRecord], list[GrantRecord]]:
    """Fine-grained PAT grants (GET /orgs/{org}/personal-access-tokens)."""
    principals: dict[str, PrincipalRecord] = {}
    credentials = []
    grants = []
    for pat in payload:
        owner = pat.get("owner")
        if not isinstance(owner, dict) or "id" not in owner:
            raise ValueError("PAT grant without owner")
        owner_external = f"user:{owner['id']}"
        principals.setdefault(
            owner_external,
            PrincipalRecord(
                external_id=owner_external,
                kind=_user_kind(owner),
                display_name=owner.get("login"),
            ),
        )
        credential_external = f"pat:{pat['id']}"
        credentials.append(
            CredentialRecord(
                external_id=credential_external,
                kind=CredentialKind.PAT,
                principal_external_id=owner_external,
                issued_at=_ts(pat.get("access_granted_at")),
                last_used_at=_ts(pat.get("token_last_used_at")),
                expires_at=_ts(pat.get("token_expires_at")),
            )
        )
        caps = _caps_for_permission_map(
            pat.get("permissions", {}).get("repository", {})
        ) | _caps_for_permission_map(pat.get("permissions", {}).get("organization", {}))
        if not caps:
            continue
        selection = pat.get("repository_selection")
        if selection == "all":
            selector = f"{pat.get('org', '*')}/*"
        elif selection == "subset":
            selector = "__selected__"  # connector expands via the repositories URL
        elif selection == "none":
            continue  # org-only permissions; no repository reach to record
        else:
            raise ValueError(f"unknown PAT repository_selection {selection!r}")
        grants.append(
            GrantRecord(
                principal_external_id=owner_external,
                credential_external_id=credential_external,
                resource_selector=selector,
                scope_raw="pat:"
                + ",".join(
                    f"{scope}={level}"
                    for scope, level in sorted(
                        {
                            **pat.get("permissions", {}).get("repository", {}),
                            **pat.get("permissions", {}).get("organization", {}),
                        }.items()
                    )
                ),
                capabilities=caps,
                granted_at=_ts(pat.get("access_granted_at")),
            )
        )
    return list(principals.values()), credentials, grants


def extract_deploy_keys(
    repo_full_name: str, payload: list[dict[str, Any]]
) -> tuple[list[PrincipalRecord], list[CredentialRecord], list[GrantRecord]]:
    """Deploy keys are credentials without a human: each becomes a service
    principal named for the key, holding read or read/write on exactly one repo."""
    principals = []
    credentials = []
    grants = []
    for key in payload:
        if "id" not in key:
            raise ValueError("deploy key without id")
        external = f"deploy-key:{key['id']}"
        scope = "deploy_key:ro" if key.get("read_only", True) else "deploy_key:rw"
        principals.append(
            PrincipalRecord(
                external_id=external,
                kind=PrincipalKind.SERVICE,
                display_name=key.get("title") or f"deploy key {key['id']}",
                created_at=_ts(key.get("created_at")),
                last_active_at=_ts(key.get("last_used")),
            )
        )
        credentials.append(
            CredentialRecord(
                external_id=f"deploy-key:{key['id']}",
                kind=CredentialKind.SSH_KEY,
                principal_external_id=external,
                issued_at=_ts(key.get("created_at")),
                last_used_at=_ts(key.get("last_used")),
            )
        )
        grants.append(
            GrantRecord(
                principal_external_id=external,
                credential_external_id=f"deploy-key:{key['id']}",
                resource_selector=repo_full_name,
                scope_raw=scope,
                capabilities=capabilities_for("github", scope),
                granted_at=_ts(key.get("created_at")),
            )
        )
    return principals, credentials, grants


def extract_collaborators(
    repo_full_name: str, payload: list[dict[str, Any]]
) -> tuple[list[PrincipalRecord], list[GrantRecord]]:
    principals = []
    grants = []
    for user in payload:
        if "id" not in user:
            raise ValueError("collaborator without id")
        external = f"user:{user['id']}"
        principals.append(
            PrincipalRecord(
                external_id=external,
                kind=_user_kind(user),
                display_name=user.get("name") or user.get("login"),
                email=user.get("email") or None,
            )
        )
        role = user.get("role_name")
        if not role:
            raise ValueError(f"collaborator {user.get('login')!r} without role_name")
        grants.append(
            GrantRecord(
                principal_external_id=external,
                resource_selector=repo_full_name,
                scope_raw=f"permission:{role}",
                capabilities=capabilities_for("github", f"permission:{role}"),
            )
        )
    return principals, grants


def extract_audit_log(payload: list[dict[str, Any]]) -> list[EventRecord]:
    """Org audit log entries. `actor_id` may reference users no longer in the
    org — the pipeline turns those into deleted stubs."""
    events = []
    for entry in payload:
        if "action" not in entry or "@timestamp" not in entry:
            raise ValueError(f"audit entry missing action/timestamp: {json.dumps(entry)[:120]}")
        ts = _ts(entry["@timestamp"])
        assert ts is not None
        raw = json.dumps(entry, sort_keys=True)
        events.append(
            EventRecord(
                raw_ref=hashlib.sha256(raw.encode()).hexdigest(),
                action=f"github.{entry['action']}",
                ts=ts,
                provenance=Provenance.AUDIT_LOG,
                actor_external_id=f"user:{entry['actor_id']}" if entry.get("actor_id") else None,
                target_resource_external_id=f"repo:{entry['repo_id']}"
                if entry.get("repo_id")
                else None,
                ip=entry.get("actor_ip") or None,
                user_agent=entry.get("user_agent") or None,
            )
        )
    return events
