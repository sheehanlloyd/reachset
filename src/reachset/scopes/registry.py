"""Owns the declarative scope-to-capability tables.

One versioned table per app, no scattered if-statements. Unknown scope strings
raise UnknownScopeError — mapping something we don't understand to `read` would
mean silently understating reach, which is the exact failure mode this project
exists to avoid.
"""

from dataclasses import dataclass

from reachset.models import Capability


class UnknownScopeError(Exception):
    def __init__(self, app_id: str, scope: str) -> None:
        super().__init__(
            f"app {app_id!r} returned scope {scope!r} which version-pinned mapping "
            f"table does not cover; refusing to guess capabilities"
        )
        self.app_id = app_id
        self.scope = scope


@dataclass(frozen=True)
class ScopeTable:
    app_id: str
    version: str
    # scope string -> capability set. `prefixes` keys are bare prefixes
    # (e.g. "custom.") matched with str.startswith, no trailing "*" — neither
    # table below uses one yet, but the shape is here for an app whose scopes
    # are namespaced rather than an enumerable flat list.
    exact: dict[str, frozenset[Capability]]
    prefixes: dict[str, frozenset[Capability]]

    def capabilities_for(self, scope: str) -> frozenset[Capability]:
        if scope in self.exact:
            return self.exact[scope]
        for prefix, caps in self.prefixes.items():
            if scope.startswith(prefix):
                return caps
        raise UnknownScopeError(self.app_id, scope)


_R = frozenset({Capability.READ})
_RW = frozenset({Capability.READ, Capability.WRITE})
_RWD = frozenset({Capability.READ, Capability.WRITE, Capability.DELETE})
_ADMIN = frozenset({Capability.READ, Capability.WRITE, Capability.DELETE, Capability.ADMIN})
_SUDO = frozenset(
    {Capability.READ, Capability.WRITE, Capability.DELETE, Capability.ADMIN, Capability.IMPERSONATE}
)

# Vault policy capability strings, as they appear in ACL policy documents.
# https://developer.hashicorp.com/vault/docs/concepts/policies
VAULT_SCOPES = ScopeTable(
    app_id="vault",
    version="2026-08-1",
    exact={
        "read": _R,
        "list": _R,
        "create": _RW,
        "update": _RW,
        "patch": _RW,
        "delete": frozenset({Capability.DELETE}),
        "sudo": _SUDO,
        "deny": frozenset(),
        # root policy has no document; the connector emits this synthetic scope
        "policy:root": _SUDO,
    },
    prefixes={},
)

# GitHub classic PAT / app permission strings.
# https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
GITHUB_SCOPES = ScopeTable(
    app_id="github",
    version="2026-08-1",
    exact={
        "repo": _RWD,
        "repo:status": _R,
        "repo_deployment": _RW,
        "public_repo": _RW,
        "repo:invite": _R,
        "read:org": _R,
        "write:org": _RW,
        "admin:org": _ADMIN,
        "read:user": _R,
        "user:email": _R,
        "read:project": _R,
        "write:packages": _RW,
        "read:packages": _R,
        "delete_repo": frozenset({Capability.DELETE}),
        "workflow": _RW,
        "gist": _RW,
        "notifications": _R,
        # repository permission levels (collaborator / team / app installation)
        "permission:pull": _R,
        "permission:triage": _R,
        "permission:push": _RW,
        "permission:maintain": _RWD,
        "permission:admin": _ADMIN,
        # deploy keys
        "deploy_key:ro": _R,
        "deploy_key:rw": _RW,
        # app installation permission field values, prefixed by subject
        "contents:read": _R,
        "contents:write": _RW,
        "administration:read": _R,
        "administration:write": _ADMIN,
        "metadata:read": _R,
        "issues:read": _R,
        "issues:write": _RW,
        "pull_requests:read": _R,
        "pull_requests:write": _RW,
        "secrets:read": _R,
        "secrets:write": _RW,
        "actions:read": _R,
        "actions:write": _RW,
        "members:read": _R,
        "members:write": _ADMIN,
    },
    prefixes={},
)

_TABLES: dict[str, ScopeTable] = {t.app_id: t for t in (VAULT_SCOPES, GITHUB_SCOPES)}


def table_for(app_id: str) -> ScopeTable:
    if app_id not in _TABLES:
        raise KeyError(f"no scope table registered for app {app_id!r}")
    return _TABLES[app_id]


def capabilities_for(app_id: str, scope: str) -> frozenset[Capability]:
    return table_for(app_id).capabilities_for(scope)
