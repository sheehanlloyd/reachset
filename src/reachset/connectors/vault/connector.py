"""Owns Vault sync orchestration: which endpoints to walk, in what order, and how
their payloads feed the pure extractor. All I/O goes through the injected
transport, so the same code runs live, from fixtures, or under chaos."""

from collections.abc import Callable
from dataclasses import dataclass

from reachset.connectors.base import TransportBase, TransportHTTPError
from reachset.connectors.vault import extractor
from reachset.records import CredentialRecord, ExtractBatch, GrantRecord, PrincipalRecord

APP_ID = "vault"

# LIST in Vault's HTTP API is GET with ?list=true.
_LIST = {"list": "true"}


def make_transport_headers(token: str) -> dict[str, str]:
    return {"X-Vault-Token": token}


@dataclass
class VaultConnector:
    """One sync pass over a Vault server.

    `read_audit_lines` abstracts the file audit device: live mode reads the real
    file (or a mounted volume), tests read fixture lines. It is not HTTP, which
    is why it is not forced through the transport.
    """

    transport: TransportBase
    read_audit_lines: Callable[[], list[str]] | None = None
    kv_mount: str = "secret"

    async def sync(self) -> ExtractBatch:
        auth_payload = (await self.transport.get("/v1/sys/auth")).json()
        auth_resources = extractor.extract_auth_methods(auth_payload)

        policy_list = (await self.transport.request("GET", "/v1/sys/policies/acl", _LIST)).json()
        docs: dict[str, str] = {}
        for name in policy_list.get("data", {}).get("keys", []):
            if name == "root":
                continue
            doc_payload = (await self.transport.get(f"/v1/sys/policies/acl/{name}")).json()
            docs[name] = doc_payload.get("data", {}).get("policy", "")
        policy_rules = extractor.extract_policies(policy_list, docs)

        accessors_payload = (
            await self.transport.request("GET", "/v1/auth/token/accessors", _LIST)
        ).json()
        accessors = extractor.extract_accessor_list(accessors_payload)

        principals: dict[str, PrincipalRecord] = {}
        credentials: list[CredentialRecord] = []
        grants: list[GrantRecord] = []
        for accessor in accessors:
            lookup = (
                await self.transport.request(
                    "POST", "/v1/auth/token/lookup-accessor", json_body={"accessor": accessor}
                )
            ).json()
            principal, credential, token_grants = extractor.extract_token(
                accessor, lookup, policy_rules
            )
            principals.setdefault(principal.external_id, principal)
            credentials.append(credential)
            grants.extend(token_grants)

        secret_paths = await self._walk_kv_metadata("")
        secret_resources = extractor.extract_secret_paths(secret_paths)

        events = (
            extractor.extract_audit_events(self.read_audit_lines())
            if self.read_audit_lines is not None
            else []
        )

        return ExtractBatch(
            principals=list(principals.values()),
            credentials=credentials,
            resources=[*auth_resources, *secret_resources],
            grants=grants,
            events=events,
        )

    async def _walk_kv_metadata(self, prefix: str) -> list[str]:
        """Depth-first walk of the KV v2 metadata tree under the mount.

        Vault answers 404 for an empty tree, which simply means no secrets yet.
        """
        try:
            response = await self.transport.request(
                "GET", f"/v1/{self.kv_mount}/metadata/{prefix}".rstrip("/"), _LIST
            )
        except TransportHTTPError as exc:
            if exc.status == 404:
                return []
            raise
        listing = response.json()
        keys = listing.get("data", {}).get("keys", [])
        paths: list[str] = []
        for key in keys:
            if key.endswith("/"):
                paths.extend(await self._walk_kv_metadata(f"{prefix}{key}"))
            else:
                paths.append(f"{self.kv_mount}/data/{prefix}{key}")
        return paths
