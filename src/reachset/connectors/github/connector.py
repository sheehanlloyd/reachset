"""Owns GitHub sync orchestration over an injected transport.

Pagination uses explicit page/cursor params so FixtureTransport (and chaos) can
replay it. The audit-log stream is the cursor-paginated one and plugs into the
generic StreamSyncer; the inventory endpoints are walked in one pass here.
"""

from dataclasses import dataclass
from typing import Any

from reachset.connectors.base import StreamSpec, TransportBase
from reachset.connectors.github import extractor
from reachset.ingest.engine import PageResult
from reachset.records import (
    CredentialRecord,
    ExtractBatch,
    GrantRecord,
    PrincipalRecord,
    ResourceRecord,
)

APP_ID = "github"


def audit_stream_spec(org: str) -> StreamSpec:
    """The org audit log is the incremental, cursor-paginated stream; it runs
    through the generic StreamSyncer rather than the one-shot sync below.

    Fixture envelope note: live GitHub returns a bare JSON array with the cursor
    in the Link header. Fixtures wrap it as {"entries": [...], "after": ...};
    the HttpTransport adapter that unwraps Link headers is future work tracked
    in NOTES.md.
    """
    return StreamSpec(
        name="audit_log",
        method="GET",
        path=f"/orgs/{org}/audit-log",
        cursor_param="after",
        static_params={"per_page": "100"},
    )


def audit_page(payload: dict[str, Any]) -> PageResult:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("audit page missing entries")
    return PageResult(
        batch=ExtractBatch(events=extractor.extract_audit_log(entries)),
        next_cursor=payload.get("after"),
    )


@dataclass
class GitHubConnector:
    transport: TransportBase
    org: str

    async def _paged_list(self, path: str) -> list[dict[str, Any]]:
        """Walk classic page-numbered pagination until a short page."""
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self.transport.get(path, {"per_page": "100", "page": str(page)})
            chunk = resp.json()
            if not isinstance(chunk, list):
                raise ValueError(f"expected list page from {path}")
            items.extend(chunk)
            if len(chunk) < 100:
                return items
            page += 1

    async def sync(self) -> ExtractBatch:
        principals: dict[str, PrincipalRecord] = {}
        credentials: list[CredentialRecord] = []
        resources: list[ResourceRecord] = []
        grants: list[GrantRecord] = []

        def add_principals(records: list[PrincipalRecord]) -> None:
            for record in records:
                # First write wins; member records carry richer profile data and
                # are ingested before collaborator/PAT stubs.
                principals.setdefault(record.external_id, record)

        # The members list is login/id only; profile detail (name, public email)
        # comes from /users/{login}, which is what identity linking feeds on.
        member_stubs = await self._paged_list(f"/orgs/{self.org}/members")
        member_details = []
        for stub in member_stubs:
            member_details.append((await self.transport.get(f"/users/{stub['login']}")).json())
        add_principals(extractor.extract_members(member_details))

        repos_payload = await self._paged_list(f"/orgs/{self.org}/repos")
        resources.extend(extractor.extract_repos(repos_payload))

        inst_payload = (await self.transport.get(f"/orgs/{self.org}/installations")).json()
        inst_payload["org"] = self.org
        inst_principals, inst_grants = extractor.extract_installations(inst_payload)
        add_principals(inst_principals)
        for grant in inst_grants:
            if grant.resource_selector == "__selected__":
                installation_id = grant.principal_external_id.removeprefix("installation:")
                repo_list = (
                    await self.transport.get(f"/app/installations/{installation_id}/repositories")
                ).json()
                grants.extend(extractor.expand_selected_grant(grant, repo_list["repositories"]))
            else:
                grants.append(grant)

        pat_payload = await self._paged_list(f"/orgs/{self.org}/personal-access-tokens")
        for pat in pat_payload:
            pat.setdefault("org", self.org)
        pat_principals, pat_credentials, pat_grants = extractor.extract_pat_grants(pat_payload)
        add_principals(pat_principals)
        credentials.extend(pat_credentials)
        for grant in pat_grants:
            if grant.resource_selector == "__selected__":
                pat_id = (grant.credential_external_id or "").removeprefix("pat:")
                selected = await self._paged_list(
                    f"/orgs/{self.org}/personal-access-tokens/{pat_id}/repositories"
                )
                grants.extend(extractor.expand_selected_grant(grant, selected))
            else:
                grants.append(grant)

        for repo in repos_payload:
            full_name = repo["full_name"]
            key_principals, key_credentials, key_grants = extractor.extract_deploy_keys(
                full_name, await self._paged_list(f"/repos/{full_name}/keys")
            )
            add_principals(key_principals)
            credentials.extend(key_credentials)
            grants.extend(key_grants)

            collab_principals, collab_grants = extractor.extract_collaborators(
                full_name,
                await self._paged_list(f"/repos/{full_name}/collaborators"),
            )
            add_principals(collab_principals)
            grants.extend(collab_grants)

        return ExtractBatch(
            principals=list(principals.values()),
            credentials=credentials,
            resources=resources,
            grants=grants,
        )
