"""Owns identity correlation between principals of different apps.

Method ladder, strongest first; a pair links once, by its strongest method:
1. external_id_exact (1.0) — same IdP subject in two apps.
2. email_exact (0.95) — normalized: lowercased, +tag stripped, dots stripped
   for gmail-hosted domains.
3. sso_subject (0.95) — SAML NameID equality, supplied per app by connectors.
4. fuzzy_name (0.6) — token-set ratio >= 90, same tenant, and no conflicting
   email. Fuzzy links are review flags: the reach engine refuses to traverse
   them when materializing.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from rapidfuzz import fuzz
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import IdentityLink, LinkMethod, Principal

_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
FUZZY_THRESHOLD = 90.0

METHOD_CONFIDENCE = {
    LinkMethod.EXTERNAL_ID_EXACT: 1.0,
    LinkMethod.EMAIL_EXACT: 0.95,
    LinkMethod.SSO_SUBJECT: 0.95,
    LinkMethod.FUZZY_NAME: 0.6,
}


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if "@" not in email:
        return email
    local, _, domain = email.rpartition("@")
    local = local.split("+", 1)[0]
    if domain in _GMAIL_DOMAINS:
        local = local.replace(".", "")
    return f"{local}@{domain}"


@dataclass(frozen=True)
class LinkProposal:
    principal_a: uuid.UUID
    principal_b: uuid.UUID
    method: LinkMethod
    confidence: float
    evidence: dict[str, Any]


def propose_links(
    principals: list[Principal],
    sso_subjects: Mapping[uuid.UUID, str] | None = None,
) -> list[LinkProposal]:
    """Pure pairing logic over already-loaded principals (single tenant).

    `sso_subjects` maps principal row id -> SAML NameID, supplied by whichever
    connector saw the SSO assertion mapping.
    """
    sso_subjects = sso_subjects or {}
    proposals: dict[tuple[uuid.UUID, uuid.UUID], LinkProposal] = {}

    def claim(a: Principal, b: Principal, method: LinkMethod, evidence: dict[str, Any]) -> None:
        if a.app_id == b.app_id:
            return
        key = (min(a.id, b.id), max(a.id, b.id))
        if key in proposals:  # strongest method ran earlier; keep it
            return
        proposals[key] = LinkProposal(
            principal_a=key[0],
            principal_b=key[1],
            method=method,
            confidence=METHOD_CONFIDENCE[method],
            evidence=evidence,
        )

    by_external: dict[str, list[Principal]] = {}
    for p in principals:
        by_external.setdefault(p.external_id, []).append(p)
    for external_id, group in by_external.items():
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                claim(a, b, LinkMethod.EXTERNAL_ID_EXACT, {"external_id": external_id})

    by_email: dict[str, list[Principal]] = {}
    for p in principals:
        if p.email:
            by_email.setdefault(normalize_email(p.email), []).append(p)
    for email, group in by_email.items():
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                claim(a, b, LinkMethod.EMAIL_EXACT, {"normalized_email": email})

    by_sso: dict[str, list[Principal]] = {}
    for p in principals:
        subject = sso_subjects.get(p.id)
        if subject:
            by_sso.setdefault(subject, []).append(p)
    for subject, group in by_sso.items():
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                claim(a, b, LinkMethod.SSO_SUBJECT, {"sso_subject": subject})

    named = [p for p in principals if p.display_name]
    for i, a in enumerate(named):
        for b in named[i + 1 :]:
            if a.app_id == b.app_id:
                continue
            assert a.display_name is not None and b.display_name is not None
            score = fuzz.token_set_ratio(a.display_name, b.display_name)
            if score < FUZZY_THRESHOLD:
                continue
            if a.email and b.email and normalize_email(a.email) != normalize_email(b.email):
                continue  # conflicting emails: same name, different people
            claim(
                a,
                b,
                LinkMethod.FUZZY_NAME,
                {
                    "names": [a.display_name, b.display_name],
                    "token_set_ratio": score,
                    "note": "review only; never expands reach",
                },
            )

    return sorted(proposals.values(), key=lambda p: (str(p.principal_a), str(p.principal_b)))


async def link_tenant(
    session: AsyncSession,
    tenant_id: str,
    sso_subjects: Mapping[uuid.UUID, str] | None = None,
) -> list[LinkProposal]:
    """Load, propose, persist. Existing (pair, method) rows are left untouched."""
    principals = list(
        (await session.execute(select(Principal).where(Principal.tenant_id == tenant_id))).scalars()
    )
    proposals = propose_links(principals, sso_subjects)
    for proposal in proposals:
        await session.execute(
            insert(IdentityLink)
            .values(
                tenant_id=tenant_id,
                principal_a=proposal.principal_a,
                principal_b=proposal.principal_b,
                method=proposal.method,
                confidence=proposal.confidence,
                evidence_json=proposal.evidence,
            )
            .on_conflict_do_nothing(constraint="uq_link_identity")
        )
    return proposals
