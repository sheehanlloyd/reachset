"""Owns the labeled synthetic dataset for identity-linking evaluation.

Ground truth is known by construction: each generated person owns one account
per app, wired together through one of the real-world signal patterns below.
Distractors are the cases that actually break naive linkers — name collisions,
shared display names without emails, service accounts named after humans.
"""

import random
import uuid
from dataclasses import dataclass, field

from reachset.models import Principal, PrincipalKind

FIRST = [
    "Mira",
    "Julián",
    "Dana",
    "Anil",
    "Sofia",
    "Tomasz",
    "Yuki",
    "Amara",
    "Neil",
    "Priya",
    "Lars",
    "Fatima",
    "Diego",
    "Ingrid",
    "Kofi",
    "Elena",
    "Marcus",
    "Wei",
    "Aoife",
    "Sami",
]
LAST = [
    "Kraft",
    "Ortega",
    "Wu",
    "Kapoor",
    "Rossi",
    "Nowak",
    "Tanaka",
    "Okafor",
    "Byrne",
    "Iyer",
    "Berg",
    "Haddad",
    "Silva",
    "Larsen",
    "Mensah",
    "Petrova",
    "Hale",
    "Chen",
    "Kelly",
    "Aalto",
]


@dataclass
class SyntheticDataset:
    principals: list[Principal]
    # ground-truth same-person pairs, canonically ordered by row id
    truth: set[tuple[uuid.UUID, uuid.UUID]]
    sso_subjects: dict[uuid.UUID, str] = field(default_factory=dict)


def _person_name(rng: random.Random, used: set[str]) -> str:
    while True:
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        if name not in used:
            used.add(name)
            return name


def build_dataset(tenant_id: str, *, people: int = 200, seed: int = 20260818) -> SyntheticDataset:
    """`people` cross-app persons plus distractors. Signal mix:
    ~55% email pairs (with tag/dot noise), ~15% sso, ~10% shared IdP subject,
    ~12% fuzzy-only (no email on one side), ~8% unlinkable (no shared signal).
    """
    rng = random.Random(seed)
    used_names: set[str] = set()
    principals: list[Principal] = []
    truth: set[tuple[uuid.UUID, uuid.UUID]] = set()
    sso_subjects: dict[uuid.UUID, str] = {}

    def mk(app: str, external: str, name: str | None, email: str | None) -> Principal:
        p = Principal(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            app_id=app,
            external_id=external,
            kind=PrincipalKind.HUMAN,
            display_name=name,
            email=email,
        )
        principals.append(p)
        return p

    for i in range(people):
        name = _person_name(rng, used_names)
        local = name.lower().replace(" ", ".").replace("á", "a").replace("é", "e")
        email = f"{local}@acme.io"
        bucket = rng.random()

        if bucket < 0.55:
            # email pair, with realistic noise on one side
            noisy = email
            noise = rng.random()
            if noise < 0.3:
                noisy = email.replace("@", "+gh@")
            elif noise < 0.4:
                noisy = email.upper()
            a = mk("vault", f"entity-{i:04d}", name, email)
            b = mk("github", f"user:{1000 + i}", name, noisy)
        elif bucket < 0.70:
            # sso pair; emails hidden on the github side
            a = mk("vault", f"entity-{i:04d}", name, email)
            b = mk("github", f"user:{1000 + i}", name, None)
            subject = f"saml|{local}"
            sso_subjects[a.id] = subject
            sso_subjects[b.id] = subject
        elif bucket < 0.80:
            # same IdP subject as external id in both apps
            subject = f"okta|{i:06d}"
            a = mk("vault", subject, name, None)
            b = mk("github", subject, name, None)
        elif bucket < 0.92:
            # fuzzy-only: same human name, email on at most one side
            a = mk("vault", f"entity-{i:04d}", name, email if rng.random() < 0.5 else None)
            b = mk("github", f"user:{1000 + i}", name, None)
        else:
            # unlinkable: different display forms, no shared signal
            a = mk("vault", f"entity-{i:04d}", name, None)
            b = mk("github", f"user:{1000 + i}", name.split()[0].lower() + "-dev", None)
        truth.add((min(a.id, b.id), max(a.id, b.id)))

    # Distractors — all of these are DIFFERENT people:
    # 1. name collision with different emails in each app (email guard case)
    for i in range(6):
        name = _person_name(rng, used_names)
        mk("vault", f"entity-dup-{i}", name, f"{name.split()[0].lower()}.a@acme.io")
        mk("github", f"user:dup-{i}", name, f"{name.split()[0].lower()}.b@acme.io")
    # 2. name collision with no emails at all: the honest failure mode of
    #    fuzzy_name, kept in the dataset so precision reflects reality
    for i in range(2):
        name = _person_name(rng, used_names)
        mk("vault", f"entity-trap-{i}", name, None)
        mk("github", f"user:trap-{i}", name, None)
    # 3. a service account named after its creator (kind guard is not applied by
    #    the linker; the conflicting-email rule has to do the work)
    creator = _person_name(rng, used_names)
    mk("vault", "entity-svc-owner", creator, f"{creator.split()[0].lower()}@acme.io")
    mk("github", "user:svc-1", f"{creator} (svc)", "platform-bots@acme.io")

    return SyntheticDataset(principals=principals, truth=truth, sso_subjects=sso_subjects)
