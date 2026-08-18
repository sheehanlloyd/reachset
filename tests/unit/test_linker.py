"""Identity linker: unit behavior plus the labeled-dataset precision gate.

Precision >= 0.98 is asserted; recall is reported (not asserted) into
bench/identity_linking.json, per the PRD.
"""

import json
import uuid
from pathlib import Path

from reachset.linking.linker import normalize_email, propose_links
from reachset.linking.synthetic import build_dataset
from reachset.models import LinkMethod, Principal, PrincipalKind

BENCH_DIR = Path(__file__).parent.parent.parent / "bench"


def _p(app: str, external: str, name: str | None = None, email: str | None = None) -> Principal:
    return Principal(
        id=uuid.uuid4(),
        tenant_id="t",
        app_id=app,
        external_id=external,
        kind=PrincipalKind.HUMAN,
        display_name=name,
        email=email,
    )


def test_normalize_email() -> None:
    assert normalize_email("Mira.Kraft@Acme.IO") == "mira.kraft@acme.io"
    assert normalize_email("j.ortega+gh@acme.io") == "j.ortega@acme.io"
    assert normalize_email("d.a.n.a.wu+x@gmail.com") == "danawu@gmail.com"
    assert normalize_email("d.a.n.a.wu@googlemail.com") == "danawu@googlemail.com"
    assert normalize_email("not-an-email") == "not-an-email"


def test_strongest_method_wins() -> None:
    a = _p("vault", "okta|123", "Mira Kraft", "mira@acme.io")
    b = _p("github", "okta|123", "Mira Kraft", "mira@acme.io")
    (proposal,) = propose_links([a, b])
    assert proposal.method is LinkMethod.EXTERNAL_ID_EXACT
    assert proposal.confidence == 1.0


def test_same_app_never_links() -> None:
    a = _p("github", "user:1", "Mira Kraft", "mira@acme.io")
    b = _p("github", "user:2", "Mira Kraft", "mira@acme.io")
    assert propose_links([a, b]) == []


def test_email_tag_and_case_variants_link() -> None:
    a = _p("vault", "e1", "Julián Ortega", "j.ortega@acme.io")
    b = _p("github", "user:502", "J. Ortega", "J.Ortega+gh@ACME.io")
    (proposal,) = propose_links([a, b])
    assert proposal.method is LinkMethod.EMAIL_EXACT


def test_sso_subject_links_without_email() -> None:
    a = _p("vault", "e1", "Dana Wu")
    b = _p("github", "user:503", "Dana Wu")
    (proposal,) = propose_links([a, b], sso_subjects={a.id: "saml|dana.wu", b.id: "saml|dana.wu"})
    assert proposal.method is LinkMethod.SSO_SUBJECT
    assert proposal.confidence == 0.95


def test_conflicting_email_blocks_fuzzy() -> None:
    a = _p("vault", "e1", "Dana Wu", "dana.a@acme.io")
    b = _p("github", "user:9", "Dana Wu", "dana.b@acme.io")
    assert propose_links([a, b]) == []


def test_fuzzy_link_is_review_only_confidence() -> None:
    a = _p("vault", "e1", "Dana Wu")
    b = _p("github", "user:9", "Wu, Dana")  # token-set handles reordering
    (proposal,) = propose_links([a, b])
    assert proposal.method is LinkMethod.FUZZY_NAME
    assert proposal.confidence == 0.6
    assert "review only" in proposal.evidence["note"]


def test_precision_on_labeled_dataset_and_report_recall() -> None:
    dataset = build_dataset("t-synth", people=200, seed=20260818)
    proposals = propose_links(dataset.principals, dataset.sso_subjects)

    predicted = {(p.principal_a, p.principal_b) for p in proposals}
    true_positives = predicted & dataset.truth
    precision = len(true_positives) / len(predicted)
    recall = len(true_positives) / len(dataset.truth)

    by_method: dict[str, dict[str, int]] = {}
    for p in proposals:
        stats = by_method.setdefault(p.method.value, {"predicted": 0, "correct": 0})
        stats["predicted"] += 1
        if (p.principal_a, p.principal_b) in dataset.truth:
            stats["correct"] += 1

    BENCH_DIR.mkdir(exist_ok=True)
    (BENCH_DIR / "identity_linking.json").write_text(
        json.dumps(
            {
                "dataset": {"people": 200, "seed": 20260818, "principals": len(dataset.principals)},
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "by_method": by_method,
                "note": "precision is asserted >= 0.98 in tests/unit/test_linker.py; "
                "recall is reported, not asserted",
            },
            indent=2,
        )
        + "\n"
    )

    assert precision >= 0.98, f"precision {precision:.4f} below the 0.98 gate"
