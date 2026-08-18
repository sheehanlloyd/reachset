"""Canonical record invariants: frozen, validated, closed to unknown fields."""

import pytest
from pydantic import ValidationError

from reachset.models import Capability, PrincipalKind, ResourceKind
from reachset.records import ExtractBatch, GrantRecord, PrincipalRecord, ResourceRecord


def test_records_are_frozen() -> None:
    p = PrincipalRecord(external_id="x", kind=PrincipalKind.SERVICE)
    with pytest.raises(ValidationError):
        p.external_id = "y"  # type: ignore[misc]  # asserting runtime immutability


def test_sensitivity_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        ResourceRecord(external_id="r", kind=ResourceKind.REPO, path="org/repo", sensitivity=4)


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        PrincipalRecord(external_id="x", kind=PrincipalKind.HUMAN, shoe_size=9)  # type: ignore[call-arg]


def test_batch_counts() -> None:
    batch = ExtractBatch(
        principals=[PrincipalRecord(external_id="x", kind=PrincipalKind.AGENT)],
        grants=[
            GrantRecord(
                principal_external_id="x",
                resource_selector="secret/*",
                scope_raw="policy:default",
                capabilities=frozenset({Capability.READ}),
            )
        ],
    )
    assert batch.counts() == {
        "principals": 1,
        "credentials": 0,
        "resources": 0,
        "grants": 1,
        "events": 0,
    }
