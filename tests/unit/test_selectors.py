"""The selector language: glob matching and the principal namespace.

The SQL translation of these rules lives in reach/engine.py and is held to
agree with them by the CTE-vs-BFS property test; this file pins the Python
side on its own.
"""

import pytest

from reachset.reach.selectors import (
    glob_match,
    glob_to_regex,
    has_wildcard,
    is_principal_selector,
    principal_pattern,
    sql_glob_to_ere,
)


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("*", "anything/at/all", True),
        ("a/*", "a/b/c", True),
        ("a/*", "b/c", False),
        ("a/?", "a/b", True),
        ("a/?", "a/bc", False),
        ("a/b", "a/b", True),
        ("a/b", "a/bb", False),
        # LIKE metacharacters are literals in our language, not wildcards.
        ("a%b", "a/b", False),
        ("a%b", "a%b", True),
        ("a_b", "axb", False),
        ("a_b", "a_b", True),
        # and the match is anchored at both ends
        ("a", "aa", False),
        ("π/*", "π/prod", True),
        # `+` matches exactly one non-empty path segment — Vault semantics.
        ("secret/data/ci/scratch/+/state", "secret/data/ci/scratch/build-42/state", True),
        # unlike `*`, `+` never crosses a `/` — a multi-segment value doesn't match.
        ("secret/data/ci/scratch/+/state", "secret/data/ci/scratch/build-42/x/state", False),
        # and `+` is never empty, unlike `*`.
        ("secret/data/ci/scratch/+/state", "secret/data/ci/scratch//state", False),
        ("a/+", "a/b", True),
        ("a/+", "a/", False),
        # regex metacharacters that aren't part of our language are literals too.
        ("a[b", "a[b", True),
        ("a(b)|c", "a(b)|c", True),
    ],
)
def test_glob_match(pattern: str, value: str, expected: bool) -> None:
    assert glob_match(pattern, value) is expected


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("secret/data/prod/db", False),
        ("secret/data/prod/*", True),
        ("secret/data/ci/scratch/+/state", True),
        ("a/?/b", True),
    ],
)
def test_has_wildcard(pattern: str, expected: bool) -> None:
    assert has_wildcard(pattern) is expected


def test_wildcards_cross_newlines_like_sql_like_does() -> None:
    """SQL's % spans newlines; the regex must use DOTALL to agree, or the CTE
    and the BFS would disagree on paths containing one."""
    assert glob_match("a/*", "a/b\nc") is True
    assert glob_to_regex("*").flags & __import__("re").DOTALL


def test_principal_namespace() -> None:
    assert is_principal_selector("principal:svc-1") is True
    assert is_principal_selector("secret/data/*") is False
    assert principal_pattern("principal:svc-*") == "svc-*"


def test_sql_glob_to_ere_is_anchored_and_escapes_regex_metacharacters() -> None:
    """Structural check on the SQL side of the translation — the actual
    equivalence with glob_match is what the CTE-vs-BFS property test proves
    against a live Postgres, this just pins the shape so a refactor here
    can't silently drop the anchors or an escape step."""
    expr = sql_glob_to_ere("col")
    assert expr.startswith("('^' || ")
    assert expr.endswith(" || '$')")
    # every replace() call nests the previous one — one call per escape/
    # substitution rule, so the count is a cheap proxy for "didn't lose a step"
    assert expr.count("replace(") == 14


def test_principal_pattern_rejects_a_resource_selector() -> None:
    with pytest.raises(ValueError, match="not a principal selector"):
        principal_pattern("secret/data/*")
