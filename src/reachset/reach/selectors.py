"""Owns the selector language: globs with `*` (any run, crosses `/`), `?` (one
char, crosses `/`), and `+` (one non-empty path segment — mirrors Vault's `+`
exactly, so a Vault policy's own selector text can be stored and matched
verbatim instead of being widened into something that overstates reach).

Two implementations that must agree exactly — the SQL translation used by the
CTE and the regex translation used by the BFS reference. The property test in
tests/integration/test_reach_property.py is the referee.

Impersonation selectors live in a namespace: `principal:<glob>` matches
principal external ids instead of resource paths. `+` is defined there too
(one non-empty run without a `/`), which degrades gracefully for slash-free
external ids: it behaves like "exactly one non-empty token".
"""

import re

PRINCIPAL_PREFIX = "principal:"

# SQL expression translating a glob column/param into an anchored POSIX ERE
# for Postgres's `~` operator, used by reach/engine.py for any selector that
# actually contains wildcard syntax (see has_wildcard below — selectors
# without it join by plain equality instead, no pattern match involved).
# LIKE could express `*` and `?` but not `+`, which needs a negated character
# class ("one or more chars that are not '/'") — a regex feature, not a LIKE
# feature — so this project matches every glob selector as a regex rather
# than juggling two translations for two subsets of the language.
#
# Order matters: escape every ERE metacharacter that is *not* part of our own
# glob syntax first (innermost calls), then substitute our three wildcards
# last, so a substitution can never be re-escaped by a later step. Our
# language has no literal form for `*`, `?`, or `+` — they are always
# wildcards — so once escaping is done, every remaining occurrence of those
# three characters is unambiguously ours.
_ERE_LITERAL_ESCAPES: list[tuple[str, str]] = [
    ("\\", "\\\\"),
    (".", "\\."),
    ("^", "\\^"),
    ("$", "\\$"),
    ("(", "\\("),
    (")", "\\)"),
    ("[", "\\["),
    ("]", "\\]"),
    ("{", "\\{"),
    ("}", "\\}"),
    ("|", "\\|"),
]
_ERE_WILDCARD_SUBS: list[tuple[str, str]] = [
    ("*", ".*"),
    ("?", "."),
    ("+", "[^/]+"),
]


def _sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def sql_glob_to_ere(expr: str) -> str:
    """Anchored POSIX-ERE SQL expression for matching `expr` with `~`."""
    result = expr
    for old, new in (*_ERE_LITERAL_ESCAPES, *_ERE_WILDCARD_SUBS):
        result = f"replace({result}, {_sql_str(old)}, {_sql_str(new)})"
    return f"('^' || {result} || '$')"


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        elif ch == "+":
            parts.append("[^/]+")
        else:
            parts.append(re.escape(ch))
    # DOTALL: LIKE's % and _ cross newlines, so our wildcards must too. It has
    # no effect on the `+` class above, which excludes '/' explicitly rather
    # than relying on '.' semantics.
    return re.compile("".join(parts), re.DOTALL)


def has_wildcard(pattern: str) -> bool:
    """True if `pattern` uses any glob syntax at all. Selectors with none of
    these are exact strings, which lets the reach engine join them by
    equality instead of a pattern match — see reach/engine.py."""
    return any(ch in pattern for ch in "*?+")


def glob_match(pattern: str, value: str) -> bool:
    return glob_to_regex(pattern).fullmatch(value) is not None


def is_principal_selector(selector: str) -> bool:
    return selector.startswith(PRINCIPAL_PREFIX)


def principal_pattern(selector: str) -> str:
    if not is_principal_selector(selector):
        raise ValueError(f"not a principal selector: {selector!r}")
    return selector[len(PRINCIPAL_PREFIX) :]
