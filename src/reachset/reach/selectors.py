"""Owns the selector language: globs with `*` (any run) and `?` (one char).

Two implementations that must agree exactly — the SQL LIKE translation used by
the CTE and the regex translation used by the BFS reference. The property test
in tests/integration/test_reach_property.py is the referee.

Impersonation selectors live in a namespace: `principal:<glob>` matches
principal external ids instead of resource paths.
"""

import re

PRINCIPAL_PREFIX = "principal:"

# SQL expression translating a glob column/param into a LIKE pattern.
# Escape order matters: backslash first, then LIKE's own wildcards, then ours.
# Single '%' on purpose: asyncpg binds with native $n parameters, so percent
# signs are plain characters here — doubling them would inject a second
# wildcard. The property test caught exactly that bug once already.
SQL_GLOB_TO_LIKE = (
    "replace(replace(replace(replace(replace({expr}, "
    "'\\', '\\\\'), '%', '\\%'), '_', '\\_'), '*', '%'), '?', '_')"
)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    # DOTALL: LIKE's % and _ cross newlines, so our wildcards must too.
    return re.compile("".join(parts), re.DOTALL)


def glob_match(pattern: str, value: str) -> bool:
    return glob_to_regex(pattern).fullmatch(value) is not None


def is_principal_selector(selector: str) -> bool:
    return selector.startswith(PRINCIPAL_PREFIX)


def principal_pattern(selector: str) -> str:
    if not is_principal_selector(selector):
        raise ValueError(f"not a principal selector: {selector!r}")
    return selector[len(PRINCIPAL_PREFIX) :]
