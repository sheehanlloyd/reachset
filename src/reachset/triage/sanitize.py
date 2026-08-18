"""Owns the untrusted-content boundary.

Anything that originated inside a connected app — display names, repo
descriptions, Vault path names, user agents, audit log fields — is
attacker-controlled and must cross into agent context only as a tagged, quoted
value with explicit provenance. Nothing downstream is allowed to treat the text
inside as instructions, and the Adjudicator never sees it at all.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

# Phrases that mark a value as *suspicious*. Detection is best-effort and only
# ever adds a flag — the security property comes from quoting + provenance +
# the structured-fields-only Adjudicator, not from this list.
_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (all )?(previous|prior|above)",
        r"disregard (all )?(previous|prior|above)",
        r"you are now",
        r"new instructions",
        r"system\s*(message|prompt)?\s*:",
        r"assistant\s*:",
        r"</?\s*(system|instructions?|untrusted)\b",
        r"\[\s*/?\s*system\s*\]",
        r"suppress (alerting|alerts?|finding|report)",
        r"(security|admin|operator) (team )?override",
        r"\[/?INST\]",
        r"tool_call",
        r"function_call",
        r"set_verdict",
        r"invoke\s+\w+\(",
        r"call the \w+ tool",
        # word separators include + and _ to catch URL-encoded smuggling
        r"previous[\s+_-]+session[\s+_-]+(has[\s+_-]+)?authoriz",
        r"(was|is) (pre-?)?approved by (security|admin|the operator)",
        r"do not (flag|report|alert)",
        r"mark\s+(\w+\s+){0,3}(benign|safe|false.positive)",
        r"(prior|previous)[\s+_-]+session",
        r"already (reviewed|approved|authorized)",
        r"verdict\s*[:=]",
        r"confidence\s*[:=]\s*[0-9.]+",
    )
]

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]{24,}")


@dataclass(frozen=True)
class UntrustedValue:
    """A quoted, provenance-tagged string from a connected app."""

    text: str
    provenance: str
    suspicious: bool

    def render(self) -> str:
        """How the value appears in any prompt/narrative context: fenced, with
        the fence characters themselves neutralized inside."""
        body = self.text.replace("<", "\\u003c").replace(">", "\\u003e")
        return f'<untrusted provenance="{self.provenance}">{body}</untrusted>'

    def as_dict(self) -> dict[str, Any]:
        return {
            "untrusted": True,
            "provenance": self.provenance,
            "text": self.text,
            "suspicious": self.suspicious,
        }


def looks_injected(value: str) -> bool:
    if any(pattern.search(value) for pattern in _INJECTION_PATTERNS):
        return True
    # decoded base64 runs get one more pass; attackers love one layer of hiding
    for run in _BASE64_RUN.findall(value):
        try:
            decoded = base64.b64decode(run, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if any(pattern.search(decoded) for pattern in _INJECTION_PATTERNS):
            return True
    return False


def untrusted(value: str | None, provenance: str) -> dict[str, Any] | None:
    """Wrap an app-originated string for transport to agent context."""
    if value is None:
        return None
    return UntrustedValue(
        text=value, provenance=provenance, suspicious=looks_injected(value)
    ).as_dict()
