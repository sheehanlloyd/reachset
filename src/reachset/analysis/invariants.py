"""Owns policy-as-code invariants: declarative rules evaluated against a
tenant's materialized reach, independent of any single detection rule.

A detection (detections/) answers "does this look like an incident" and
expects a human to triage the finding. An invariant answers a narrower,
sharper question an organization has already decided the answer to — "no
principal matching X may ever hold Y" — the kind of rule a security team
writes once and wants enforced in CI forever, not re-judged by a human every
run. Rules are read from a TOML config (see `reachset check-invariants`),
not hand-coded, so adding one is an edit to config, not a PR to this file —
the same principle behind the scope tables and the AI-vendor list.

Two rule kinds ship: `vendor_capability_sensitivity` ("no principal whose
name matches these globs may hold this capability on resources at or above
this sensitivity") and `max_apps_per_principal` ("no principal of these
kinds may hold reach into more than N distinct apps"). An unrecognized rule
kind, or a rule missing a required field, is a config error raised at load
time — a rule Reachset silently drops is worse than one that fails to load,
because the CI gate would look green for the wrong reason.
"""

import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import Capability, PrincipalKind
from reachset.reach.selectors import glob_match

# SARIF's own three levels, used directly as the severity vocabulary instead
# of inventing a second one to translate through.
_SARIF_LEVELS = frozenset({"error", "warning", "note"})


class InvariantConfigError(ValueError):
    """A rules file that doesn't parse into a known, complete rule shape."""


@dataclass(frozen=True)
class VendorCapabilitySensitivityRule:
    id: str
    description: str
    principal_patterns: tuple[str, ...]
    capability: str
    min_sensitivity: int
    severity: str = "error"


@dataclass(frozen=True)
class MaxAppsPerPrincipalRule:
    id: str
    description: str
    principal_kinds: tuple[str, ...]
    max_apps: int
    severity: str = "error"


Rule = VendorCapabilitySensitivityRule | MaxAppsPerPrincipalRule

_RULE_KINDS = ("vendor_capability_sensitivity", "max_apps_per_principal")


def _require(entry: dict[str, Any], field_name: str, path: Path, rule_id: str) -> Any:
    if field_name not in entry:
        raise InvariantConfigError(
            f"{path}: rule {rule_id!r} missing required field {field_name!r}"
        )
    return entry[field_name]


def _validated_severity(entry: dict[str, Any], path: Path, rule_id: str) -> str:
    severity = entry.get("severity", "error")
    if severity not in _SARIF_LEVELS:
        raise InvariantConfigError(
            f"{path}: rule {rule_id!r} has severity {severity!r}, expected one of "
            f"{sorted(_SARIF_LEVELS)}"
        )
    return str(severity)


def load_rules(path: Path) -> list[Rule]:
    """Parse a `[[rule]]` TOML array into typed rules. Every field is
    validated against the vocabulary the evaluators actually understand
    (real capabilities, real principal kinds, real SARIF levels) so a typo in
    config fails at load time, not silently as zero violations forever."""
    try:
        raw = path.read_text()
    except OSError as exc:
        raise InvariantConfigError(f"{path}: cannot read config: {exc}") from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise InvariantConfigError(f"{path}: invalid TOML: {exc}") from exc

    entries = data.get("rule")
    if not isinstance(entries, list) or not entries:
        raise InvariantConfigError(f"{path}: expected a non-empty [[rule]] array")

    rules: list[Rule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise InvariantConfigError(f"{path}: rule entries must be tables")
        rule_id = entry.get("id", "<unnamed>")
        kind = entry.get("kind")
        if kind not in _RULE_KINDS:
            raise InvariantConfigError(
                f"{path}: rule {rule_id!r} has unknown kind {kind!r}, expected one of {_RULE_KINDS}"
            )
        _require(entry, "id", path, rule_id)
        _require(entry, "description", path, rule_id)
        severity = _validated_severity(entry, path, rule_id)

        if kind == "vendor_capability_sensitivity":
            capability = _require(entry, "capability", path, rule_id)
            if capability not in {c.value for c in Capability}:
                raise InvariantConfigError(
                    f"{path}: rule {rule_id!r} has unknown capability {capability!r}"
                )
            rules.append(
                VendorCapabilitySensitivityRule(
                    id=entry["id"],
                    description=entry["description"],
                    principal_patterns=tuple(_require(entry, "principal_patterns", path, rule_id)),
                    capability=capability,
                    min_sensitivity=int(_require(entry, "min_sensitivity", path, rule_id)),
                    severity=severity,
                )
            )
        else:
            kinds = tuple(_require(entry, "principal_kinds", path, rule_id))
            unknown = set(kinds) - {k.value for k in PrincipalKind}
            if unknown:
                raise InvariantConfigError(
                    f"{path}: rule {rule_id!r} has unknown principal_kinds {sorted(unknown)}"
                )
            rules.append(
                MaxAppsPerPrincipalRule(
                    id=entry["id"],
                    description=entry["description"],
                    principal_kinds=kinds,
                    max_apps=int(_require(entry, "max_apps", path, rule_id)),
                    severity=severity,
                )
            )
    return rules


@dataclass(frozen=True)
class Violation:
    rule_id: str
    description: str
    severity: str
    principal_id: uuid.UUID
    external_id: str
    display_name: str | None
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "principal_id": str(self.principal_id),
            "external_id": self.external_id,
            "display_name": self.display_name,
            "detail": self.detail,
            "evidence": self.evidence,
        }


_VENDOR_SQL = """
SELECT p.id AS principal_id, p.external_id, p.display_name,
       jsonb_agg(DISTINCT jsonb_build_object(
           'resource', res.path, 'app', res.app_id, 'sensitivity', res.sensitivity
       )) AS resources
FROM reach_edges re
JOIN principals p ON p.id = re.principal_id
JOIN resources res ON res.id = re.resource_id
WHERE re.tenant_id = :tenant
  AND re.capability = :capability
  AND res.sensitivity >= :min_sensitivity
GROUP BY p.id, p.external_id, p.display_name
"""


async def _check_vendor_capability_sensitivity(
    session: AsyncSession, tenant_id: str, rule: VendorCapabilitySensitivityRule
) -> list[Violation]:
    rows = (
        await session.execute(
            text(_VENDOR_SQL),
            {
                "tenant": tenant_id,
                "capability": rule.capability,
                "min_sensitivity": rule.min_sensitivity,
            },
        )
    ).all()
    violations = []
    for row in rows:
        candidates = (row.display_name or "", row.external_id)
        matched = any(
            glob_match(pattern, candidate.lower())
            for pattern in rule.principal_patterns
            for candidate in candidates
        )
        if not matched:
            continue
        violations.append(
            Violation(
                rule_id=rule.id,
                description=rule.description,
                severity=rule.severity,
                principal_id=row.principal_id,
                external_id=row.external_id,
                display_name=row.display_name,
                detail=(
                    f"{row.display_name or row.external_id} holds {rule.capability!r} on "
                    f"{len(row.resources)} resource(s) at sensitivity >= {rule.min_sensitivity}"
                ),
                evidence={"resources": row.resources},
            )
        )
    return violations


_MAX_APPS_SQL = """
SELECT p.id AS principal_id, p.external_id, p.display_name, p.kind,
       array_agg(DISTINCT res.app_id ORDER BY res.app_id) AS apps
FROM reach_edges re
JOIN principals p ON p.id = re.principal_id
JOIN resources res ON res.id = re.resource_id
WHERE re.tenant_id = :tenant
  AND p.kind = ANY(:kinds)
GROUP BY p.id, p.external_id, p.display_name, p.kind
HAVING COUNT(DISTINCT res.app_id) > :max_apps
"""


async def _check_max_apps_per_principal(
    session: AsyncSession, tenant_id: str, rule: MaxAppsPerPrincipalRule
) -> list[Violation]:
    rows = (
        await session.execute(
            text(_MAX_APPS_SQL),
            {"tenant": tenant_id, "kinds": list(rule.principal_kinds), "max_apps": rule.max_apps},
        )
    ).all()
    return [
        Violation(
            rule_id=rule.id,
            description=rule.description,
            severity=rule.severity,
            principal_id=row.principal_id,
            external_id=row.external_id,
            display_name=row.display_name,
            detail=(
                f"{row.display_name or row.external_id} ({row.kind}) reaches "
                f"{len(row.apps)} apps ({', '.join(row.apps)}), over the limit of {rule.max_apps}"
            ),
            evidence={"apps": row.apps},
        )
        for row in rows
    ]


async def evaluate(session: AsyncSession, tenant_id: str, rules: list[Rule]) -> list[Violation]:
    """Evaluate every rule against the tenant's current materialized reach.
    Reads reach_edges as it stands — callers that want fresh results should
    materialize first, same as every other analysis in this package.
    """
    violations: list[Violation] = []
    for rule in rules:
        if isinstance(rule, VendorCapabilitySensitivityRule):
            violations.extend(await _check_vendor_capability_sensitivity(session, tenant_id, rule))
        else:
            violations.extend(await _check_max_apps_per_principal(session, tenant_id, rule))
    return violations


_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def to_sarif(violations: list[Violation], rules: list[Rule], config_path: str) -> dict[str, Any]:
    """SARIF 2.1.0, shaped for GitHub code scanning to ingest.

    Reachset violations have no source line to point at — the closest honest
    "location" is the invariants config that defines the violated rule, so
    every result's physicalLocation points there instead of somewhere made
    up. That is the same convention non-code SARIF producers (dependency and
    IaC scanners) use when they have no line to report.
    """
    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reachset",
                        "rules": [
                            {
                                "id": rule.id,
                                "shortDescription": {"text": rule.description},
                                "defaultConfiguration": {"level": rule.severity},
                            }
                            for rule in rules
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": v.rule_id,
                        "level": v.severity,
                        "message": {"text": f"{v.detail} (principal {v.external_id})"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": config_path},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "reachsetViolationId": f"{v.rule_id}:{v.principal_id}",
                        },
                    }
                    for v in violations
                ],
            }
        ],
    }
