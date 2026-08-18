"""Owns the triage pipeline: Analyst -> Adversary -> Adjudicator.

The roles are deterministic heuristics behind role-shaped interfaces. There is
no LLM in the loop in v0 — no live model API exists under this repo's
constraints — but the shape is the point: an LLM Analyst/Adversary could be
swapped in without touching the safety property, because the Adjudicator only
ever consumes AdjudicatorInput, a struct of numbers and enums that contains no
attacker-controlled text at all. Injected strings can decorate the narrative;
they cannot reach the decision.
"""

import time
from dataclasses import dataclass, field
from typing import Literal

from reachset.triage.sanitize import UntrustedValue

Decision = Literal["true_positive", "false_positive", "needs_review"]

# Declarative by-design patterns: service accounts that are *supposed* to hold
# broad, rarely-used power. Same registry philosophy as the scope tables.
BY_DESIGN_PATTERNS: tuple[str, ...] = (
    "break-glass",
    "backup",
    "disaster-recovery",
    "terraform",
    "provisioner",
)


@dataclass(frozen=True)
class IncidentContext:
    """Structured, graph-derived features of one finding. Everything here is
    computed by Reachset from ingested rows — never copied from app text."""

    incident_id: str
    rule_id: str
    severity: str
    principal_kind: str
    max_sensitivity: int
    privileged_edges: int
    apps_reached: int
    idle_days: int | None
    # 0..1; 1.0 = the principal's activity is strongly periodic (cron-shaped)
    periodicity_score: float
    corroborating_change_events: int
    by_design_name_match: bool
    in_migration_window: bool
    # Quoted app-originated strings; narrative color only.
    display_name: UntrustedValue | None = None
    resource_names: tuple[UntrustedValue, ...] = ()


@dataclass(frozen=True)
class Draft:
    incident_id: str
    hypothesis: str
    risk_score: float
    evidence_refs: tuple[str, ...]
    tool_calls: int


@dataclass(frozen=True)
class CounterEvidence:
    kind: str
    strength: float
    detail: str


@dataclass(frozen=True)
class AdversaryReport:
    incident_id: str
    counters: tuple[CounterEvidence, ...]
    tool_calls: int


@dataclass(frozen=True)
class AdjudicatorInput:
    """Everything the Adjudicator is allowed to see. By construction there is
    not a single free-text field of app origin in here; the red-team suite
    asserts this structurally."""

    rule_id: str
    severity: str
    principal_kind: str
    max_sensitivity: int
    risk_score: float
    counter_strengths: tuple[float, ...]
    counter_kinds: tuple[str, ...]
    suspicious_input_flags: int


@dataclass(frozen=True)
class Verdict:
    incident_id: str
    decision: Decision
    confidence: float
    rationale: str
    cited_evidence: tuple[str, ...]
    cost_units: int
    latency_seconds: float = field(compare=False, default=0.0)


_SEVERITY_WEIGHT = {"low": 0.2, "medium": 0.45, "high": 0.7, "critical": 0.9}


def analyst(context: IncidentContext) -> Draft:
    """Gathers context (simulated as feature reads) and drafts the case for the
    finding being real. The narrative embeds untrusted strings only in their
    quoted, fenced form."""
    score = _SEVERITY_WEIGHT.get(context.severity, 0.4)
    score += 0.1 * min(context.max_sensitivity, 3) / 3
    if context.privileged_edges > 0:
        score += 0.1
    if context.apps_reached >= 3:
        score += 0.1
    if context.idle_days is not None and context.idle_days > 90:
        score += 0.05
    score = min(score, 1.0)

    name = context.display_name.render() if context.display_name else "(unnamed principal)"
    hypothesis = (
        f"[{context.rule_id}] {name} — {context.principal_kind} with "
        f"{context.privileged_edges} privileged edge(s), max sensitivity "
        f"{context.max_sensitivity}, spanning {context.apps_reached} app(s)."
    )
    refs = tuple(
        f"edge:{value.provenance}:{index}" for index, value in enumerate(context.resource_names)
    ) or (f"finding:{context.rule_id}",)
    return Draft(
        incident_id=context.incident_id,
        hypothesis=hypothesis,
        risk_score=round(score, 3),
        evidence_refs=refs,
        tool_calls=3,  # assess_principal + activity + evidence pulls
    )


def adversary(context: IncidentContext) -> AdversaryReport:
    """Tries to kill the finding: scheduled jobs, by-design accounts, migration
    windows, and audit-corroborated changes are all benign explanations."""
    counters: list[CounterEvidence] = []
    tool_calls = 1  # activity-history pull
    if context.periodicity_score >= 0.8:
        counters.append(
            CounterEvidence(
                kind="scheduled_job",
                strength=context.periodicity_score,
                detail=(
                    f"activity autocorrelation {context.periodicity_score:.2f}: "
                    "cron-shaped, not interactive"
                ),
            )
        )
    if context.by_design_name_match:
        tool_calls += 1
        counters.append(
            CounterEvidence(
                kind="by_design_account",
                strength=0.9,
                detail="matches the declarative by-design service-account registry",
            )
        )
    if context.in_migration_window:
        tool_calls += 1
        counters.append(
            CounterEvidence(
                kind="migration_window",
                strength=0.7,
                detail="tenant has an open, operator-declared migration window",
            )
        )
    if context.corroborating_change_events > 0 and context.rule_id == "scope_expansion":
        tool_calls += 1
        counters.append(
            CounterEvidence(
                kind="audited_change",
                strength=0.85,
                detail=(
                    f"{context.corroborating_change_events} matching change event(s) "
                    "in the app audit stream"
                ),
            )
        )
    return AdversaryReport(
        incident_id=context.incident_id, counters=tuple(counters), tool_calls=tool_calls
    )


def _combined_counter_strength(strengths: tuple[float, ...]) -> float:
    remaining = 1.0
    for strength in strengths:
        remaining *= 1.0 - strength
    return 1.0 - remaining


def adjudicate(inputs: AdjudicatorInput) -> tuple[Decision, float, str]:
    """Decides from structured fields only. Suspicious-input flags make the
    verdict *more* conservative (never auto-benign): a poisoned record can
    escalate to review, but it cannot talk its way into false_positive."""
    counter = _combined_counter_strength(inputs.counter_strengths)
    if counter >= 0.75 and inputs.suspicious_input_flags == 0:
        return (
            "false_positive",
            round(counter, 3),
            f"benign explanation dominates ({', '.join(inputs.counter_kinds)}; "
            f"combined strength {counter:.2f})",
        )
    if inputs.risk_score >= 0.65 and counter < 0.4:
        return (
            "true_positive",
            round(inputs.risk_score * (1 - counter), 3),
            f"risk {inputs.risk_score:.2f} with weak counter-evidence ({counter:.2f})",
        )
    if counter >= 0.75:
        return (
            "needs_review",
            0.5,
            "benign explanation exists but inputs carried suspected injection; "
            "refusing to auto-close",
        )
    return (
        "needs_review",
        round(max(0.3, 1 - abs(inputs.risk_score - counter)), 3),
        f"risk {inputs.risk_score:.2f} vs counter {counter:.2f}: ambiguous",
    )


def triage(context: IncidentContext) -> Verdict:
    started = time.perf_counter()
    draft = analyst(context)
    report = adversary(context)

    suspicious_flags = sum(
        1
        for value in (context.display_name, *context.resource_names)
        if value is not None and value.suspicious
    )
    inputs = AdjudicatorInput(
        rule_id=context.rule_id,
        severity=context.severity,
        principal_kind=context.principal_kind,
        max_sensitivity=context.max_sensitivity,
        risk_score=draft.risk_score,
        counter_strengths=tuple(c.strength for c in report.counters),
        counter_kinds=tuple(c.kind for c in report.counters),
        suspicious_input_flags=suspicious_flags,
    )
    decision, confidence, rationale = adjudicate(inputs)
    return Verdict(
        incident_id=context.incident_id,
        decision=decision,
        confidence=confidence,
        rationale=rationale,
        cited_evidence=draft.evidence_refs + tuple(f"counter:{c.kind}" for c in report.counters),
        cost_units=draft.tool_calls + report.tool_calls + 1,  # +1 adjudication
        latency_seconds=time.perf_counter() - started,
    )


def rules_only_baseline(context: IncidentContext) -> Verdict:
    """What shipping detections without triage means: every finding is treated
    as real. This is the baseline the pipeline has to beat."""
    return Verdict(
        incident_id=context.incident_id,
        decision="true_positive",
        confidence=_SEVERITY_WEIGHT.get(context.severity, 0.4),
        rationale="rules-only: findings are alerts",
        cited_evidence=(f"finding:{context.rule_id}",),
        cost_units=0,
    )
