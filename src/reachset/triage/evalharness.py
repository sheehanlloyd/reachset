"""Owns the triage eval: 48 labeled synthetic incidents (8 per rule, half true
positives, half plausible false positives), scored against the rules-only
baseline. Numbers land in bench/triage_eval.json; the README repeats them
verbatim, wins and losses alike.
"""

import json
import random
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reachset.triage.pipeline import (
    IncidentContext,
    Verdict,
    rules_only_baseline,
    triage,
)
from reachset.triage.sanitize import UntrustedValue

RULES = (
    "dormant_privileged_nhi",
    "orphaned_grant",
    "scope_expansion",
    "cross_app_concentration",
    "shadow_ai_integration",
    "off_hours_bulk_read",
)


@dataclass(frozen=True)
class LabeledIncident:
    context: IncidentContext
    is_real: bool
    scenario: str


def _name(text: str) -> UntrustedValue:
    return UntrustedValue(text=text, provenance="app_profile", suspicious=False)


def build_incidents(seed: int = 20260818) -> list[LabeledIncident]:
    """Deterministic corpus. False positives are *plausible*: scheduled jobs,
    by-design accounts, migration windows, audited changes — the things that
    actually burn analyst time."""
    rng = random.Random(seed)
    incidents: list[LabeledIncident] = []

    def add(
        rule: str,
        index: int,
        *,
        real: bool,
        scenario: str,
        severity: str,
        periodicity: float = 0.0,
        by_design: bool = False,
        migration: bool = False,
        corroborated: int = 0,
        idle_days: int | None = None,
        apps: int = 1,
        sensitivity: int = 2,
        privileged: int = 1,
        kind: str = "service",
    ) -> None:
        incidents.append(
            LabeledIncident(
                context=IncidentContext(
                    incident_id=f"{rule}-{index}",
                    rule_id=rule,
                    severity=severity,
                    principal_kind=kind,
                    max_sensitivity=sensitivity,
                    privileged_edges=privileged,
                    apps_reached=apps,
                    idle_days=idle_days,
                    periodicity_score=periodicity,
                    corroborating_change_events=corroborated,
                    by_design_name_match=by_design,
                    in_migration_window=migration,
                    display_name=_name(f"{scenario}-{index}"),
                    resource_names=(
                        UntrustedValue(
                            text=f"resource-{rng.randrange(1000)}",
                            provenance="app_inventory",
                            suspicious=False,
                        ),
                    ),
                ),
                is_real=real,
                scenario=scenario,
            )
        )

    for rule in RULES:
        # 4 true positives with varying nastiness
        add(
            rule,
            0,
            real=True,
            scenario="stale-automation",
            severity="high",
            idle_days=200,
            sensitivity=3,
            privileged=4,
            apps=2,
            kind="agent",
        )
        add(
            rule,
            1,
            real=True,
            scenario="compromised-integration",
            severity="critical",
            idle_days=120,
            sensitivity=3,
            privileged=6,
            apps=3 if rule == "cross_app_concentration" else 2,
        )
        add(
            rule,
            2,
            real=True,
            scenario="forgotten-vendor-app",
            severity="high",
            idle_days=300,
            sensitivity=2,
            privileged=2,
            kind="app",
        )
        add(
            rule,
            3,
            real=True,
            scenario="quiet-priv-creep",
            severity="high",
            sensitivity=2,
            privileged=3,
            periodicity=0.3,
        )
        # 4 plausible false positives
        add(
            rule,
            4,
            real=False,
            scenario="nightly-batch",
            severity="high",
            periodicity=0.93,
            sensitivity=2,
            privileged=2,
        )
        add(
            rule,
            5,
            real=False,
            scenario="break-glass-account",
            severity="high",
            by_design=True,
            idle_days=250,
            sensitivity=3,
            privileged=5,
        )
        add(
            rule,
            6,
            real=False,
            scenario="declared-migration",
            severity="medium",
            migration=True,
            periodicity=0.5,
            sensitivity=2,
        )
        add(
            rule,
            7,
            real=False,
            scenario="ticketed-change",
            severity="medium",
            corroborated=2 if rule == "scope_expansion" else 0,
            periodicity=0.85,
            sensitivity=2,
        )

    return incidents


def evaluate(incidents: list[LabeledIncident]) -> dict[str, Any]:
    def score(verdicts: list[Verdict]) -> dict[str, Any]:
        by_id = {v.incident_id: v for v in verdicts}
        tp = fp = fn = tn = review = 0
        for incident in incidents:
            verdict = by_id[incident.context.incident_id]
            if verdict.decision == "needs_review":
                review += 1
                # a review outcome is neither an alert nor a dismissal; for
                # precision/recall it counts as an alert (it reaches a human)
                predicted_real = True
            else:
                predicted_real = verdict.decision == "true_positive"
            if predicted_real and incident.is_real:
                tp += 1
            elif predicted_real and not incident.is_real:
                fp += 1
            elif not predicted_real and incident.is_real:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        latencies = sorted(v.latency_seconds for v in verdicts)
        p95 = latencies[min(len(latencies) - 1, round(0.95 * (len(latencies) - 1)))]
        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "needs_review": review,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "mean_cost_units": round(statistics.mean(v.cost_units for v in verdicts), 2),
            "p95_latency_ms": round(p95 * 1000, 3),
        }

    pipeline_verdicts = [triage(incident.context) for incident in incidents]
    baseline_verdicts = [rules_only_baseline(incident.context) for incident in incidents]
    return {
        "incidents": len(incidents),
        "labels": {
            "real": sum(1 for i in incidents if i.is_real),
            "benign": sum(1 for i in incidents if not i.is_real),
        },
        "pipeline": score(pipeline_verdicts),
        "baseline_rules_only": score(baseline_verdicts),
        "cost_note": (
            "cost_units are simulated tool invocations (the roles are "
            "deterministic heuristics, not LLM calls); latency is measured wall "
            "time of the deterministic pipeline"
        ),
    }


def write_report(path: Path | None = None, seed: int = 20260818) -> dict[str, Any]:
    report = evaluate(build_incidents(seed))
    target = path or Path(__file__).parent.parent.parent.parent / "bench" / "triage_eval.json"
    target.write_text(json.dumps(report, indent=2) + "\n")
    return report
