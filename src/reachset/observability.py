"""Owns in-process metrics and their Prometheus text exposition.

This is a small, deliberately limited registry: counters, gauges, and
histograms with string labels, rendered in the Prometheus text format v0.0.4.
It exists because Reachset needs eight metrics, not a metrics framework — and
because the exposition format is simple enough that a dependency costs more
than it saves at this size. If you outgrow it (exemplars, native histograms,
multiprocess collection), swap in `prometheus_client`; the call sites here are
the same shape.

Thread-safe: every mutation holds a lock, because the API and the worker both
record from multiple tasks.
"""

import math
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field

# Buckets tuned for this workload: sub-millisecond DB round-trips through
# multi-second full-tenant recomputes.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
)

_LabelKey = tuple[tuple[str, str], ...]


def _key(labels: Mapping[str, str] | None) -> _LabelKey:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_labels(key: _LabelKey, extra: tuple[tuple[str, str], ...] = ()) -> str:
    pairs = tuple(key) + extra
    if not pairs:
        return ""
    body = ",".join(f'{name}="{_escape(value)}"' for name, value in pairs)
    return "{" + body + "}"


def _format_float(value: float) -> str:
    """Prometheus wants +Inf, not inf, and no scientific notation surprises."""
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


@dataclass
class _Metric:
    name: str
    help_text: str
    kind: str
    label_names: tuple[str, ...] = ()

    def _check(self, labels: Mapping[str, str] | None) -> None:
        given = tuple(sorted(labels or {}))
        expected = tuple(sorted(self.label_names))
        if given != expected:
            raise ValueError(f"metric {self.name!r} expects labels {expected}, got {given}")


@dataclass
class Counter(_Metric):
    """Monotonically increasing count."""

    values: dict[_LabelKey, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        if amount < 0:
            raise ValueError("counters cannot decrease")
        self._check(labels)
        with self._lock:
            self.values[_key(labels)] = self.values.get(_key(labels), 0.0) + amount

    def value(self, **labels: str) -> float:
        return self.values.get(_key(labels), 0.0)

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        if not self.values:
            # A counter with no observations still reports zero, so dashboards
            # can tell "never happened" from "metric missing".
            lines.append(f"{self.name}{_render_labels(())} 0")
        for key, value in sorted(self.values.items()):
            lines.append(f"{self.name}{_render_labels(key)} {_format_float(value)}")
        return lines


@dataclass
class Gauge(_Metric):
    """Point-in-time value that can go up or down."""

    values: dict[_LabelKey, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set(self, value: float, **labels: str) -> None:
        self._check(labels)
        with self._lock:
            self.values[_key(labels)] = float(value)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        self._check(labels)
        with self._lock:
            self.values[_key(labels)] = self.values.get(_key(labels), 0.0) + amount

    def value(self, **labels: str) -> float:
        return self.values.get(_key(labels), 0.0)

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} gauge"]
        for key, value in sorted(self.values.items()):
            lines.append(f"{self.name}{_render_labels(key)} {_format_float(value)}")
        return lines


@dataclass
class Histogram(_Metric):
    """Cumulative bucket histogram, the Prometheus flavour."""

    buckets: tuple[float, ...] = DEFAULT_BUCKETS
    counts: dict[_LabelKey, list[int]] = field(default_factory=dict)
    sums: dict[_LabelKey, float] = field(default_factory=dict)
    totals: dict[_LabelKey, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def observe(self, seconds: float, **labels: str) -> None:
        self._check(labels)
        key = _key(labels)
        with self._lock:
            if key not in self.counts:
                self.counts[key] = [0] * len(self.buckets)
                self.sums[key] = 0.0
                self.totals[key] = 0
            for index, edge in enumerate(self.buckets):
                if seconds <= edge:
                    self.counts[key][index] += 1
            self.sums[key] += seconds
            self.totals[key] += 1

    @contextmanager
    def time(self, **labels: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.observe(time.perf_counter() - started, **labels)

    def total(self, **labels: str) -> int:
        return self.totals.get(_key(labels), 0)

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]
        for key in sorted(self.counts):
            for index, edge in enumerate(self.buckets):
                labels = _render_labels(key, (("le", _format_float(edge)),))
                lines.append(f"{self.name}_bucket{labels} {self.counts[key][index]}")
            inf_labels = _render_labels(key, (("le", "+Inf"),))
            lines.append(f"{self.name}_bucket{inf_labels} {self.totals[key]}")
            lines.append(f"{self.name}_sum{_render_labels(key)} {_format_float(self.sums[key])}")
            lines.append(f"{self.name}_count{_render_labels(key)} {self.totals[key]}")
        return lines


class Registry:
    """Holds metrics and renders the exposition payload."""

    def __init__(self) -> None:
        self._metrics: dict[str, Counter | Gauge | Histogram] = {}
        self._lock = threading.Lock()

    def register(self, metric: Counter | Gauge | Histogram) -> None:
        with self._lock:
            if metric.name in self._metrics:
                raise ValueError(f"metric {metric.name!r} already registered")
            self._metrics[metric.name] = metric

    def counter(self, name: str, help_text: str, labels: Sequence[str] = ()) -> Counter:
        metric = Counter(name=name, help_text=help_text, kind="counter", label_names=tuple(labels))
        self.register(metric)
        return metric

    def gauge(self, name: str, help_text: str, labels: Sequence[str] = ()) -> Gauge:
        metric = Gauge(name=name, help_text=help_text, kind="gauge", label_names=tuple(labels))
        self.register(metric)
        return metric

    def histogram(
        self,
        name: str,
        help_text: str,
        labels: Sequence[str] = (),
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> Histogram:
        metric = Histogram(
            name=name,
            help_text=help_text,
            kind="histogram",
            label_names=tuple(labels),
            buckets=tuple(sorted(buckets)),
        )
        self.register(metric)
        return metric

    def get(self, name: str) -> Counter | Gauge | Histogram:
        return self._metrics[name]

    def render(self) -> str:
        chunks: list[str] = []
        for name in sorted(self._metrics):
            chunks.extend(self._metrics[name].render())
        return "\n".join(chunks) + "\n"

    def reset(self) -> None:
        """Test helper: clear observations without re-registering metrics."""
        with self._lock:
            for metric in self._metrics.values():
                if isinstance(metric, Histogram):
                    metric.counts.clear()
                    metric.sums.clear()
                    metric.totals.clear()
                else:
                    metric.values.clear()


CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

REGISTRY = Registry()

# --- the metrics Reachset actually reports ------------------------------

INGEST_RECORDS = REGISTRY.counter(
    "reachset_ingest_records_total",
    "Canonical records upserted, by tenant, app and record type.",
    labels=("tenant", "app", "record_type"),
)
INGEST_DURATION = REGISTRY.histogram(
    "reachset_ingest_duration_seconds",
    "Wall time to upsert one extracted batch.",
    labels=("app",),
)
DEAD_LETTERS = REGISTRY.counter(
    "reachset_dead_letters_total",
    "Pages that exhausted their retries and were dead-lettered.",
    labels=("app", "stream"),
)
REACH_EDGES = REGISTRY.gauge(
    "reachset_reach_edges",
    "Materialized reach edges per tenant, as of the last recomputation.",
    labels=("tenant",),
)
REACH_DURATION = REGISTRY.histogram(
    "reachset_reach_recompute_seconds",
    "Wall time of a reach materialization.",
    labels=("mode",),
)
HTTP_REQUESTS = REGISTRY.counter(
    "reachset_http_requests_total",
    "HTTP requests served by the API.",
    labels=("method", "route", "status"),
)
HTTP_DURATION = REGISTRY.histogram(
    "reachset_http_request_duration_seconds",
    "HTTP request latency.",
    labels=("method", "route"),
)
FINDINGS = REGISTRY.counter(
    "reachset_findings_total",
    "Detection findings emitted, by rule and severity.",
    labels=("rule", "severity"),
)


def render_metrics() -> str:
    return REGISTRY.render()
