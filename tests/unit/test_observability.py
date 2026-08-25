"""The metrics registry and its Prometheus exposition.

These tests exist because a metrics bug is silent: nothing breaks, the numbers
are just wrong, and you find out during an incident. So the exposition format
is asserted literally.
"""

import threading

import pytest

from reachset.observability import (
    DEFAULT_BUCKETS,
    Counter,
    Gauge,
    Histogram,
    Registry,
    _format_float,
)


def test_counter_accumulates_per_label_set() -> None:
    counter = Counter(name="c", help_text="h", kind="counter", label_names=("app",))
    counter.inc(app="vault")
    counter.inc(2, app="vault")
    counter.inc(app="github")
    assert counter.value(app="vault") == 3
    assert counter.value(app="github") == 1
    assert counter.value(app="never-seen") == 0


def test_counter_rejects_negative_and_wrong_labels() -> None:
    counter = Counter(name="c", help_text="h", kind="counter", label_names=("app",))
    with pytest.raises(ValueError, match="cannot decrease"):
        counter.inc(-1, app="vault")
    with pytest.raises(ValueError, match="expects labels"):
        counter.inc(app="vault", extra="nope")
    with pytest.raises(ValueError, match="expects labels"):
        counter.inc()


def test_counter_renders_zero_when_never_incremented() -> None:
    counter = Counter(name="reachset_thing_total", help_text="Things.", kind="counter")
    rendered = counter.render()
    assert rendered[0] == "# HELP reachset_thing_total Things."
    assert rendered[1] == "# TYPE reachset_thing_total counter"
    assert rendered[2] == "reachset_thing_total 0"


def test_gauge_goes_both_ways() -> None:
    gauge = Gauge(name="g", help_text="h", kind="gauge", label_names=("tenant",))
    gauge.set(10, tenant="t1")
    gauge.inc(-4, tenant="t1")
    assert gauge.value(tenant="t1") == 6
    assert 'g{tenant="t1"} 6' in gauge.render()


def test_histogram_buckets_are_cumulative() -> None:
    hist = Histogram(name="h", help_text="h", kind="histogram", buckets=(0.1, 1.0, 10.0))
    for value in (0.05, 0.5, 5.0, 50.0):
        hist.observe(value)
    lines = hist.render()
    assert 'h_bucket{le="0.1"} 1' in lines
    assert 'h_bucket{le="1"} 2' in lines
    assert 'h_bucket{le="10"} 3' in lines
    assert 'h_bucket{le="+Inf"} 4' in lines
    assert "h_count 4" in lines
    assert hist.total() == 4


def test_histogram_context_manager_records() -> None:
    hist = Histogram(name="h", help_text="h", kind="histogram", label_names=("op",))
    with hist.time(op="query"):
        pass
    assert hist.total(op="query") == 1


def test_histogram_context_manager_records_on_exception() -> None:
    """A failing operation still took time; losing that observation would hide
    exactly the slow failures you want on a dashboard."""
    hist = Histogram(name="h", help_text="h", kind="histogram", label_names=("op",))
    with pytest.raises(RuntimeError), hist.time(op="query"):
        raise RuntimeError("boom")
    assert hist.total(op="query") == 1


def test_label_values_are_escaped() -> None:
    counter = Counter(name="c", help_text="h", kind="counter", label_names=("route",))
    counter.inc(route='/a"b\\c')
    rendered = "\n".join(counter.render())
    assert r'route="/a\"b\\c"' in rendered


def test_format_float_matches_prometheus_expectations() -> None:
    assert _format_float(float("inf")) == "+Inf"
    assert _format_float(float("-inf")) == "-Inf"
    assert _format_float(3.0) == "3"
    assert _format_float(0.25) == "0.25"


def test_registry_rejects_duplicate_names() -> None:
    registry = Registry()
    registry.counter("dup", "first")
    with pytest.raises(ValueError, match="already registered"):
        registry.counter("dup", "second")


def test_registry_renders_all_metric_types() -> None:
    registry = Registry()
    registry.counter("a_total", "A counter.").inc()
    registry.gauge("b_current", "A gauge.").set(7)
    registry.histogram("c_seconds", "A histogram.", buckets=(1.0,)).observe(0.5)
    payload = registry.render()

    assert "# TYPE a_total counter" in payload
    assert "# TYPE b_current gauge" in payload
    assert "# TYPE c_seconds histogram" in payload
    assert payload.endswith("\n")
    # Metric families are emitted in sorted order, which keeps diffs readable.
    assert payload.index("a_total") < payload.index("b_current") < payload.index("c_seconds")


def test_registry_get_and_reset() -> None:
    registry = Registry()
    counter = registry.counter("x_total", "X.")
    hist = registry.histogram("y_seconds", "Y.")
    counter.inc()
    hist.observe(0.2)
    assert registry.get("x_total") is counter

    registry.reset()
    assert counter.value() == 0
    assert hist.total() == 0
    # Reset clears observations but keeps registrations, so re-registering fails.
    with pytest.raises(ValueError, match="already registered"):
        registry.counter("x_total", "X.")


def test_default_buckets_are_sorted() -> None:
    assert list(DEFAULT_BUCKETS) == sorted(DEFAULT_BUCKETS)


def test_concurrent_increments_do_not_lose_updates() -> None:
    """The API middleware and the worker both write; a lost update here shows
    up as quietly undercounted traffic."""
    counter = Counter(name="c", help_text="h", kind="counter")
    threads = [
        threading.Thread(target=lambda: [counter.inc() for _ in range(500)]) for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert counter.value() == 4000
