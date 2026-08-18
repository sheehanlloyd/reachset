"""Render bench/results.json into a plain SVG (no plotting dependencies).

Two panels: ingest throughput by worker count, and single-origin reachability
latency percentiles by tenant scale. Run after `make bench`:

    uv run python -m bench.plot
"""

import json
from pathlib import Path
from typing import Any

RESULTS = Path(__file__).parent / "results.json"
OUT = Path(__file__).parent / "results.svg"

_W, _H = 900, 360
_PANEL_W = 400
_BAR_FILL = "#4c78a8"
_PCT_FILLS = {"p50_ms": "#4c78a8", "p95_ms": "#f58518", "p99_ms": "#e45756"}


def _bar(x: float, y: float, w: float, h: float, fill: str, title: str) -> str:
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
        f'fill="{fill}"><title>{title}</title></rect>'
    )


def _text(x: float, y: float, s: str, size: int = 11, anchor: str = "middle") -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" text-anchor="{anchor}" '
        f'font-family="system-ui, sans-serif" fill="#333">{s}</text>'
    )


def render(results: dict[str, Any]) -> str:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_W}" height="{_H}" '
        f'viewBox="0 0 {_W} {_H}">',
        f'<rect width="{_W}" height="{_H}" fill="white"/>',
        _text(
            _W / 2,
            20,
            f"Reachset benchmarks — {results['machine'].get('cpu', '?')}, "
            f"scale profile: {results['scale_profile']}",
            13,
        ),
    ]

    # panel 1: ingest throughput
    ingest = results["ingest_throughput_by_workers"]
    top = max(v["events_per_sec"] for v in ingest.values()) or 1
    base_y, height = 300, 220
    parts.append(_text(60 + _PANEL_W / 2, 50, "ingest throughput (events/sec)", 12))
    for i, (workers, stats) in enumerate(sorted(ingest.items(), key=lambda kv: int(kv[0]))):
        x = 80 + i * 90
        h = height * stats["events_per_sec"] / top
        parts.append(
            _bar(
                x,
                base_y - h,
                60,
                h,
                _BAR_FILL,
                f"{workers} workers: {stats['events_per_sec']} ev/s",
            )
        )
        parts.append(_text(x + 30, base_y - h - 6, str(stats["events_per_sec"])))
        parts.append(_text(x + 30, base_y + 16, f"{workers}w"))

    # panel 2: reach latency percentiles
    reach = results["reachability"]
    lat_top = max(t["single_origin_query"]["p99_ms"] for t in reach) or 1
    x0 = 520
    parts.append(_text(x0 + 160, 50, "single-origin reach latency (ms)", 12))
    for i, tenant in enumerate(reach):
        gx = x0 + i * 110
        for j, key in enumerate(("p50_ms", "p95_ms", "p99_ms")):
            value = tenant["single_origin_query"][key]
            h = height * value / lat_top
            x = gx + j * 26
            parts.append(_bar(x, base_y - h, 20, h, _PCT_FILLS[key], f"{key}: {value} ms"))
        edges = tenant["materialized_edges"]
        parts.append(_text(gx + 39, base_y + 16, f"{edges:,} edges", 10))
    for j, key in enumerate(("p50", "p95", "p99")):
        parts.append(_bar(x0 + j * 70, 330, 12, 12, _PCT_FILLS[f"{key}_ms"], key))
        parts.append(_text(x0 + j * 70 + 36, 340, key, 10))

    parts.append("</svg>")
    return "\n".join(parts)


def main() -> None:
    results = json.loads(RESULTS.read_text())
    OUT.write_text(render(results) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
