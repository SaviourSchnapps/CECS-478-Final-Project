"""Aggregate Alerts into CSV + JSON summary artifacts."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from .classifier import Alert

CSV_FIELDS = ("ts", "severity", "note", "src", "dst", "msg", "sub", "uid")


def write_alerts_csv(alerts: Iterable[Alert], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert.to_row())
            n += 1
    return n


def build_summary(alerts: list[Alert]) -> dict:
    by_note = Counter(a.notice.note for a in alerts)
    by_severity = Counter(a.severity.label() for a in alerts)
    by_src = Counter(a.notice.src for a in alerts if a.notice.src)
    top_sources = by_src.most_common(10)
    return {
        "total_alerts": len(alerts),
        "by_note": dict(by_note),
        "by_severity": dict(by_severity),
        "top_sources": [{"src": s, "count": c} for s, c in top_sources],
    }


def write_summary_json(alerts: list[Alert], path: Path) -> dict:
    summary = build_summary(alerts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return summary
