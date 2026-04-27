"""Summarizer tests — CSV + JSON output."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from analyzer.classifier import classify
from analyzer.parser import Notice
from analyzer.summarizer import (
    CSV_FIELDS,
    build_summary,
    write_alerts_csv,
    write_summary_json,
)


def _alerts():
    return [
        classify(Notice(datetime(2026, 4, 25), "IDS::PortScan", "x", "10.0.0.5", "10.0.0.10", None, None)),
        classify(Notice(datetime(2026, 4, 25), "IDS::PortScan", "x", "10.0.0.5", "10.0.0.10", None, None)),
        classify(Notice(datetime(2026, 4, 25), "IDS::ConnFlood", "x", "10.0.0.6", "10.0.0.10", None, None)),
        classify(Notice(datetime(2026, 4, 25), "IDS::SSHBruteForce", "x", None, None, None, None)),
    ]


def test_build_summary_counts_correctly():
    summary = build_summary(_alerts())
    assert summary["total_alerts"] == 4
    assert summary["by_note"]["IDS::PortScan"] == 2
    assert summary["by_note"]["IDS::ConnFlood"] == 1
    assert summary["by_severity"]["medium"] == 2
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1


def test_top_sources_orders_by_count_desc():
    summary = build_summary(_alerts())
    assert summary["top_sources"][0] == {"src": "10.0.0.5", "count": 2}


def test_top_sources_skips_alerts_without_src():
    summary = build_summary(_alerts())
    srcs = [t["src"] for t in summary["top_sources"]]
    assert None not in srcs


def test_empty_input_produces_zero_summary():
    summary = build_summary([])
    assert summary["total_alerts"] == 0
    assert summary["by_note"] == {}
    assert summary["top_sources"] == []


def test_write_alerts_csv_has_header_and_rows(tmp_path: Path):
    out = tmp_path / "alerts.csv"
    n = write_alerts_csv(_alerts(), out)
    assert n == 4
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert len(rows) == 4
    assert set(rows[0].keys()) == set(CSV_FIELDS)


def test_write_summary_json_round_trips(tmp_path: Path):
    out = tmp_path / "summary.json"
    summary = write_summary_json(_alerts(), out)
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk == summary
