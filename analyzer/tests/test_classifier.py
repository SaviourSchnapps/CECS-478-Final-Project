"""Classifier tests — severity rules."""

from __future__ import annotations

from datetime import datetime

from analyzer.classifier import Severity, classify
from analyzer.parser import Notice


def _n(note: str) -> Notice:
    return Notice(
        ts=datetime(2026, 4, 25),
        note=note,
        msg="x",
        src="10.0.0.1",
        dst="10.0.0.2",
        sub=None,
        uid=None,
    )


def test_port_scan_is_medium():
    assert classify(_n("IDS::PortScan")).severity is Severity.MEDIUM


def test_ssh_brute_is_high():
    assert classify(_n("IDS::SSHBruteForce")).severity is Severity.HIGH


def test_conn_flood_is_critical():
    assert classify(_n("IDS::ConnFlood")).severity is Severity.CRITICAL


def test_unknown_note_falls_back_to_low():
    alert = classify(_n("Custom::Whatever"))
    assert alert.severity is Severity.LOW
    assert alert.severity.label() == "low"


def test_severity_ordering_is_total():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_alert_to_row_handles_optional_fields():
    n = Notice(
        ts=datetime(2026, 4, 25, 12, 0, 0),
        note="IDS::PortScan", msg="m", src=None, dst=None, sub=None, uid=None,
    )
    row = classify(n).to_row()
    assert row["src"] == ""
    assert row["dst"] == ""
    assert row["sub"] == ""
    assert row["uid"] == ""
    assert row["severity"] == "medium"
