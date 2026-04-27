"""Chart tests — render with matplotlib if present, skip cleanly if not."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from analyzer.chart import render_alert_chart


def _has_matplotlib() -> bool:
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not _has_matplotlib(), reason="matplotlib not installed")
def test_render_chart_produces_png(tmp_path: Path):
    out = tmp_path / "chart.png"
    written = render_alert_chart({"IDS::PortScan": 3, "IDS::ConnFlood": 1}, out)
    assert written is True
    assert out.exists() and out.stat().st_size > 0


@pytest.mark.skipif(not _has_matplotlib(), reason="matplotlib not installed")
def test_empty_input_renders_placeholder(tmp_path: Path):
    out = tmp_path / "chart.png"
    assert render_alert_chart({}, out) is True
    assert out.exists()


def test_render_skipped_when_matplotlib_missing(tmp_path: Path, monkeypatch):
    # Force ImportError by stubbing matplotlib in sys.modules
    monkeypatch.setitem(sys.modules, "matplotlib", None)
    out = tmp_path / "chart.png"
    written = render_alert_chart({"IDS::PortScan": 1}, out)
    assert written is False
    assert not out.exists()
