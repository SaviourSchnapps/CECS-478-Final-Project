"""End-to-end pipeline tests via the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.__main__ import main, run


def test_e2e_happy_path(tmp_path: Path, notice_log: Path):
    out_dir = tmp_path / "out"
    rc = run(log_dir=notice_log.parent, out_dir=out_dir, rate_limit_per_sec=1000)
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["total_alerts"] == 4
    assert summary["by_note"]["IDS::PortScan"] == 2

    csv_text = (out_dir / "alerts.csv").read_text()
    assert "ts,severity,note" in csv_text.splitlines()[0]
    assert csv_text.count("\n") == 5  # header + 4 rows


def test_e2e_skips_malformed_lines(tmp_path: Path, malformed_notice_log: Path):
    out_dir = tmp_path / "out"
    rc = run(log_dir=malformed_notice_log.parent, out_dir=out_dir, rate_limit_per_sec=1000)
    assert rc == 0
    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["total_alerts"] == 2  # only 2 valid lines in fixture


def test_e2e_handles_missing_notice_log(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    out_dir = tmp_path / "out"
    rc = run(log_dir=log_dir, out_dir=out_dir, rate_limit_per_sec=1000)
    assert rc == 0
    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["total_alerts"] == 0


def test_e2e_rate_limit_drops_overflow(tmp_path: Path, make_notice_line):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    lines = [make_notice_line(src="10.0.0.42") for _ in range(500)]
    (log_dir / "notice.log").write_text("\n".join(lines), encoding="utf-8")

    out_dir = tmp_path / "out"
    rc = run(log_dir=log_dir, out_dir=out_dir, rate_limit_per_sec=1)
    assert rc == 0
    summary = json.loads((out_dir / "summary.json").read_text())
    # burst floor is 10, so up to ~10 should pass; the limiter must drop the rest
    assert summary["total_alerts"] < 100
    assert summary["total_alerts"] > 0


def test_cli_handles_run_failure(tmp_path: Path, monkeypatch):
    """If something inside run() raises, main() should return 1, not crash."""
    from analyzer import __main__ as cli

    def boom(*a, **kw):
        raise RuntimeError("simulated")

    monkeypatch.setattr(cli, "run", boom)
    rc = main(["--log-dir", str(tmp_path), "--out-dir", str(tmp_path / "out")])
    assert rc == 1
