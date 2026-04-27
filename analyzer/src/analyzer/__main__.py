"""CLI entry: parse Zeek logs, classify, rate-limit, write evidence artifacts."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .chart import render_alert_chart
from .classifier import classify
from .parser import parse_file
from .ratelimit import TokenBucketLimiter
from .summarizer import write_alerts_csv, write_summary_json

log = logging.getLogger("analyzer")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="analyzer", description="Zeek IDS post-processor")
    p.add_argument("--log-dir", type=Path,
                   default=Path(os.environ.get("ANALYZER_LOG_DIR", "/logs")),
                   help="directory containing Zeek notice.log")
    p.add_argument("--out-dir", type=Path,
                   default=Path(os.environ.get("ANALYZER_OUT_DIR", "/out")),
                   help="directory for evidence artifacts")
    p.add_argument("--rate-limit-per-sec", type=float,
                   default=float(os.environ.get("ANALYZER_RATE_LIMIT_PER_SEC", "50")),
                   help="per-source alert rate limit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def run(log_dir: Path, out_dir: Path, rate_limit_per_sec: float) -> int:
    notice_path = log_dir / "notice.log"
    csv_path = out_dir / "alerts.csv"
    summary_path = out_dir / "summary.json"
    chart_path = out_dir / "alerts.png"

    limiter = TokenBucketLimiter(rate_per_sec=rate_limit_per_sec,
                                 burst=max(rate_limit_per_sec * 2.0, 10.0))

    accepted: list = []
    dropped = 0
    parsed = 0
    log.info("reading notices from %s", notice_path)

    for notice in parse_file(notice_path):
        parsed += 1
        key = notice.src or "anon"
        if not limiter.allow(key):
            dropped += 1
            continue
        alert = classify(notice)
        accepted.append(alert)
        log.debug("alert %s severity=%s src=%s",
                  alert.notice.note, alert.severity.label(), alert.notice.src)

    csv_count = write_alerts_csv(accepted, csv_path)
    summary = write_summary_json(accepted, summary_path)
    render_alert_chart(summary["by_note"], chart_path)

    log.info("parsed=%d accepted=%d dropped=%d -> %s",
             parsed, csv_count, dropped, out_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return run(args.log_dir, args.out_dir, args.rate_limit_per_sec)
    except Exception:
        log.exception("analyzer run failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
