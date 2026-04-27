"""Shared fixtures for analyzer tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _line(**kwargs) -> str:
    base = {
        "ts": "2026-04-25T12:00:00Z",
        "note": "IDS::PortScan",
        "msg": "demo",
    }
    base.update(kwargs)
    return json.dumps(base)


@pytest.fixture
def make_notice_line():
    return _line


@pytest.fixture
def synthetic_notices() -> list[str]:
    return [
        _line(note="IDS::PortScan",      src="10.0.0.5", dst="10.0.0.10", msg="scan", sub="count=20"),
        _line(note="IDS::ConnFlood",     src="10.0.0.6", dst="10.0.0.10", msg="flood", sub="count=300"),
        _line(note="IDS::SSHBruteForce", src="10.0.0.7", dst="10.0.0.10", msg="ssh"),
        _line(note="IDS::PortScan",      src="10.0.0.5", dst="10.0.0.10", msg="scan2"),
    ]


@pytest.fixture
def notice_log(tmp_path: Path, synthetic_notices: list[str]) -> Path:
    p = tmp_path / "notice.log"
    p.write_text("\n".join(synthetic_notices) + "\n", encoding="utf-8")
    return p


@pytest.fixture
def malformed_notice_log(tmp_path: Path) -> Path:
    p = tmp_path / "notice.log"
    lines = [
        _line(note="IDS::PortScan", src="10.0.0.5"),
        "this is not json",
        _line(note="IDS::ConnFlood", src="10.0.0.6"),
        '{"ts":"bad","note":"IDS::PortScan","msg":"x"}',
        _line(note="IDS::SSHBruteForce", src="not-an-ip"),
    ]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


class FakeClock:
    """Manually-advanced monotonic clock for ratelimit tests."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()
