"""Parser tests — happy path + several negative/edge cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.parser import (
    InvalidNoticeError,
    Notice,
    parse_file,
    parse_iter,
    parse_line,
    MAX_LINE_BYTES,
)


def test_parse_line_happy_path(make_notice_line):
    raw = make_notice_line(
        note="IDS::PortScan",
        src="10.0.0.5",
        dst="10.0.0.10",
        msg="port scan detected",
        sub="count=20",
        uid="abc123",
    )
    notice = parse_line(raw)
    assert isinstance(notice, Notice)
    assert notice.note == "IDS::PortScan"
    assert notice.src == "10.0.0.5"
    assert notice.dst == "10.0.0.10"
    assert notice.msg == "port scan detected"
    assert notice.uid == "abc123"


def test_parse_line_unix_timestamp(make_notice_line):
    raw = make_notice_line(ts=1714000000.0)
    notice = parse_line(raw)
    assert notice.ts.year == 2024


def test_parse_line_rejects_non_json():
    with pytest.raises(InvalidNoticeError, match="json decode"):
        parse_line("definitely not json")


def test_parse_line_rejects_empty_input():
    with pytest.raises(InvalidNoticeError):
        parse_line("")


def test_parse_line_rejects_oversized_input():
    huge = json.dumps({"ts": 0, "note": "IDS::PortScan", "msg": "x" * (MAX_LINE_BYTES + 100)})
    with pytest.raises(InvalidNoticeError):
        parse_line(huge)


def test_parse_line_rejects_array_root():
    with pytest.raises(InvalidNoticeError, match="must be a JSON object"):
        parse_line('[1,2,3]')


def test_parse_line_rejects_missing_required_field():
    with pytest.raises(InvalidNoticeError, match="missing required field"):
        parse_line(json.dumps({"ts": 0, "msg": "x"}))


def test_parse_line_rejects_bad_ip(make_notice_line):
    raw = make_notice_line(src="not-an-ip")
    with pytest.raises(InvalidNoticeError, match="not a valid IP"):
        parse_line(raw)


def test_parse_line_rejects_bad_timestamp(make_notice_line):
    raw = make_notice_line(ts="not-a-date")
    with pytest.raises(InvalidNoticeError, match="bad ts"):
        parse_line(raw)


def test_parse_line_rejects_non_string_msg(make_notice_line):
    raw = make_notice_line(msg=12345)
    with pytest.raises(InvalidNoticeError, match="msg must be string"):
        parse_line(raw)


def test_parse_line_unknown_note_passes_through(make_notice_line, caplog):
    raw = make_notice_line(note="Custom::SomethingNew")
    with caplog.at_level("WARNING"):
        notice = parse_line(raw)
    assert notice.note == "Custom::SomethingNew"
    assert any("unknown notice" in rec.message for rec in caplog.records)


def test_parse_line_optional_sub_uid_can_be_absent(make_notice_line):
    notice = parse_line(make_notice_line())
    assert notice.sub is None
    assert notice.uid is None


def test_parse_file_skips_malformed_and_keeps_going(malformed_notice_log: Path):
    notices = list(parse_file(malformed_notice_log))
    # 5 input lines, 2 invalid (not-json, bad ts, bad ip = 3 invalid actually)
    valid_notes = [n.note for n in notices]
    assert "IDS::PortScan" in valid_notes
    assert "IDS::ConnFlood" in valid_notes
    assert len(notices) == 2


def test_parse_file_missing_path_returns_empty(tmp_path: Path):
    notices = list(parse_file(tmp_path / "does-not-exist.log"))
    assert notices == []


def test_parse_iter_yields_valid_skips_invalid(make_notice_line):
    lines = [make_notice_line(), "garbage", make_notice_line(note="IDS::ConnFlood")]
    notices = list(parse_iter(lines))
    assert len(notices) == 2
