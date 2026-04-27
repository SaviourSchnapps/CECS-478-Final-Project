"""Parse Zeek notice.log JSON lines with strict validation.

Zeek 6.x writes one JSON object per line when LogAscii::use_json is enabled.
We validate each record before letting it propagate downstream so that a
malformed line cannot inject unexpected fields into the alert pipeline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

log = logging.getLogger(__name__)

MAX_LINE_BYTES = 64 * 1024
REQUIRED_FIELDS = ("ts", "note", "msg")
KNOWN_NOTES = {
    "IDS::PortScan",
    "IDS::SSHBruteForce",
    "IDS::ConnFlood",
}


class InvalidNoticeError(ValueError):
    """Raised when a line cannot be parsed into a valid Notice."""


@dataclass(frozen=True)
class Notice:
    ts: datetime
    note: str
    msg: str
    src: str | None
    dst: str | None
    sub: str | None
    uid: str | None

    def to_dict(self) -> dict:
        return {
            "ts": self.ts.isoformat(),
            "note": self.note,
            "msg": self.msg,
            "src": self.src,
            "dst": self.dst,
            "sub": self.sub,
            "uid": self.uid,
        }


def _parse_ts(value: object) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise InvalidNoticeError(f"bad ts: {value!r}") from e
    raise InvalidNoticeError(f"ts must be number or ISO string, got {type(value).__name__}")


def _parse_ip(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidNoticeError(f"{field} must be string, got {type(value).__name__}")
    try:
        ipaddress.ip_address(value)
    except ValueError as e:
        raise InvalidNoticeError(f"{field} not a valid IP: {value!r}") from e
    return value


def parse_line(line: str) -> Notice:
    """Validate a single JSON line and return a Notice. Raises InvalidNoticeError."""
    if not line or len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise InvalidNoticeError("line empty or exceeds size limit")
    try:
        record = json.loads(line)
    except json.JSONDecodeError as e:
        raise InvalidNoticeError(f"json decode failed: {e.msg}") from e
    if not isinstance(record, dict):
        raise InvalidNoticeError("notice must be a JSON object")

    for field in REQUIRED_FIELDS:
        if field not in record:
            raise InvalidNoticeError(f"missing required field {field!r}")

    note = record["note"]
    if not isinstance(note, str):
        raise InvalidNoticeError("note must be string")
    if note not in KNOWN_NOTES:
        log.warning("unknown notice type %r — passing through as low severity", note)

    msg = record["msg"]
    if not isinstance(msg, str) or len(msg) > 4096:
        raise InvalidNoticeError("msg must be string up to 4096 chars")

    sub = record.get("sub")
    if sub is not None and (not isinstance(sub, str) or len(sub) > 4096):
        raise InvalidNoticeError("sub must be string up to 4096 chars")

    uid = record.get("uid")
    if uid is not None and not isinstance(uid, str):
        raise InvalidNoticeError("uid must be string")

    return Notice(
        ts=_parse_ts(record["ts"]),
        note=note,
        msg=msg,
        src=_parse_ip(record.get("src"), "src"),
        dst=_parse_ip(record.get("dst"), "dst"),
        sub=sub,
        uid=uid,
    )


def parse_file(path: Path) -> Iterator[Notice]:
    """Yield validated Notices from a Zeek notice.log JSON file.

    Malformed lines are logged and skipped — one bad line should not block
    the rest of the run.
    """
    if not path.exists():
        log.info("notice.log not present at %s — yielding zero notices", path)
        return
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                yield parse_line(line)
            except InvalidNoticeError as e:
                log.warning("notice.log:%d skipped: %s", n, e)


def parse_iter(lines: Iterable[str]) -> Iterator[Notice]:
    """Iterator-friendly variant for tests and stdin streams."""
    for n, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            yield parse_line(line)
        except InvalidNoticeError as e:
            log.warning("input:%d skipped: %s", n, e)
