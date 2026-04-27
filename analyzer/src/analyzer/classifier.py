"""Classify a Notice into a severity level.

Static rule table. A future iteration could feed src reputation or asset
criticality from a sidecar enrichment file.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .parser import Notice


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name.lower()


_RULES: dict[str, Severity] = {
    "IDS::PortScan": Severity.MEDIUM,
    "IDS::SSHBruteForce": Severity.HIGH,
    "IDS::ConnFlood": Severity.CRITICAL,
}


@dataclass(frozen=True)
class Alert:
    notice: Notice
    severity: Severity

    def to_row(self) -> dict[str, str]:
        n = self.notice
        return {
            "ts": n.ts.isoformat(),
            "severity": self.severity.label(),
            "note": n.note,
            "src": n.src or "",
            "dst": n.dst or "",
            "msg": n.msg,
            "sub": n.sub or "",
            "uid": n.uid or "",
        }


def classify(notice: Notice) -> Alert:
    return Alert(notice=notice, severity=_RULES.get(notice.note, Severity.LOW))
