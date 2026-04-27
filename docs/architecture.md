# Architecture

## Pipeline

pcap → Zeek (sensor) → notice.log → Python analyzer → alerts.csv, summary.json,

Strictly one-way. Zeek exits before the analyzer starts (`depends_on:
service_completed_successfully`), so the input is frozen.

## Containers

| Service | Image | User | Caps | RO FS | Net | Mounts |

## Data shapes

**Zeek `notice.log`** — one JSON object per line. Required: `ts`, `note`, `msg`. Optional: `src`, `dst`, `sub`, `uid`.

**`alerts.csv`** — columns: `ts, severity, note, src, dst, msg, sub, uid`.

**`summary.json`** — `total_alerts`, `by_note`, `by_severity`, `top_sources`.