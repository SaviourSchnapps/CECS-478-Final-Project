# Architecture

## Pipeline

```
pcap → Zeek (sensor) → notice.log → Python analyzer → alerts.csv
                                                    → summary.json
                                                    → alerts.png
                                                    → run.log
```

Strictly one-way. Zeek exits before the analyzer starts
(`depends_on: service_completed_successfully` in `docker-compose.yml`), so
the input file is frozen by the time the analyzer opens it. The analyzer
never reads packet bytes — it only consumes Zeek's structured `notice.log`.

## Containers

| Service  | Image                     | User    | Caps    | RO FS | Net  | Mounts                                                     |
|----------|---------------------------|---------|---------|-------|------|------------------------------------------------------------|
| zeek     | `zeek-ids/zeek:local`     | 1000    | drop ALL| yes   | none | `pcaps/:/pcaps:ro`, `zeek/scripts/:/scripts:ro`, `zeek/logs/:/logs:rw` |
| analyzer | `zeek-ids/analyzer:local` | 1000    | drop ALL| yes   | none | `zeek/logs/:/logs:ro`, `artifacts/release/:/out:rw`        |

Both containers also set `no-new-privileges:true` and back `/tmp` with a
size-bounded `tmpfs`. No ports are exposed; no networks are attached.

## Data shapes

**Zeek `notice.log`** — one JSON object per line.
- Required: `ts`, `note`, `msg`
- Optional: `src`, `dst`, `sub`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`

**`alerts.csv`** — columns: `ts, severity, note, src, dst, msg, sub, uid`.

**`summary.json`** — `total_alerts`, `by_note`, `by_severity`, `top_sources`.

## Modules

- `analyzer/src/analyzer/parser.py` — strict line-bounded JSON parser; rejects
  lines >64 KB, malformed JSON, invalid IPs, bad timestamps.
- `analyzer/src/analyzer/classifier.py` — maps `note` → `Severity` (low / medium
  / high / critical) using a static table.
- `analyzer/src/analyzer/ratelimit.py` — per-source token-bucket limiter
  (default 50 alerts/s, burst floor 10) to defang a single noisy source.
- `analyzer/src/analyzer/summarizer.py` — writes CSV + summary JSON.
- `analyzer/src/analyzer/chart.py` — matplotlib bar chart (alerts per detector).
- `analyzer/src/analyzer/__main__.py` — CLI entry point.

## Zeek scripts

- `zeek/scripts/main.zeek` — entry; enables JSON logging and loads detectors.
- `zeek/scripts/port-scan.zeek` — `IDS::PortScan` (≥15 distinct dst ports / 60 s).
- `zeek/scripts/ssh-bruteforce.zeek` — `IDS::SSHBruteForce` (failed SSH attempts).
- `zeek/scripts/dos-detect.zeek` — `IDS::ConnFlood` (≥200 conns / 30 s).
