# Release evidence

Frozen artifacts produced by `make demo` and committed for grader / future
verification. See [`RELEASE_NOTES.md`](RELEASE_NOTES.md) for what changed in
this version, and [`../../docs/FINAL_REPORT.md`](../../docs/FINAL_REPORT.md)
for the full write-up.

| File              | Origin              | What it shows                                       |
|-------------------|---------------------|-----------------------------------------------------|
| `demo.pcap`       | `tools/gen_pcap.py` | Deterministic 290-packet synthetic capture          |
| `notice.log`      | Zeek                | 3 alerts: 2 × `IDS::PortScan`, 1 × `IDS::ConnFlood` |
| `alerts.csv`      | analyzer            | Same alerts, flat CSV with severity + timestamps    |
| `summary.json`    | analyzer            | Aggregate counts (`by_note`, `by_severity`, `top_sources`) |
| `alerts.png`      | analyzer            | Bar chart of alerts per detector                    |
| `run.log`         | analyzer + zeek     | Combined pipeline stdout/stderr (wall-clock trace)  |

## Reproducing

```sh
make up
make demo
```

This regenerates every file in this directory from scratch. By default
`make demo` seeds the synthetic pcap with the current wall-clock, so
`demo.pcap`, `notice.log`, and `alerts.csv` show up-to-date timestamps each
run. `summary.json` and `alerts.png` are byte-stable regardless of the seed
(they reflect alert counts, not timestamps). `run.log` is the live trace of
docker-compose and Python logging output and is also not byte-stable.

To reproduce the canonical release output quoted in
[`../../docs/FINAL_REPORT.md`](../../docs/FINAL_REPORT.md):

```sh
make demo PCAP_BASE_TS=1745000000
```

## Snapshot history

`tools/snapshot_evidence.sh` archives each run into
`artifacts/release/runs/<UTC-timestamp>/` so historic runs can be compared.
