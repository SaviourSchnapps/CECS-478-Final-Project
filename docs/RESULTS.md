# Results

_Final results — v1.0.0 release, 2026-05-02._

## Datasets

| Source | Type | Use |
|---|---|---|
| `tools/gen_pcap.py` (synthetic) | TCP SYN scan + flood, 290 pkts | Demo: validates PortScan + ConnFlood end-to-end |
| `analyzer/tests/conftest.py` (fixture) | 4 fabricated `notice.log` lines | Validates classifier/summarizer paths offline |
| _planned_: CTU-13 scenario 4 | real botnet capture | Future detection-rate measurement |
| _planned_: 24h benign LAN capture | normal traffic | Future false-positive baseline |

## Demo output (frozen in `artifacts/release/`)

`make demo` defaults to seeding the synthetic pcap with the current
wall-clock, so the timestamps in `notice.log` and `alerts.csv` reflect each
run. The alert counts below are seed-independent — running with the
canonical pinned seed (`make demo PCAP_BASE_TS=1745000000`) reproduces the
exact output below:

```json
{
  "total_alerts": 3,
  "by_note":     { "IDS::PortScan": 2, "IDS::ConnFlood": 1 },
  "by_severity": { "medium": 2, "critical": 1 },
  "top_sources": [
    { "src": "10.0.0.5", "count": 1 },
    { "src": "10.0.0.7", "count": 1 },
    { "src": "10.0.0.6", "count": 1 }
  ]
}
```

![alerts by detector](../artifacts/release/alerts.png)

Three alerts across two detectors and three source IPs:

- Two **PortScan** notices (medium): `10.0.0.5` and `10.0.0.7` each touched 15
  distinct destination ports on `10.0.0.10` within the 60 s detector window.
- One **ConnFlood** notice (critical): `10.0.0.6` opened 200 connections to
  `10.0.0.10:80` in 30 s.

The pipeline parsed 3 notices, accepted 3, dropped 0 (well below the
50 alerts/sec/source rate-limit ceiling).

## Performance

Wall-clock for the full pipeline on the demo input is under 2 s on a developer
laptop (Docker Desktop, M-class CPU). The dominant cost is matplotlib's first
import (~250 ms); Zeek's pcap pass and the analyzer's parse/classify/summarize
stages are each under 100 ms.

The analyzer test suite runs 42 tests in ~2.7 s with **97 % line coverage**
(`make test`).

## Detector status

| Detector | Exercised by | End-to-end demo? |
|---|---|---|
| `IDS::PortScan` | synthetic pcap | yes — fires twice |
| `IDS::ConnFlood` | synthetic pcap | yes — fires once |
| `IDS::SSHBruteForce` | analyzer fixtures only | no — needs real SSH transcript |

The SSH brute-force detector is wired through Zeek (`ssh-bruteforce.zeek`),
classified, and tested at the analyzer layer, but the synthetic pcap is pure
TCP SYN traffic so it cannot trip the SSH protocol analyzer. Producing a
real SSH transcript pcap is listed under future work.

## Reproducing

```sh
make up      # build container images
make demo    # generate pcap, run zeek, run analyzer, write evidence
cat artifacts/release/summary.json
```

To analyze a different capture, drop it at `pcaps/sample/demo.pcap` and run
`make analyze` (skips pcap generation).
