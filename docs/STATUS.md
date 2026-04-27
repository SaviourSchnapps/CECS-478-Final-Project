# Status

Updated: 2026-04-26_

## What works

`make up && make demo` on a fresh clone produces evidence in `artifacts/release/`.

- Zeek 6.0 + Python analyzer in two non-root containers (read-only FS, no caps, no network)
- Three detectors: PortScan, SSHBruteForce, ConnFlood
- Analyzer pipeline: parse → classify → rate-limit → CSV/JSON/chart/log
- Deterministic synthetic pcap (pure stdlib, no scapy)
- 46 tests, 95% line+branch coverage, CI on every push

## Known gaps

- Synthetic pcap exercises PortScan + ConnFlood at the network level. SSHBruteForce is exercised via fixture (`artifacts/release/notice.log`) — protocol-level SSH replay is Week 16 work.
- Live capture mode documented but not the default (requires Linux + elevated caps).
- Demo video not yet recorded.

## Next

- Run the pipeline against CTU-13 / MACCDC pcaps for real-data detection numbers.
- Measure false-positive rate on a benign baseline; tune thresholds.
- Add an SSH-transcript pcap so the Zeek SSH analyzer fires end-to-end.
- Record the ≤2-min demo video.
