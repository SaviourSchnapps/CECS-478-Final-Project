# Status

Updated: 2026-05-02 — v1.0.0 release candidate.

## What works

`make up && make demo` on a fresh clone produces evidence in
`artifacts/release/` with deterministic content (when `--base-ts` is fixed).

- Zeek 6.0 + Python 3.12 analyzer in two non-root containers
  (read-only FS, no caps, no network)
- Three detectors: `IDS::PortScan`, `IDS::SSHBruteForce`, `IDS::ConnFlood`
- Analyzer pipeline: parse → classify → rate-limit → CSV / JSON / chart / log
- Deterministic synthetic pcap (pure stdlib, no scapy)
- 42 unit + integration tests, **97 %** line coverage, CI on every push
- Recorded demo (`demo.mp4`) covers the full pipeline end-to-end

## Frozen results

Demo run produces 3 alerts (2 PortScan, 1 ConnFlood) across 3 source IPs.
See [RESULTS.md](./RESULTS.md) and `artifacts/release/summary.json`.

## Known gaps

- The synthetic pcap exercises PortScan and ConnFlood at the network level.
  `SSHBruteForce` is wired through Zeek + classified + unit-tested, but the
  end-to-end demo does not trip it (synthetic pcap is pure TCP SYN traffic, no
  SSH protocol payload).
- Live capture mode is documented in the runbook but is not the default
  (requires Linux + elevated `cap_net_raw`).
- No measurement against real captures yet; detection numbers in this release
  are demonstrative, not statistical.

## Out of scope (future work)

- Run the pipeline against CTU-13 / MACCDC pcaps for real detection rates.
- Measure false-positive rate on a benign baseline; tune detector thresholds.
- Add an SSH-transcript pcap so the Zeek SSH analyzer fires end-to-end.
- Lateral-movement, beaconing, and DNS-tunneling detectors.
