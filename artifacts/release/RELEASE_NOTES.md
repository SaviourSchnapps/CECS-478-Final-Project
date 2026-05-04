# Release notes — v1.0.0

**Date:** 2026-05-02
**Tag:** `v1.0.0`

First stable release of the Zeek IDS pipeline. This is the version submitted
for the CECS 478 final milestone and the snapshot used to produce the report
under [`docs/FINAL_REPORT.md`](../../docs/FINAL_REPORT.md).

## Highlights

- **End-to-end reproducible demo.** `make up && make demo` on a fresh clone
  produces every artifact in this directory from scratch.
- **Sandboxed by default.** Both Zeek and the analyzer run as UID 1000 with
  no Linux capabilities, no network, and a read-only root filesystem.
- **3-alert demo output.** The frozen synthetic pcap trips the PortScan
  detector twice (10.0.0.5 and 10.0.0.7) and the ConnFlood detector once
  (10.0.0.6). See [`summary.json`](summary.json).
- **97 % line coverage** across 42 analyzer tests (`make test`).

## Changes since the prior tag

This is the first tagged release. Compared with the alpha-beta integration
checkpoint (`09ea471`):

- Synthetic pcap now contains a second port scanner so the demo trips two
  `IDS::PortScan` notices in addition to the existing `IDS::ConnFlood`.
  Frozen `summary.json` reflects 3 alerts.
- Final report added at `docs/FINAL_REPORT.md` (and `.docx`).
- README, runbook, and architecture docs filled out (previously stubs).
- `Dockerfile.dev` / `tests/test_gen_pcap.py` reconciled so `make test`
  succeeds cleanly in the dev container (the suite that needs the
  repo-root layout skips itself when run inside the container; it runs
  end-to-end via `make test-local`).

## How to verify

```sh
make clean   # remove runtime artifacts (release/ preserved)
make up
make demo
make test    # 42 tests, ~97 % line coverage
```

`tools/snapshot_evidence.sh` archives a run into
`artifacts/release/runs/<UTC-timestamp>/` so you can compare across runs.
