# Release Evidence

Artifacts produced by `make demo` and committed for verification.

| File | Origin | What it shows |
|---|---|---|
| `demo.pcap` | `tools/gen_pcap.py`
| `notice.log` | Zeek (sample) | Representative `notice.log` JSON output, five alerts across all three detectors |
| `alerts.csv` | analyzer
| `summary.json` | analyzer
| `alerts.png` | analyzer 
| `run.log` | analyzer

## Reproducing

make up
make demo

This regenerates every file in this directory from scratch.

## Snapshot history

`tools/snapshot_evidence.sh` archives each run into `artifacts/release/runs/<UTC-timestamp>/`

## What's new and what's next

What works right now is the planned pipeline. This is the pcap and Zeek using 3 detectors and a python-based analyzer. It currently stands as reproduceable and it’s something I think is essentially plug and play with the exception of needing docker to run the containers. I tested it with 95% coverage, so I'm confident in the pipeline. For what’s next, I hope I can run the pipeline with real detection numbers. I would also like to confidently measure false positives. There are some gaps currently which are the synthetic exercises, and the current default pipeline is file based. 