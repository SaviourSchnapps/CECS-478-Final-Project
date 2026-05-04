# Zeek IDS Pipeline

A small, reproducible network IDS built around Zeek and a Python post-processor.
Zeek consumes a pcap (or live interface), emits structured `notice.log`
records, and the analyzer parses, classifies, rate-limits, and summarizes the
alerts into evidence artifacts (CSV, JSON, chart, log).

CECS 478 final project. Built and maintained by Marco.

## Quickstart

```sh
git clone <repo> && cd CECS-478-Final-Project
make up      # build the two container images
make demo    # generate pcap → run Zeek → run analyzer → write evidence
cat artifacts/release/summary.json
```

Both Zeek and the analyzer run in non-root containers with no capabilities,
no network, and a read-only root filesystem (see [docs/SECURITY.md](docs/SECURITY.md)).

## What's in the box

```
analyzer/        Python 3.12 post-processor + tests (97% coverage)
zeek/            Zeek 6.0 image + three IDS scripts
tools/           Deterministic pcap generator (pure stdlib)
pcaps/sample/    Generated demo capture
artifacts/release/  Frozen v1.0.0 evidence (CSV / JSON / PNG / log)
docs/            Report, runbook, architecture, threat model, results
demo.mp4         Recorded end-to-end demo
```

## Detectors

| Note                  | Trigger                                              | Severity |
|-----------------------|------------------------------------------------------|----------|
| `IDS::PortScan`       | ≥15 distinct destination ports per source / 60 s     | medium   |
| `IDS::SSHBruteForce`  | ≥5 failed SSH auths per (src, dst) / 5 min           | high     |
| `IDS::ConnFlood`      | ≥200 new connections per source / 30 s               | critical |

Thresholds are `&redef`-able in [zeek/scripts/](zeek/scripts/).

## Documentation

- [docs/FINAL_REPORT.md](docs/FINAL_REPORT.md) — final 5–6 page report.
- [docs/architecture.md](docs/architecture.md) — pipeline + container layout.
- [docs/SECURITY.md](docs/SECURITY.md) — invariants and threat model.
- [docs/RESULTS.md](docs/RESULTS.md) — frozen v1.0.0 results and reproduction steps.
- [docs/RUNBOOK.md](docs/RUNBOOK.md) — operational recipes.
- [docs/STATUS.md](docs/STATUS.md) — what works, what's gaps, what's next.

## Reproducibility

The release pack at [artifacts/release/](artifacts/release/) is regenerable
end-to-end with `make clean && make up && make demo` on a fresh clone. The
synthetic pcap is deterministic when invoked with `--base-ts <epoch>`.

## License

See [LICENSE](LICENSE).
