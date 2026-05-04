# Runbook

Operational recipes for building, running, debugging, and re-baselining the
IDS pipeline.

## Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose ...`)
- GNU Make
- Python 3.12 + pip (only needed for `make test-local`)

## Cold start

```sh
git clone <repo> && cd CECS-478-Final-Project
make up      # build the two container images
make demo    # generate pcap → run zeek → run analyzer → write evidence
```

After `make demo`, every artifact in `artifacts/release/` is freshly
regenerated. `summary.json` should match the version frozen in the v1.0.0
release.

## Common targets

| Target          | Effect                                                          |
|-----------------|-----------------------------------------------------------------|
| `make up`       | Build the `zeek` and `analyzer` images.                         |
| `make pcap`     | Regenerate `pcaps/sample/demo.pcap` deterministically.          |
| `make analyze`  | Run Zeek over the current pcap, then run the analyzer.          |
| `make demo`     | `pcap` → `analyze` → `status` (one-shot end-to-end).            |
| `make test`     | Build the dev image and run pytest with coverage in-container.  |
| `make test-local` | Run pytest natively (no Docker).                              |
| `make evidence` | Snapshot `artifacts/release/` into a timestamped subdirectory.  |
| `make clean`    | Remove runtime artifacts (preserves `artifacts/release/`).      |
| `make down`     | `docker compose down --remove-orphans`.                         |

## Reproducing the v1.0.0 demo numbers

The frozen `summary.json` was produced with a fixed pcap timestamp seed:

```sh
python tools/gen_pcap.py --out pcaps/sample/demo.pcap --base-ts 1745000000
make analyze
diff <(jq -S . artifacts/release/summary.json) <(jq -S . release/summary.json)
```

Without `--base-ts` the pcap uses wall-clock time, which still produces the
same alert *counts* but different timestamps in `notice.log` / `alerts.csv`.

## Re-baselining a real capture

1. Drop a pcap at `pcaps/sample/demo.pcap` (or anywhere under `pcaps/`).
2. `make analyze` (skips the synthetic generator; runs Zeek + analyzer).
3. Inspect `artifacts/release/summary.json` and `alerts.csv`.
4. `make evidence` to archive the run under `artifacts/release/runs/<ts>/`.

## Debugging

- **Zeek silent (no `notice.log` produced)** — Zeek only emits `notice.log`
  when at least one detector fires. `find-filtered-trace` warnings about
  pure-control-packet pcaps are expected and harmless for the synthetic input.
- **Analyzer "(no notice.log produced)"** — the previous Zeek run found no
  alerts. Drop in a richer pcap or lower a threshold in `zeek/scripts/`.
- **`make test` collection error for `test_gen_pcap`** — the dev image only
  ships `analyzer/`. The suite skips itself when `tools/gen_pcap.py` is not on
  the filesystem; it runs end-to-end via `make test-local`.
- **Container won't start as UID 1000** — make sure `zeek/logs/` and
  `artifacts/release/` are writable by your host user (the bind mounts inherit
  host ownership).

## Live capture (optional, Linux-only)

The default mode reads pcaps from disk. To run Zeek live on an interface:

1. Add `cap_add: [NET_RAW, NET_ADMIN]` to the `zeek` service in
   `docker-compose.yml` (this *weakens* the security posture).
2. Replace `command: ["-C", "-r", ...]` with `command: ["-i", "<iface>", ...]`
   and add `network_mode: host`.
3. Restart with `docker compose up zeek`.

This is documented but not the supported demo configuration; it trades the
"no caps + no network" invariants for live-capture capability.
