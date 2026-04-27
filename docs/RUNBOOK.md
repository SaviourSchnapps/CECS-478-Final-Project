# Runbook

Operational recipes for building, running, debugging, and re-baselining
the IDS pipeline.

## Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose ...`)
- GNU make
Python 3.12 + pip


## Cold start

git clone <repo> && cd zeek-ids-skeleton
make up
make demo  