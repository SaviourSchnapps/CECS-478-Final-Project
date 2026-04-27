#!/usr/bin/env bash
# Snapshot the current artifacts/release/ into a timestamped subfolder.
# Useful before re-running the demo so prior runs aren't overwritten.

set -euo pipefail

RELEASE="artifacts/release"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$RELEASE/runs/$TS"

if [[ ! -d "$RELEASE" ]]; then
    echo "no release dir at $RELEASE — nothing to snapshot" >&2
    exit 1
fi

mkdir -p "$DEST"
shopt -s nullglob
for f in "$RELEASE"/*.csv "$RELEASE"/*.json "$RELEASE"/*.png "$RELEASE"/*.log; do
    [[ -e "$f" ]] || continue
    cp "$f" "$DEST/"
done

# Also include the pcap and zeek logs for traceability
[[ -f "pcaps/sample/demo.pcap" ]] && cp "pcaps/sample/demo.pcap" "$DEST/"
[[ -d "zeek/logs" ]] && cp -r "zeek/logs" "$DEST/zeek-logs"

echo "snapshot written to $DEST"
ls -la "$DEST"
