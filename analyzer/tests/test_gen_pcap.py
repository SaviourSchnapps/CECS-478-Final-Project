"""Smoke tests for the pcap generator."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

# tools/ is a sibling of analyzer/ in the repo, but the dev container only
# ships the analyzer/ subtree, so the suite is skipped there. Probe both layouts.
_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "tools",  # repo-root layout (local runs)
    Path("/tools"),                                  # mounted at /tools in CI/container
]
_TOOLS_DIR = next((p for p in _CANDIDATES if (p / "gen_pcap.py").exists()), None)
if _TOOLS_DIR is None:
    pytest.skip("gen_pcap.py not reachable in this layout", allow_module_level=True)
sys.path.insert(0, str(_TOOLS_DIR))

import gen_pcap  # noqa: E402

PCAP_LE_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def _read_records(path: Path):
    with path.open("rb") as fh:
        header = fh.read(24)
        magic, vmaj, vmin, _tz, _sig, snap, lt = struct.unpack("<IHHIIII", header)
        assert magic == PCAP_LE_MAGIC
        assert (vmaj, vmin) == (2, 4)
        assert lt == LINKTYPE_ETHERNET
        records = []
        while True:
            rh = fh.read(16)
            if not rh:
                break
            ts_s, ts_us, cap, orig = struct.unpack("<IIII", rh)
            payload = fh.read(cap)
            assert len(payload) == cap
            records.append((ts_s, ts_us, payload))
        return records


def test_default_pcap_has_expected_packet_count(tmp_path: Path):
    out = tmp_path / "demo.pcap"
    info = gen_pcap.write_pcap(out, scan_ports=20, flood_count=250)
    # two scanners (scan_ports each) + one flood
    assert info["total_packets"] == 2 * 20 + 250
    records = _read_records(out)
    assert len(records) == 2 * 20 + 250


def test_pcap_packets_are_tcp_syn(tmp_path: Path):
    out = tmp_path / "demo.pcap"
    gen_pcap.write_pcap(out, scan_ports=5, flood_count=5)
    records = _read_records(out)
    for _, _, payload in records:
        # Eth(14) + IP(20) + TCP(20) = 54 bytes
        assert len(payload) == 54
        # IP proto byte at offset 14+9
        assert payload[14 + 9] == 6  # TCP
        # TCP flags byte (data offset+flags lower octet)
        flags_lo = payload[14 + 20 + 13]
        assert flags_lo & 0x02  # SYN bit set


def test_pcap_distinct_destination_ports_in_scan(tmp_path: Path):
    out = tmp_path / "demo.pcap"
    gen_pcap.write_pcap(out, scan_ports=15, flood_count=0)
    records = _read_records(out)
    # two scanners, each hitting `scan_ports` distinct destination ports
    assert len(records) == 2 * 15
    by_src = {}
    for _, _, payload in records:
        src_ip = ".".join(str(b) for b in payload[14 + 12:14 + 16])
        dst_port = struct.unpack("!H", payload[14 + 20 + 2:14 + 20 + 4])[0]
        by_src.setdefault(src_ip, set()).add(dst_port)
    assert len(by_src) == 2
    for ports in by_src.values():
        assert len(ports) == 15


def test_pcap_zero_packets_still_writes_valid_header(tmp_path: Path):
    out = tmp_path / "empty.pcap"
    info = gen_pcap.write_pcap(out, scan_ports=0, flood_count=0)
    assert info["total_packets"] == 0
    assert _read_records(out) == []
