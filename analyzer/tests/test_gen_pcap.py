"""Smoke tests for the pcap generator."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

# tools/ is a sibling of analyzer/ — add it to path explicitly
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

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
    assert info["total_packets"] == 270
    records = _read_records(out)
    assert len(records) == 270


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
    dst_ports = set()
    for _, _, payload in records:
        # TCP dst port is at offset eth(14) + ip(20) + 2
        dst_ports.add(struct.unpack("!H", payload[14 + 20 + 2:14 + 20 + 4])[0])
    assert len(dst_ports) == 15


def test_pcap_zero_packets_still_writes_valid_header(tmp_path: Path):
    out = tmp_path / "empty.pcap"
    info = gen_pcap.write_pcap(out, scan_ports=0, flood_count=0)
    assert info["total_packets"] == 0
    assert _read_records(out) == []
