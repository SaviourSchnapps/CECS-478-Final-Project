"""Generate a deterministic demo pcap with port-scan and DoS traffic.

Pure stdlib. Writes Ethernet + IPv4 + TCP SYN packets in libpcap format
(little-endian on disk, network byte order in protocol headers as required).
No protocol-level HTTP/SSH synthesis — those are exercised by analyzer
tests via notice.log fixtures.
"""

from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _mac(b: int) -> bytes:
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, b])


def _ip(s: str) -> bytes:
    return bytes(int(p) for p in s.split("."))


def _tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int) -> bytes:
    ihl_ver = (4 << 4) | 5
    tos = 0
    total_len = 40
    ident = 0
    flags_frag = 0x4000
    ttl = 64
    proto = 6
    ip_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, tos, total_len, ident, flags_frag, ttl, proto, 0,
        _ip(src_ip), _ip(dst_ip),
    )
    ip_csum = _checksum(ip_no_csum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, tos, total_len, ident, flags_frag, ttl, proto, ip_csum,
        _ip(src_ip), _ip(dst_ip),
    )

    data_off_flags = (5 << 12) | 0x02  # SYN
    pseudo = struct.pack("!4s4sBBH", _ip(src_ip), _ip(dst_ip), 0, proto, 20)
    tcp_no_csum = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, 0, data_off_flags, 65535, 0, 0
    )
    tcp_csum = _checksum(pseudo + tcp_no_csum)
    tcp = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, 0, data_off_flags, 65535, tcp_csum, 0
    )

    eth = _mac(0xAA) + _mac(0xBB) + struct.pack("!H", 0x0800)
    return eth + ip_header + tcp


def write_pcap(path: Path, *, scan_ports: int = 20, flood_count: int = 250,
               base_ts: int | None = None) -> dict:
    scanner_a = "10.0.0.5"
    scanner_b = "10.0.0.7"
    flooder = "10.0.0.6"
    target = "10.0.0.10"
    if base_ts is None:
        base_ts = int(time.time())

    records: list[tuple[int, int, bytes]] = []
    seq = 1000

    for i in range(scan_ports):
        pkt = _tcp_syn(scanner_a, target, 50000 + i, 1 + i, seq)
        seq += 1
        records.append((base_ts + i // 5, (i % 5) * 10_000, pkt))

    scan_b_start = base_ts + 10
    for i in range(scan_ports):
        pkt = _tcp_syn(scanner_b, target, 51000 + i, 100 + i, seq)
        seq += 1
        records.append((scan_b_start + i // 5, (i % 5) * 10_000, pkt))

    flood_start = base_ts + 30
    for i in range(flood_count):
        pkt = _tcp_syn(flooder, target, 40000 + (i % 1000), 80, seq)
        seq += 1
        records.append((flood_start + i // 50, (i % 50) * 1_000, pkt))

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts_sec, ts_usec, payload in records:
            n = len(payload)
            fh.write(struct.pack("<IIII", ts_sec, ts_usec, n, n))
            fh.write(payload)

    return {"path": str(path), "scan_ports": scan_ports, "flood_count": flood_count,
            "total_packets": len(records)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("/pcaps/sample/demo.pcap"))
    parser.add_argument("--scan-ports", type=int, default=20)
    parser.add_argument("--flood-count", type=int, default=250)
    parser.add_argument("--base-ts", type=int, default=None,
                        help="Unix epoch seconds to use as the first packet ts. "
                             "Default: current time. Pass a fixed value for "
                             "deterministic output (e.g. CI snapshots).")
    args = parser.parse_args(argv)
    info = write_pcap(args.out, scan_ports=args.scan_ports,
                      flood_count=args.flood_count, base_ts=args.base_ts)
    print(f"wrote {info['total_packets']} packets to {info['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
