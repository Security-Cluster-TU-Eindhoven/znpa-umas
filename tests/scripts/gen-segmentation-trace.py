# Copyright (c) 2025-2026, Eindhoven University of Technology
# SPDX-License-Identifier: BSD-3-Clause

"""Generate tests/traces/umas_segmentation.pcap.

A synthetic Modbus/TCP trace exercising UMAS PDUs that are pipelined in one
segment, split across segments, mixed with other Modbus PDUs, or use an unknown
UMAS function code.

Usage: python3 gen-segmentation-trace.py ../traces/umas_segmentation.pcap
"""
import struct
import sys

CLI, SRV = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CPORT, SPORT = 40000, 502


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def mbap(tid, unit, pdu):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def umas(tid, key, sub, data=b""):
    return mbap(tid, 0, bytes([0x5A, key, sub]) + data)


class Flow:
    def __init__(self):
        self.seq = {True: 1000, False: 5000}
        self.ts = 1700000000.0
        self.pkts = []

    def pkt(self, from_cli, flags, payload=b""):
        src, dst = (CLI, SRV) if from_cli else (SRV, CLI)
        sp, dp = (CPORT, SPORT) if from_cli else (SPORT, CPORT)
        seq, ack = self.seq[from_cli], self.seq[not from_cli]
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        eth = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" if from_cli else b"\x02\0\0\0\0\x01" + b"\x02\0\0\0\0\x02"
        self.pkts.append((self.ts, eth + b"\x08\x00" + ip + tcp + payload))
        self.seq[from_cli] += len(payload) + (1 if flags & 0x03 else 0)
        self.ts += 0.01

    def data(self, from_cli, payload):
        self.pkt(from_cli, 0x18, payload)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, p in self.pkts:
                f.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(p), len(p)) + p)


f = Flow()
f.pkt(True, 0x02)
f.pkt(False, 0x12)
f.pkt(True, 0x10)

# Two pipelined UMAS requests in one segment, two responses in one segment.
f.data(True, umas(1, 0x00, 0x02) + umas(2, 0x00, 0x0A, b"\x01\x02"))
f.data(False, umas(1, 0x00, 0xFE, b"\x00" * 8) + umas(2, 0x00, 0xFE, b"\x01\x02"))

# UMAS request split across two segments (header split).
req = umas(3, 0x00, 0x10, b"\x00\x00\x0aENG-STATION")
f.data(True, req[:5])
f.data(True, req[5:])
f.data(False, umas(3, 0x00, 0xFE, b"\x42"))

# Standard Modbus PDU followed by a UMAS PDU in the same segment.
f.data(True, mbap(4, 1, b"\x03\x00\x00\x00\x01") + umas(5, 0x42, 0x20, b"\x00\x00\x00\x00\x00\x00\x10"))
f.data(False, mbap(4, 1, b"\x03\x02\x00\x07") + umas(5, 0x42, 0xFE, b"\x00" * 16))

# Unknown UMAS sub-function code (0x99 = 153).
f.data(True, umas(6, 0x42, 0x99))
f.data(False, umas(6, 0x42, 0xFD, b"\x01"))

f.pkt(True, 0x11)
f.pkt(False, 0x11)
f.pkt(True, 0x10)
f.write(sys.argv[1])
