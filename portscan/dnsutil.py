"""Just enough DNS wire format to build queries and read names out of answers."""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

PTR = 12
NS = 2


def encode_name(name: str) -> bytes:
    labels = [label for label in name.rstrip(".").split(".") if label]
    return b"".join(bytes([len(lb)]) + lb.encode() for lb in labels) + b"\x00"


def build_query(name: str, qtype: int, tid: int = 0x5053, recursion: bool = True, unicast_response: bool = False) -> bytes:
    flags = 0x0100 if recursion else 0
    qclass = 0x8001 if unicast_response else 0x0001
    return struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", qtype, qclass)


def read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Read a possibly-compressed name; return (name, offset just past it)."""
    labels: List[str] = []
    end = None
    for _ in range(128):  # guard against pointer loops
        if offset >= len(data):
            raise ValueError("name runs past end of packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated compression pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels), (end if end is not None else offset)
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    raise ValueError("too many labels or pointer loop")


def answers(data: bytes) -> List[Tuple[str, int, int, int]]:
    """Return (name, type, rdata_offset, rdata_length) for each answer record."""
    if len(data) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4
    out = []
    for _ in range(an):
        name, offset = read_name(data, offset)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        out.append((name, rtype, offset, rdlen))
        offset += rdlen
    return out


def first_ptr(data: bytes) -> Optional[str]:
    for _, rtype, rdata, _ in answers(data):
        if rtype == PTR:
            return read_name(data, rdata)[0]
    return None


def recursion_available(data: bytes) -> bool:
    return len(data) >= 4 and bool(data[3] & 0x80)
