"""Find friendly device names ("Romans-iPhone.local", "HP-PRINTER") for IP addresses."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

from . import dnsutil
from .textutil import clean


def _reverse_arpa(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def mdns_name(ip: str, timeout: float = 0.6) -> Optional[str]:
    """Ask the device itself over mDNS (Apple devices, most Linux, many printers and smart TVs)."""
    query = dnsutil.build_query(_reverse_arpa(ip), dnsutil.PTR, recursion=False, unicast_response=True)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (ip, 5353))
            data, _ = s.recvfrom(4096)
        return dnsutil.first_ptr(data)
    except (OSError, ValueError, struct.error):
        return None


def netbios_name(ip: str, timeout: float = 0.6) -> Optional[str]:
    """Ask a Windows (or Samba) machine for its computer name."""
    from .udp import NETBIOS_STATUS

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(NETBIOS_STATUS, (ip, 137))
            data, _ = s.recvfrom(4096)
    except OSError:
        return None
    # Header (12) + answer name (34) + type/class/ttl/rdlength (10), then the name count and 18-byte entries.
    offset = 56
    if len(data) <= offset:
        return None
    for i in range(data[offset]):
        entry = data[offset + 1 + i * 18: offset + 1 + (i + 1) * 18]
        if len(entry) < 18:
            break
        name, suffix, flags = entry[:15], entry[15], struct.unpack(">H", entry[16:18])[0]
        if suffix == 0x00 and not flags & 0x8000:  # workstation name, not a group
            return name.decode("ascii", errors="replace").strip()
    return None


def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Ask the network's DNS server (home routers often know DHCP client names)."""
    result: list = []

    def lookup() -> None:
        try:
            result.append(socket.gethostbyaddr(ip)[0])
        except OSError:
            pass

    t = threading.Thread(target=lookup, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else None


def lookup(ip: str, timeout: float = 0.6) -> str:
    """Try each method, best names first. Returns "" if nothing knows this device."""
    for method in (mdns_name, netbios_name, reverse_dns):
        try:
            name = method(ip, timeout)
        except Exception:  # replies come from arbitrary devices; never let one crash the scan
            name = None
        if name:
            name = clean(name).rstrip(".")
            if name and name != ip:
                return name
    return ""
