"""UDP scanning: send each service a request it understands and see whether it answers."""

from __future__ import annotations

import socket
import struct

from . import dnsutil
from .results import PortResult
from .textutil import clean

# SNMPv1 GetRequest for sysDescr.0 using the default community "public".
SNMP_GET_PUBLIC = bytes.fromhex(
    "302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500"
)
# NetBIOS node status request for the wildcard name "*".
NETBIOS_STATUS = (
    struct.pack(">HHHHHH", 0x5053, 0, 1, 0, 0, 0)
    + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    + struct.pack(">HH", 0x21, 1)
)


def _ssdp(ip: str) -> bytes:
    return (
        f"M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    ).encode()


# port -> (service, risk if it answers, note, payload builder)
UDP_SERVICES = {
    53: ("dns", "medium", "DNS server; make sure it does not answer recursive queries for the internet.",
         lambda ip: dnsutil.build_query(".", dnsutil.NS)),
    69: ("tftp", "high", "TFTP has no authentication; anyone can read (and maybe write) files.",
         lambda ip: b"\x00\x01portscan-probe\x00octet\x00"),
    123: ("ntp", "low", "Time server; keep it patched (old versions allow DDoS amplification).",
          lambda ip: b"\x1b" + b"\x00" * 47),
    137: ("netbios-ns", "high", "Windows name service leaks the computer and user names; block externally.",
          lambda ip: NETBIOS_STATUS),
    161: ("snmp", "high", "SNMP exposes device configuration; disable it or use SNMPv3.",
          lambda ip: SNMP_GET_PUBLIC),
    1900: ("ssdp/upnp", "medium", "UPnP discovery; can be abused for DDoS and to open router ports.",
           lambda ip: _ssdp(ip)),
    5353: ("mdns", "low", "Bonjour/mDNS announces device names and services on the local network.",
           lambda ip: dnsutil.build_query("_services._dns-sd._udp.local", dnsutil.PTR, recursion=False, unicast_response=True)),
}
UDP_COMMON_PORTS = sorted(UDP_SERVICES)


def _summarize(port: int, data: bytes) -> tuple[str, str, str]:
    """Return (banner, extra risk, extra note) for a UDP reply."""
    if port == 161:
        return ("Answers to community 'public'", "critical",
                "SNMP answers to the default community 'public'; change it or disable SNMP.")
    if port == 53 and dnsutil.recursion_available(data):
        return ("Recursion available", "high",
                "DNS server offers recursion; if reachable from the internet it is an open resolver.")
    if port == 1900:
        text = data.decode("utf-8", errors="replace")
        server = next((ln.strip() for ln in text.splitlines() if ln.lower().startswith("server:")), "")
        return clean(server), "", ""
    return f"{len(data)}-byte reply", "", ""


def scan_udp_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    service, risk, note, build = UDP_SERVICES.get(
        port, ("unknown", "info", "Unrecognized UDP service; identify what is listening.", lambda ip: b"\r\n")
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        raise RuntimeError(f"could not open a socket ({e}); lower --workers") from e
    with sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            sock.send(build(ip))
            data = sock.recv(4096)
        except ConnectionRefusedError:
            return PortResult(port, "closed", protocol="udp")  # ICMP port unreachable
        except OSError:
            # No reply: the port may be open but silent, or filtered. UDP can't tell these apart.
            return PortResult(port, "filtered", protocol="udp")
    banner, extra_risk, extra_note = _summarize(port, data)
    if extra_risk:
        risk, note = extra_risk, extra_note
    return PortResult(port, "open", service, risk, note, banner, protocol="udp")
