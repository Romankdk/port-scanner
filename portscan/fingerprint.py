"""Identify a service from what it sends back, instead of trusting the port number."""

from __future__ import annotations

import re
import socket
from typing import Optional, Tuple

# Sent to silent services, in order, until one answers.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"
POSTGRES_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
PROBES = [HTTP_PROBE, POSTGRES_SSL_REQUEST]

Match = Optional[Tuple[str, str]]  # (service, product/version detail)


def _http(text: str) -> Match:
    lines = text.splitlines()
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    server = headers.get("server", "")
    if "airtunes" in server.lower():
        return "airplay", server
    if "elastic" in headers.get("x-elastic-product", "").lower():
        return "elasticsearch", server
    return "http", server


def identify(raw: bytes, probe: bytes = b"") -> Match:
    """Match a response against known service signatures. `probe` is what we sent (if anything)."""
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    first = text.splitlines()[0].strip() if text.strip() else ""

    if text.startswith("SSH-"):
        return "ssh", first[4:]
    if text.startswith("HTTP/"):
        return _http(text)
    if text.startswith("RFB "):
        return "vnc", first
    if text.startswith("AMQP"):
        return "rabbitmq", ""
    if text.startswith("+OK"):
        return "pop3", first[3:].strip()
    if text.startswith("* OK"):
        return "imap", first[4:].strip()
    if first.startswith("220"):
        lowered = first.lower()
        if "smtp" in lowered:
            return "smtp", first[4:]
        return "ftp", first[4:]
    if text.startswith("-ERR") and "command" in text.lower() or text.startswith(("+PONG", "-NOAUTH", "-DENIED")):
        return "redis", ""
    if first == "ERROR":
        return "memcached", ""
    # MySQL greeting: 3-byte length, sequence 0, protocol 10, then a NUL-terminated version.
    if len(raw) > 6 and raw[3] == 0 and raw[4] == 0x0A:
        version = raw[5:raw.find(b"\x00", 5)].decode("ascii", errors="replace")
        if re.match(r"\d+\.\d+", version):
            return ("mariadb" if "mariadb" in version.lower() else "mysql"), version
    if b"is not allowed to connect to this MySQL server" in raw or b"MariaDB" in raw:
        return "mysql", ""
    if probe == POSTGRES_SSL_REQUEST and raw[:1] in (b"S", b"N"):
        return "postgresql", "TLS supported" if raw[:1] == b"S" else "TLS not offered"
    return None


def probe(ip: str, port: int, timeout: float) -> Tuple[bytes, bytes]:
    """Send each probe on a fresh connection; return (probe, response) for the first that answers."""
    for payload in PROBES:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(payload)
                data = s.recv(512)
        except OSError:
            continue
        if data:
            return payload, data
    return b"", b""
