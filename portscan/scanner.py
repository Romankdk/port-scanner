"""Core scanning logic: parse targets and ports, then run concurrent TCP (and UDP) scans."""

from __future__ import annotations

import errno
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Iterator, List, Optional, TypeVar

from . import fingerprint, tlscheck
from .results import HostResult, PortResult
from .services import describe, describe_name, max_risk
from .textutil import clean
from .udp import scan_udp_port

MAX_HOSTS = 1024  # refuse giant ranges by accident (a /22 at most)

# "Connection refused" means a host answered "nothing listening here".
REFUSED = {errno.ECONNREFUSED, 10061}  # 10061 is WSAECONNREFUSED on Windows

# Ports where a plain HTTP request is the right first move.
HTTP_PORTS = {80, 3000, 5000, 7000, 8000, 8080}

# Never send probe data here: printers print whatever arrives on their raw ports (JetDirect).
NO_PROBE_PORTS = {9100, 9101, 9102}

T = TypeVar("T")
R = TypeVar("R")


def parse_ports(spec: str) -> list[int]:
    """Parse "22,80,8000-8010" into a sorted, de-duplicated list of ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"bad port range {part!r}: start is after end")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port {p} is out of range 1-65535")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def parse_targets(spec: str) -> list[str]:
    """Expand "192.168.1.0/24", "10.0.0.5" or "example.local" into a list of hosts."""
    hosts: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            if net.version != 4:
                raise ValueError(f"{part}: only IPv4 ranges are supported")
            # Check size before expanding so a /8 doesn't build millions of strings.
            if len(hosts) + net.num_addresses > MAX_HOSTS + 2:
                raise ValueError(f"{part} has {net.num_addresses} addresses, over the limit of {MAX_HOSTS}; narrow the range")
            members = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
            hosts.extend(members)
        else:
            hosts.append(part)
    if not hosts:
        raise ValueError("no targets given")
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"{len(hosts)} hosts is more than the limit of {MAX_HOSTS}; narrow the range")
    return hosts


def local_network() -> str:
    """This computer's local network, e.g. "192.168.1.0/24" (assumes the usual /24 home network)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connecting a UDP socket sends nothing; it just asks the OS which interface it would use.
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
    except OSError:
        ip = ""
    if not ip or ip.startswith(("127.", "0.")):
        raise ValueError("could not detect your network (are you connected?); give an address like 192.168.1.0/24")
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def expand_auto(spec: str) -> str:
    """Replace the word "auto" in a target list with this computer's network."""
    parts = [p.strip() for p in spec.split(",")]
    return ",".join(local_network() if p.lower() == "auto" else p for p in parts if p)


def resolve(host: str) -> str:
    """Resolve a hostname to an IPv4 address (raises socket.gaierror if it can't)."""
    return socket.gethostbyname(host)


def safe_workers(requested: int) -> int:
    """Cap concurrency below the open-file limit so sockets don't fail with EMFILE."""
    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY:
            return max(1, min(requested, soft - 32))
    except (ImportError, OSError, ValueError):
        pass
    return max(1, requested)


def pmap(fn: Callable[[T], R], items: List[T], workers: int) -> Iterator[R]:
    """Thread-pool map that stops promptly (cancelling queued work) if interrupted."""
    if not items:
        return
    pool = ThreadPoolExecutor(max_workers=max(1, min(safe_workers(workers), len(items))))
    finished = False
    try:
        yield from pool.map(fn, items)
        finished = True
    finally:
        pool.shutdown(wait=finished, cancel_futures=True)


def banner_text(raw: bytes) -> str:
    """A one-line, printable summary of a service's response."""
    text = raw.decode("utf-8", errors="replace")
    lines = [clean(ln).strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    # For HTTP keep the status line and Server header; otherwise the first line.
    if lines and lines[0].startswith("HTTP/"):
        server = next((ln for ln in lines if ln.lower().startswith("server:")), "")
        return f"{lines[0]} {server}".strip()
    return lines[0][:120] if lines else ""


def read_initial(sock: socket.socket, port: int, timeout: float) -> bytes:
    """Read whatever the service says first; nudge HTTP-ish ports with a HEAD request."""
    sock.settimeout(timeout)
    try:
        if port in HTTP_PORTS:
            sock.sendall(fingerprint.HTTP_PROBE)
        return sock.recv(512)
    except OSError:
        return b""


def scan_port(ip: str, port: int, timeout: float = 1.0, banners: bool = True) -> PortResult:
    """TCP connect scan of one port, then (if open) work out what is listening."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as e:
        raise RuntimeError(f"could not open a socket ({e}); lower --workers") from e
    with sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
        except OSError:
            return PortResult(port, "filtered")
        if code != 0:
            # Refused means closed; anything else (timeout, unreachable) means we couldn't tell.
            return PortResult(port, "closed" if code in REFUSED else "filtered")
        raw = b""
        if banners and port not in tlscheck.TLS_PORTS and port not in NO_PROBE_PORTS:
            raw = read_initial(sock, port, timeout)

    service, risk, note = describe(port)
    result = PortResult(port, "open", service, risk, note)
    if not banners or port in NO_PROBE_PORTS:
        return result

    sent = fingerprint.HTTP_PROBE if port in HTTP_PORTS else b""
    is_tls = port in tlscheck.TLS_PORTS
    if not raw and not is_tls:
        # Silent service: is it TLS? If not, try our probes on fresh connections.
        is_tls = tlscheck.is_tls(ip, port, timeout)
        if not is_tls:
            sent, raw = fingerprint.probe(ip, port, timeout)

    # Binary protocol replies (like PostgreSQL's one-byte answer) aren't useful as a banner.
    result.banner = "" if sent == fingerprint.POSTGRES_SSL_REQUEST else banner_text(raw)
    if is_tls:
        result.tls = {}  # filled in by the TLS check
        if service == "unknown":
            match = ("tls", "")
        else:
            match = None
    else:
        match = fingerprint.identify(raw, sent)
    if match:
        ident, product = match
        result.product = clean(product)
        # Printers, Chromecasts and many devices speak HTTP; "http" doesn't contradict a known service.
        speaks_http = ident == "http" and service != "unknown"
        if ident not in service.split("/") and ident != service and not speaks_http:
            result.service = ident
            result.identified = True
            result.risk, ident_note = describe_name(ident)
            result.note = f"Identified as {ident} from its response (port {port} usually means {service}). {ident_note}"
    return result


def apply_tls(result: PortResult, info: dict) -> None:
    result.tls = info
    for risk, issue in info.get("issues", []):
        result.issues.append(issue)
        result.risk = max_risk(result.risk, risk)
    if info.get("version") and not result.banner:
        result.banner = f"{info['version']} {info.get('subject', '')}".strip()


def scan_host(
    host: str,
    ip: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 200,
    banners: bool = True,
    tls: bool = True,
    udp_ports: Optional[Iterable[int]] = None,
) -> HostResult:
    """Scan one host. On Ctrl-C, returns partial results with interrupted=True."""
    result = HostResult(host=host, ip=ip)
    start = time.monotonic()

    def record(r: PortResult) -> None:
        result.scanned += 1
        if r.state == "open":
            result.open_ports.append(r)
        elif r.state == "closed":
            result.closed += 1
        else:
            result.filtered += 1

    try:
        for r in pmap(lambda p: scan_port(ip, p, timeout, banners), ports, workers):
            record(r)

        if tls and banners:
            server_name = None if _is_ip(host) or host == "localhost" else host
            tls_ports = [p for p in result.open_ports if p.tls is not None]
            infos = pmap(lambda p: tlscheck.check(ip, p.port, server_name, max(timeout, 2.0)), tls_ports, workers)
            for p, info in zip(tls_ports, infos):
                apply_tls(p, info)

        for r in pmap(lambda p: scan_udp_port(ip, p, max(timeout, 1.0)), list(udp_ports or []), workers):
            record(r)
    except KeyboardInterrupt:
        result.interrupted = True
    result.open_ports.sort(key=lambda p: (p.protocol, p.port))
    result.seconds = round(time.monotonic() - start, 2)
    return result


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_is_up(ip: str, timeout: float = 0.5) -> bool:
    """Cheap liveness check: any answer (open or refused) on a few common ports means the host exists."""
    probes = [80, 443, 22, 445, 3389]
    states = pmap(lambda p: scan_port(ip, p, timeout, banners=False).state, probes, len(probes))
    return any(s in ("open", "closed") for s in states)


def discover(ips: list[str], timeout: float = 0.5, workers: int = 50) -> set[str]:
    """Check many hosts for liveness in parallel; return the ones that answered."""
    alive = pmap(lambda ip: host_is_up(ip, timeout), ips, max(1, safe_workers(workers) // 5))
    return {ip for ip, up in zip(ips, alive) if up}
