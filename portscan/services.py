"""Known services for common ports, with a short risk note for each."""

from __future__ import annotations

# port -> (service name, risk level, note)
SERVICES: dict[int, tuple[str, str, str]] = {
    21: ("ftp", "high", "FTP sends credentials in plaintext; prefer SFTP."),
    22: ("ssh", "low", "Fine if key-only auth is enforced and root login is disabled."),
    23: ("telnet", "high", "Telnet is unencrypted; disable it and use SSH."),
    25: ("smtp", "medium", "Check it is not an open relay."),
    53: ("dns", "medium", "Make sure recursion is not open to the internet."),
    80: ("http", "medium", "Unencrypted web traffic; redirect to HTTPS."),
    110: ("pop3", "medium", "Plaintext mail retrieval; prefer POP3S (995)."),
    111: ("rpcbind", "high", "Leaks RPC service info; should not be exposed."),
    135: ("msrpc", "high", "Windows RPC; frequent attack target, block externally."),
    139: ("netbios-ssn", "high", "Legacy Windows file sharing; block externally."),
    143: ("imap", "medium", "Plaintext mail access; prefer IMAPS (993)."),
    443: ("https", "low", "Encrypted web; check the TLS configuration and certificate."),
    445: ("smb", "high", "SMB is a common ransomware entry point; never expose publicly."),
    993: ("imaps", "low", "Encrypted IMAP."),
    995: ("pop3s", "low", "Encrypted POP3."),
    1433: ("mssql", "high", "Database should not be reachable from untrusted networks."),
    1521: ("oracle", "high", "Database should not be reachable from untrusted networks."),
    2049: ("nfs", "high", "Network file shares; restrict by host and firewall."),
    3000: ("dev-server", "medium", "Often a development server; don't leave it exposed."),
    3306: ("mysql", "high", "Database should not be reachable from untrusted networks."),
    3389: ("rdp", "high", "Remote Desktop is heavily brute-forced; use a VPN or gateway."),
    5000: ("dev-server/airplay", "medium", "Dev server or macOS AirPlay receiver; check what is listening."),
    5432: ("postgresql", "high", "Database should not be reachable from untrusted networks."),
    5900: ("vnc", "high", "VNC often has weak auth; tunnel it over SSH or a VPN."),
    6379: ("redis", "critical", "Redis has no auth by default; exposed instances get compromised fast."),
    7000: ("airplay", "low", "macOS AirPlay receiver; disable in System Settings if unused."),
    8000: ("http-alt", "medium", "Often a development server; don't leave it exposed."),
    8080: ("http-proxy", "medium", "Alternate HTTP or proxy; confirm it is intended."),
    8443: ("https-alt", "low", "Alternate HTTPS; check the TLS configuration."),
    9200: ("elasticsearch", "critical", "Unauthenticated Elasticsearch leaks data; restrict access."),
    11211: ("memcached", "critical", "Abused for DDoS amplification and data leaks; bind to localhost."),
    27017: ("mongodb", "critical", "Exposed MongoDB is a classic data-breach source; enable auth."),
}

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A sensible default set: every port we have notes for.
COMMON_PORTS: list[int] = sorted(SERVICES)

# Services we can recognize from their responses, for when they run on an unexpected port.
BY_NAME: dict[str, tuple[str, str]] = {name: (risk, note) for name, risk, note in SERVICES.values()}
BY_NAME.update({
    "http": SERVICES[80][1:],
    "https": SERVICES[443][1:],
    "airplay": SERVICES[7000][1:],
    "tls": ("low", "Encrypted service of unknown type; check the certificate findings."),
    "rabbitmq": ("high", "Message broker; should not be reachable from untrusted networks."),
})


def describe(port: int) -> tuple[str, str, str]:
    """Return (service, risk, note) for a port, with a neutral fallback for unknown ports."""
    return SERVICES.get(port, ("unknown", "info", "Unrecognized service; identify what is listening."))


def describe_name(service: str) -> tuple[str, str]:
    """Return (risk, note) for a service identified by its response."""
    return BY_NAME.get(service, ("info", "Identify what this service is and whether it should be exposed."))


def max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: RISK_ORDER.get(r, 0))
