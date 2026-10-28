"""Result types shared by the scanner, reports and scan history."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed" or "filtered"
    service: str = ""
    risk: str = "info"
    note: str = ""
    banner: str = ""
    protocol: str = "tcp"
    product: str = ""  # software/version learned from the service's response
    identified: bool = False  # service name came from its response, not the port number
    tls: Optional[dict] = None
    issues: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass
class HostResult:
    host: str
    ip: str
    name: str = ""  # device name from mDNS / NetBIOS / reverse DNS
    open_ports: List[PortResult] = field(default_factory=list)
    scanned: int = 0
    closed: int = 0
    filtered: int = 0
    hidden: int = 0  # open ports dropped by --min-risk
    interrupted: bool = False
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "HostResult":
        known = {f for f in cls.__dataclass_fields__}
        ports = [PortResult(**{k: v for k, v in p.items() if k in PortResult.__dataclass_fields__})
                 for p in d.get("open_ports", [])]
        return cls(**{**{k: v for k, v in d.items() if k in known}, "open_ports": ports})
