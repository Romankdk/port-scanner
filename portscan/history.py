"""Save scans to disk and compare a new scan with the previous one."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .results import HostResult, PortResult
from .services import RISK_ORDER

DEFAULT_DIR = Path.home() / ".portscan"


def slug(targets: str) -> str:
    """A filesystem-safe folder name for a target spec, unique per spec."""
    readable = re.sub(r"[^A-Za-z0-9.]+", "_", targets).strip("_")[:40]
    digest = hashlib.sha1(targets.encode()).hexdigest()[:8]
    return f"{readable}-{digest}"


def scan_dir(base: Path, targets: str) -> Path:
    return base / "history" / slug(targets)


def save(base: Path, targets: str, tcp_ports: List[int], udp_ports: List[int],
         results: List[HostResult], options: Optional[dict] = None, when: Optional[datetime] = None) -> Path:
    when = when or datetime.now()
    folder = scan_dir(base, targets)
    folder.mkdir(parents=True, exist_ok=True)
    doc = {
        "version": 1,
        "time": when.isoformat(timespec="seconds"),
        "targets": targets,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "options": options or {},
        # An interrupted scan, or one where nothing answered (network down?), must not become a baseline.
        "partial": not results or any(h.interrupted for h in results),
        "hosts": [h.to_dict() for h in results],
    }
    path = folder / f"{when.strftime('%Y%m%d-%H%M%S-%f')}.json"
    path.write_text(json.dumps(doc, indent=2))
    return path


def recent(base: Path, targets: str, limit: int = 7) -> List[dict]:
    """Up to `limit` complete saved scans of these targets, newest first."""
    docs = []
    for path in sorted(scan_dir(base, targets).glob("*.json"), reverse=True):
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not doc.get("partial"):
            docs.append(doc)
            if len(docs) >= limit:
                break
    return docs


def latest(base: Path, targets: str) -> Optional[dict]:
    """The most recent complete saved scan of these targets."""
    docs = recent(base, targets, 1)
    return docs[0] if docs else None


@dataclass
class Change:
    kind: str  # new-host, gone-host, back-host, opened, closed, new-issue, fixed-issue, service-changed
    ip: str
    label: str  # host name or ip, for display
    port: str = ""  # e.g. "443/tcp"
    detail: str = ""
    risk: str = "info"

    @property
    def is_alert(self) -> bool:
        return self.kind in ("new-host", "opened", "new-issue", "service-changed")


@dataclass
class Diff:
    previous_time: str
    changes: List[Change] = field(default_factory=list)

    @property
    def alerts(self) -> List[Change]:
        return [c for c in self.changes if c.is_alert]


def _describe(p: PortResult) -> str:
    return p.service + (f" ({p.product})" if p.product else "")


def _tls_checked(p: PortResult) -> bool:
    return bool(p.tls and p.tls.get("version"))


def compare(prev: dict, results: List[HostResult], tcp_ports: List[int], udp_ports: List[int],
            options: Optional[dict] = None, older: Optional[List[dict]] = None) -> Diff:
    """What changed since `prev`? Only ports scanned both times are compared.

    `older` are earlier saved scans: a device missing from `prev` but seen in one of them
    is compared with that sighting instead of being reported as brand new.
    """
    comparable = {f"{p}/tcp" for p in set(prev.get("tcp_ports", [])) & set(tcp_ports)}
    comparable |= {f"{p}/udp" for p in set(prev.get("udp_ports", [])) & set(udp_ports)}
    # Service names and TLS findings only mean the same thing if both scans looked for them.
    same_depth = prev.get("options", {}) == (options or {})
    before = {h["ip"]: HostResult.from_dict(h) for h in prev.get("hosts", [])}
    seen_earlier = {}
    for doc in older or []:
        for h in doc.get("hosts", []):
            seen_earlier.setdefault(h["ip"], HostResult.from_dict(h))
    after = {h.ip: h for h in results}
    diff = Diff(previous_time=prev.get("time", "?"))
    add = diff.changes.append

    for ip, h in after.items():
        label = h.name or h.host
        if ip not in before and ip in seen_earlier:
            add(Change("back-host", ip, label, detail="responding again after missing the last scan"))
            before[ip] = seen_earlier[ip]
        if ip not in before:
            if h.open_ports:
                worst = max((p.risk for p in h.open_ports), key=lambda r: RISK_ORDER[r])
                ports = ", ".join(p.key for p in h.open_ports)
                add(Change("new-host", ip, label, detail=f"new device with open ports {ports}", risk=worst))
            continue
        old = {p.key: p for p in before[ip].open_ports}
        new = {p.key: p for p in h.open_ports}
        for key in sorted(set(new) - set(old)):
            if key in comparable:
                p = new[key]
                add(Change("opened", ip, label, key, f"{_describe(p)} is now open", p.risk))
        for key in sorted(set(old) - set(new)):
            if key in comparable and not h.interrupted:
                add(Change("closed", ip, label, key, f"{_describe(old[key])} is no longer open"))
        for key in sorted(set(old) & set(new)) if same_depth else []:
            o, n = old[key], new[key]
            if (o.service, o.product) != (n.service, n.product):
                add(Change("service-changed", ip, label, key, f"{_describe(o)} -> {_describe(n)}", n.risk))
            if not (_tls_checked(o) and _tls_checked(n)):
                continue  # one of the TLS checks failed or didn't run; no evidence either way
            for issue in n.issues:
                if issue not in o.issues:
                    add(Change("new-issue", ip, label, key, issue, n.risk))
            for issue in o.issues:
                if issue not in n.issues:
                    add(Change("fixed-issue", ip, label, key, issue))

    for ip, h in before.items():
        if ip not in after and h.open_ports:
            add(Change("gone-host", ip, h.name or h.host, detail="device did not respond this time"))
    return diff


SYMBOLS = {"new-host": "+", "opened": "+", "new-issue": "!", "service-changed": "~",
           "closed": "-", "gone-host": "-", "fixed-issue": "v", "back-host": "~"}


def render_text(diff: Diff) -> str:
    if not diff.changes:
        return f"No changes since the last scan ({diff.previous_time})."
    lines = [f"Changes since the last scan ({diff.previous_time}):"]
    for c in diff.changes:
        where = f"{c.label} {c.port}".strip()
        lines.append(f"  {SYMBOLS[c.kind]} {where}: {c.detail}")
    return "\n".join(lines)
