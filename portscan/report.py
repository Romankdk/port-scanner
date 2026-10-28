"""Render scan results as a terminal report, JSON, or a self-contained HTML page."""

from __future__ import annotations

import html
import json
import sys
from datetime import datetime
from typing import List, Optional

from .history import SYMBOLS, Diff
from .results import HostResult
from .services import RISK_ORDER

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[32m", "info": "\033[36m"}
RESET = "\033[0m"


def _color(text: str, risk: str, enabled: bool) -> str:
    return f"{COLORS.get(risk, '')}{text}{RESET}" if enabled else text


def host_label(h: HostResult) -> str:
    label = h.host if h.host == h.ip else f"{h.host} ({h.ip})"
    return f"{label} - {h.name}" if h.name and h.name != h.host else label


def counts_line(h: HostResult) -> str:
    hidden = f" ({h.hidden} below --min-risk not shown)" if h.hidden else ""
    partial = " [interrupted, partial]" if h.interrupted else ""
    return (f"{h.scanned} ports scanned in {h.seconds}s{partial} - "
            f"{len(h.open_ports) + h.hidden} open{hidden}, {h.closed} closed, {h.filtered} filtered")


def render_text(results: List[HostResult], color: Optional[bool] = None) -> str:
    if color is None:
        color = sys.stdout.isatty()
    out: List[str] = []
    for h in results:
        out.append(f"\nHost: {host_label(h)}")
        out.append(f"  {counts_line(h)}")
        if not h.open_ports:
            out.append("  No open ports to show." if h.hidden else "  No open ports found.")
            continue
        out.append(f"  {'PORT':<11}{'SERVICE':<20}{'RISK':<10}DETAILS")
        for p in h.open_ports:
            risk = _color(f"{p.risk:<10}", p.risk, color)
            detail = p.product if p.product and p.product not in p.banner else ""
            detail = " | ".join(x for x in (p.banner, detail) if x)
            out.append(f"  {p.key:<11}{p.service:<20}{risk}{detail}")
        out.append("  Notes:")
        for p in sorted(h.open_ports, key=lambda p: -RISK_ORDER[p.risk]):
            out.append(f"   - {p.key} {p.service}: {p.note}")
            for issue in p.issues:
                out.append(f"       ! {issue}")
    out.append("")
    out.append(summary_line(results))
    return "\n".join(out)


def risk_counts(results: List[HostResult]) -> dict:
    counts = {k: 0 for k in RISK_ORDER}
    for h in results:
        for p in h.open_ports:
            counts[p.risk] += 1
    return counts


def summary_line(results: List[HostResult]) -> str:
    counts = risk_counts(results)
    parts = [f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: -RISK_ORDER[kv[0]]) if n]
    total = sum(counts.values())
    return f"Summary: {len(results)} host(s), {total} open port(s)" + (f" - {', '.join(parts)}" if parts else "")


def render_json(results: List[HostResult], diff: Optional[Diff] = None) -> str:
    hosts = [h.to_dict() for h in results]
    if diff is None:
        return json.dumps(hosts, indent=2)
    changes = [c.__dict__ for c in diff.changes]
    return json.dumps({"hosts": hosts, "changes": changes, "previous_scan": diff.previous_time}, indent=2)


# ---------------------------------------------------------------- HTML

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;
--critical:#b42318;--high:#d4380d;--medium:#b7791f;--low:#2f855a;--info:#2b6cb0;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--fg:#ecece8;--muted:#9a9a93;--line:#33332f;
--critical:#ff6b5e;--high:#ff8a4c;--medium:#e6b450;--low:#5fcf8f;--info:#6ba8ff;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:0}.muted{color:var(--muted)}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:24px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:110px}
.tile b{display:block;font-size:24px}.tile span{font-size:13px;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-top:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);border-top:0}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}
.low{background:var(--low)}.info{background:var(--info)}
.issue{color:var(--high);font-size:13px;margin-top:4px}code{font-size:13px}
ul.changes{list-style:none;padding:0;margin:8px 0 0}ul.changes li{padding:4px 0}
.sym{display:inline-block;width:1.4em;font-weight:700}
"""


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def render_html(results: List[HostResult], targets: str = "", diff: Optional[Diff] = None,
                when: Optional[datetime] = None) -> str:
    when = when or datetime.now()
    counts = risk_counts(results)
    total = sum(counts.values())
    parts = [f"<title>Port scan - {_e(targets)}</title>",
             f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{CSS}</style>",
             "<main>",
             f"<h1>Port scan report</h1><div class='muted'>{_e(targets)} &middot; {when:%Y-%m-%d %H:%M}</div>",
             "<div class='tiles'>",
             f"<div class='tile'><b>{len(results)}</b><span>hosts</span></div>",
             f"<div class='tile'><b>{total}</b><span>open ports</span></div>"]
    for risk in ("critical", "high", "medium", "low"):
        if counts[risk]:
            parts.append(f"<div class='tile'><b>{counts[risk]}</b><span class='badge {risk}'>{risk}</span></div>")
    parts.append("</div>")

    if diff is not None:
        parts.append(f"<section class='card'><h2>Changes since {_e(diff.previous_time)}</h2>")
        if diff.changes:
            parts.append("<ul class='changes'>")
            for c in diff.changes:
                badge = f" <span class='badge {c.risk}'>{c.risk}</span>" if c.is_alert else ""
                parts.append(f"<li><span class='sym'>{_e(SYMBOLS[c.kind])}</span>"
                             f"<b>{_e(c.label)}</b> {_e(c.port)}: {_e(c.detail)}{badge}</li>")
            parts.append("</ul>")
        else:
            parts.append("<p class='muted'>No changes.</p>")
        parts.append("</section>")

    for h in results:
        parts.append(f"<section class='card'><h2>{_e(host_label(h))}</h2><div class='muted'>{_e(counts_line(h))}</div>")
        if not h.open_ports:
            parts.append("<p class='muted'>No open ports found.</p></section>")
            continue
        parts.append("<div class='wrap'><table><tr><th>Port</th><th>Service</th><th>Risk</th><th>Details</th></tr>")
        for p in sorted(h.open_ports, key=lambda p: (-RISK_ORDER[p.risk], p.protocol, p.port)):
            details = [f"<div>{_e(p.note)}</div>"]
            if p.banner:
                details.append(f"<div class='muted'><code>{_e(p.banner)}</code></div>")
            if p.product and p.product not in p.banner:
                details.append(f"<div class='muted'>{_e(p.product)}</div>")
            if p.tls and p.tls.get("version"):
                t = p.tls
                expiry = f", expires {t['not_after']}" if t.get("not_after") else ""
                details.append(f"<div class='muted'>{_e(t['version'])}, cert {_e(t.get('subject') or '?')}"
                               f" issued by {_e(t.get('issuer') or '?')}{_e(expiry)}</div>")
            details += [f"<div class='issue'>&#9888; {_e(i)}</div>" for i in p.issues]
            parts.append(f"<tr><td><b>{_e(p.key)}</b></td><td>{_e(p.service)}</td>"
                         f"<td><span class='badge {_e(p.risk)}'>{_e(p.risk)}</span></td><td>{''.join(details)}</td></tr>")
        parts.append("</table></div></section>")
    parts.append("<p class='muted'>Generated by portscan. Only scan systems you own or are authorized to test.</p></main>")
    return "<!doctype html><html lang='en'><head><meta charset='utf-8'>" + parts[0] + parts[1] + "</head><body>" + "".join(parts[2:]) + "</body></html>"
