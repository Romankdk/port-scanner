"""Command-line entry point: python3 -m portscan <targets> [options]"""

from __future__ import annotations

import argparse
import dataclasses
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import history, names, notify, schedule
from .report import render_html, render_json, render_text
from .results import HostResult
from .scanner import discover, parse_ports, parse_targets, pmap, resolve, scan_host
from .services import COMMON_PORTS, RISK_ORDER
from .udp import UDP_COMMON_PORTS

EPILOG = """examples:
  python3 -m portscan 127.0.0.1
  python3 -m portscan 192.168.1.10 -p 1-1024 --udp
  python3 -m portscan 192.168.1.0/24 --discover --html network.html
  python3 -m portscan 192.168.1.0/24 --discover --diff        # what changed since last time?
  python3 -m portscan 192.168.1.0/24 --discover --schedule 09:00
  python3 -m portscan localhost -p 22,80,443 --json -o report.json

exit codes: 0 ok, 1 runtime error, 2 bad arguments, 3 --diff found new exposure

Only scan systems you own or have written permission to test."""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="portscan",
        description="Port scanner with service identification, TLS checks, UDP, device names and change tracking.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,  # scheduled jobs re-use these args; "--sched" must not silently mean --schedule
    )
    ap.add_argument("targets", help="host, IP, CIDR range, or a comma-separated mix")
    scan = ap.add_argument_group("what to scan")
    scan.add_argument("-p", "--ports", help="TCP ports, e.g. 22,80,8000-8100 (default: common ports)")
    scan.add_argument("--top", action="store_true", help="scan TCP ports 1-1024 plus the common list")
    scan.add_argument("--udp", action="store_true", help="also scan common UDP services (DNS, SNMP, NTP, ...)")
    scan.add_argument("--udp-ports", help="UDP ports to scan (implies --udp)")
    scan.add_argument("--discover", action="store_true", help="skip hosts that don't respond on common ports")
    scan.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds per connection (default 1.0)")
    scan.add_argument("-w", "--workers", type=int, default=200, help="concurrent connections (default 200)")
    scan.add_argument("--no-banners", action="store_true", help="skip banner grabbing and service identification")
    scan.add_argument("--no-tls", action="store_true", help="skip HTTPS/TLS certificate checks")
    scan.add_argument("--no-names", action="store_true", help="skip looking up device names")

    out = ap.add_argument_group("output")
    out.add_argument("--min-risk", choices=list(RISK_ORDER), default="info", help="only report ports at or above this risk")
    out.add_argument("--json", action="store_true", help="output JSON")
    out.add_argument("-o", "--output", help="also write the text/JSON report to this file")
    out.add_argument("--html", metavar="FILE", help="write a colour-coded HTML report")
    out.add_argument("--no-color", action="store_true", help="disable colored output")

    track = ap.add_argument_group("tracking changes")
    track.add_argument("--save", action="store_true", help="save this scan to the history")
    track.add_argument("--diff", action="store_true", help="compare with the last saved scan (and save this one)")
    track.add_argument("--notify", action="store_true", help="desktop notification when --diff finds new exposure")
    track.add_argument("--history-dir", type=Path, default=history.DEFAULT_DIR, help="where scans are kept (default ~/.portscan)")
    track.add_argument("--schedule", metavar="HH:MM", help="run this scan every day at HH:MM (with --diff and --notify)")
    track.add_argument("--unschedule", action="store_true", help="remove the daily scan of these targets")
    return ap


def strip_schedule_args(argv: List[str]) -> List[str]:
    out, skip = [], False
    for a in argv:
        if skip:
            skip = False
        elif a == "--schedule":
            skip = True
        elif not a.startswith("--schedule="):
            out.append(a)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    args.history_dir = args.history_dir.expanduser().resolve()
    try:
        hosts = parse_targets(args.targets)
        if args.ports:
            ports = parse_ports(args.ports)
        elif args.top:
            ports = sorted(set(range(1, 1025)) | set(COMMON_PORTS))
        else:
            ports = COMMON_PORTS
        udp_ports = parse_ports(args.udp_ports) if args.udp_ports else (UDP_COMMON_PORTS if args.udp else [])
        if not args.timeout > 0:
            raise ValueError("--timeout must be greater than 0")
        if args.workers < 1:
            raise ValueError("--workers must be at least 1")
        if args.schedule:
            schedule.parse_time(args.schedule)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.unschedule:
        print(schedule.uninstall(args.targets))
        return 0
    if args.schedule:
        print(schedule.install(args.targets, strip_schedule_args(argv), args.schedule, args.history_dir))
        return 0

    targets: List[tuple] = []
    seen_ips = set()
    for host in hosts:
        try:
            ip = resolve(host)
        except socket.gaierror:
            print(f"  skip {host}: could not resolve", file=sys.stderr)
            continue
        if ip in seen_ips:
            print(f"  skip {host}: same address ({ip}) as an earlier target", file=sys.stderr)
            continue
        seen_ips.add(ip)
        targets.append((host, ip))

    if args.discover and len(targets) > 1:
        print(f"Discovering live hosts among {len(targets)}...", file=sys.stderr)
        try:
            alive = discover([ip for _, ip in targets], min(args.timeout, 0.5), args.workers)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
        targets = [(h, ip) for h, ip in targets if ip in alive]

    udp_note = f" + {len(udp_ports)} UDP" if udp_ports else ""
    print(f"Scanning {len(targets)} host(s), {len(ports)} TCP{udp_note} port(s) each...", file=sys.stderr)
    results: List[HostResult] = []
    for host, ip in targets:
        try:
            r = scan_host(host, ip, ports, args.timeout, args.workers, banners=not args.no_banners,
                          tls=not args.no_tls, udp_ports=udp_ports)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        results.append(r)
        if r.interrupted:
            print("\ninterrupted; showing partial results", file=sys.stderr)
            break

    if results and not args.no_names and not any(r.interrupted for r in results):
        try:
            for r, name in zip(results, pmap(lambda r: names.lookup(r.ip), results, 32)):
                r.name = name
        except KeyboardInterrupt:
            pass

    # Compare and save the full results; --min-risk only affects what is displayed.
    diff = None
    options = {"banners": not args.no_banners, "tls": not args.no_tls}
    if args.diff:
        earlier = history.recent(args.history_dir, args.targets)
        if not results:
            print("Nothing responded (is the network up?); skipping the comparison.", file=sys.stderr)
        elif not earlier:
            print("No earlier scan of these targets to compare with; saving this one as the baseline.", file=sys.stderr)
        else:
            diff = history.compare(earlier[0], results, ports, udp_ports, options, older=earlier[1:])
    if args.save or args.diff:
        path = history.save(args.history_dir, args.targets, ports, udp_ports, results, options)
        print(f"Scan saved to {path}", file=sys.stderr)

    floor = RISK_ORDER[args.min_risk]
    shown: List[HostResult] = []
    for r in results:
        kept = [p for p in r.open_ports if RISK_ORDER[p.risk] >= floor]
        shown.append(dataclasses.replace(r, open_ports=kept, hidden=len(r.open_ports) - len(kept)))

    if args.json:
        report = render_json(shown, diff)
    else:
        report = render_text(shown, color=False if args.no_color else None)
        if diff is not None:
            report += "\n\n" + history.render_text(diff)
    print(report)
    if args.output:
        plain = report if args.json else render_text(shown, color=False) + (
            "\n\n" + history.render_text(diff) if diff is not None else "")
        with open(args.output, "w") as f:
            f.write(plain + "\n")
        print(f"Report written to {args.output}", file=sys.stderr)
    if args.html:
        Path(args.html).write_text(render_html(shown, args.targets, diff, datetime.now()))
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if diff is not None and diff.alerts:
        if args.notify:
            n = len(diff.alerts)
            notify.send("portscan: network changed", f"{n} new exposure(s) on {args.targets}. See the report.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
