"""Run a scan automatically every day: a launchd agent on macOS, a cron line elsewhere."""

from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

from .history import slug

PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"


def parse_time(hhmm: str) -> Tuple[int, int]:
    try:
        h, m = (int(x) for x in hhmm.split(":"))
    except ValueError:
        raise ValueError(f"--schedule wants a time like 09:30, not {hhmm!r}") from None
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"--schedule time {hhmm!r} is out of range")
    return h, m


def scan_command(scan_args: List[str], base: Path) -> List[str]:
    """The command the schedule runs: the same scan, compared with last time, with alerts."""
    args = list(scan_args)

    def has(flag: str) -> bool:
        return any(a == flag or a.startswith(flag + "=") for a in args)

    for flag in ("--diff", "--notify", "--no-color"):
        if not has(flag):
            args.append(flag)
    if not has("--html"):
        args += ["--html", str(base / "latest.html")]
    if not has("--history-dir"):
        args += ["--history-dir", str(base)]
    return [sys.executable, "-m", "portscan", *args]


def label(targets: str) -> str:
    return f"local.portscan.{slug(targets)}"


def build_plist(targets: str, scan_args: List[str], hhmm: str, base: Path) -> dict:
    hour, minute = parse_time(hhmm)
    return {
        "Label": label(targets),
        "ProgramArguments": scan_command(scan_args, base),
        "EnvironmentVariables": {"PYTHONPATH": str(PROJECT_ROOT)},
        # Run from where the user scheduled it, so relative paths like "-o report.json" mean the same thing.
        "WorkingDirectory": os.getcwd(),
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        "StandardOutPath": str(base / "schedule.log"),
        "StandardErrorPath": str(base / "schedule.log"),
    }


def install(targets: str, scan_args: List[str], hhmm: str, base: Path) -> str:
    base.mkdir(parents=True, exist_ok=True)
    if sys.platform != "darwin":
        hour, minute = parse_time(hhmm)
        cmd = " ".join(shlex.quote(a) for a in scan_command(scan_args, base))
        env = f"PYTHONPATH={shlex.quote(str(PROJECT_ROOT))}"
        return ("Add this line with `crontab -e` to run the scan daily:\n"
                f"{minute} {hour} * * * cd {shlex.quote(os.getcwd())} && {env} {cmd} >> {shlex.quote(str(base / 'schedule.log'))} 2>&1")
    AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    path = AGENTS_DIR / f"{label(targets)}.plist"
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", domain, str(path)], capture_output=True)
    with open(path, "wb") as f:
        plistlib.dump(build_plist(targets, scan_args, hhmm, base), f)
    proc = subprocess.run(["launchctl", "bootstrap", domain, str(path)], capture_output=True, text=True)
    if proc.returncode != 0:
        return f"Wrote {path} but launchctl could not load it: {proc.stderr.strip()}"
    return (f"Scheduled a daily scan of {targets} at {hhmm}.\n"
            f"  Changes trigger a notification; report: {base / 'latest.html'}; log: {base / 'schedule.log'}\n"
            f"  Remove it with: python3 -m portscan {shlex.quote(targets)} --unschedule")


def uninstall(targets: str) -> str:
    if sys.platform != "darwin":
        return "Remove the portscan line with `crontab -e`."
    path = AGENTS_DIR / f"{label(targets)}.plist"
    if not path.exists():
        return f"No schedule found for {targets}."
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True)
    path.unlink()
    return f"Removed the daily scan of {targets}."
