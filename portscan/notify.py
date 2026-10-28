"""Desktop notifications (macOS and Linux), used by scheduled scans."""

from __future__ import annotations

import shutil
import subprocess
import sys

# Text is passed as arguments, never pasted into the script, so it can't inject AppleScript.
APPLESCRIPT = [
    "-e", "on run argv",
    "-e", "display notification (item 1 of argv) with title (item 2 of argv) sound name \"Basso\"",
    "-e", "end run",
]


def command(title: str, message: str) -> list:
    if sys.platform == "darwin":
        return ["osascript", *APPLESCRIPT, message, title]
    if shutil.which("notify-send"):
        return ["notify-send", title, message]
    return []


def send(title: str, message: str) -> bool:
    cmd = command(title, message)
    if not cmd:
        return False
    try:
        subprocess.run(cmd, check=False, timeout=10, capture_output=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
