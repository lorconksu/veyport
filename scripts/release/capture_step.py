#!/usr/bin/env python3
"""Keep full subprocess diagnostics private and emit only a safe status line."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def capture(name, command, timeout, child_umask=-1):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or not command or not 1 <= timeout <= 5400:
        raise ValueError("bounded test command required")
    root = Path(os.environ["RUNNER_TEMP"]) / "ssdf-results"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    clock = time.monotonic()
    code, timed_out = 1, False
    with (root / (name + ".stdout")).open("xb") as stdout, (root / (name + ".stderr")).open("xb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True, umask=child_umask)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        finally:
            (root / (name + ".result.json")).write_text(json.dumps({"schema_version": 1, "name": name, "exit_code": code,
                "timed_out": timed_out, "started_at": start, "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - clock, 3)}, sort_keys=True) + "\n")
    print(name + ": " + ("passed" if code == 0 else "failed") + " (private diagnostics retained)")
    return code if code >= 0 else 128 - code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--timeout", type=int, default=2700)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    original_umask = os.umask(0o077)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        parser.exit(capture(args.name, command, args.timeout, child_umask=original_umask))
    except (ValueError, OSError, subprocess.SubprocessError):
        parser.exit(1, "private diagnostic capture failed\n")


if __name__ == "__main__":
    main()
