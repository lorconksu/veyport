#!/usr/bin/env python3
"""Lint changed frontend lines while preserving the full ESLint evidence."""
import json
import os
import re
import subprocess
from pathlib import Path


def changed_lines(diff):
    lines = set()
    for start, count in re.findall(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.MULTILINE):
        first, length = int(start), int(count or "1")
        lines.update(range(first, first + length))
    return lines


def run():
    root = Path(__file__).resolve().parents[2]
    baseline = os.environ.get("BASE_SHA", "")
    if not baseline or baseline == "0" * 40:
        baseline = subprocess.check_output(["git", "merge-base", "HEAD", "origin/main"], cwd=root, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", baseline):
        raise ValueError("exact lint baseline required")
    names = subprocess.check_output(["git", "diff", "--name-only", "-z", "--diff-filter=ACMR", baseline, "--", "web/src"], cwd=root).decode().split("\0")
    files = [name for name in names if name.endswith((".ts", ".tsx", ".js", ".jsx"))]
    if len(files) > 1024:
        raise ValueError("changed file bound exceeded")
    if not files:
        return
    changed = {}
    for name in files:
        diff = subprocess.check_output(["git", "diff", "--unified=0", baseline, "--", name], cwd=root, text=True)
        changed[str((root / name).resolve())] = changed_lines(diff)
    process = subprocess.run(["npx", "--no-install", "eslint", "--format", "json", "--"] + [name.removeprefix("web/") for name in files], cwd=root / "web", capture_output=True, timeout=120)
    if process.returncode not in (0, 1) or len(process.stdout) > 8 << 20:
        raise ValueError("ESLint failed to produce bounded evidence")
    reports = json.loads(process.stdout)
    (root / "frontend-lint-results.json").write_bytes(process.stdout)
    errors = sum(1 for report in reports for message in report["messages"] if message["severity"] == 2 and (message.get("fatal") or message.get("line") in changed.get(report["filePath"], set())))
    if errors:
        raise ValueError(f"ESLint found {errors} errors on changed lines")


if __name__ == "__main__":
    try:
        run()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError):
        raise SystemExit("changed frontend lint gate failed; inspect frontend-lint-results.json")
