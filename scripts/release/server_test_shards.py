#!/usr/bin/env python3
"""Run every server test in bounded shards and verify complete race evidence."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


PACKAGE = "github.com/wyiu/veyport/hub/internal/server"
DEFAULT_SHARDS = 6


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_digest(root):
    result = hashlib.sha256()
    for module in ("hub", "proto"):
        for path in sorted((root / module).rglob("*")):
            if path.is_file() and (path.suffix in (".go", ".sql", ".s", ".c", ".h") or path.name in ("go.mod", "go.sum")):
                result.update(str(path.relative_to(root)).encode() + b"\0")
                result.update(path.read_bytes() + b"\0")
    return result.hexdigest()


def partition(names, count):
    if not 1 <= count <= 32 or not names or len(names) != len(set(names)):
        raise ValueError("invalid complete test inventory or shard count")
    if any(not re.fullmatch(r"(?:Test|Example|Fuzz)\w*", name) for name in names):
        raise ValueError("unexpected top-level test name")
    shards = [[] for _ in range(count)]
    for name in sorted(names):
        shards[int(digest(name.encode()), 16) % count].append(name)
    if any(not shard for shard in shards):
        raise ValueError("empty shard; reduce the shard count")
    return shards


def plan(root, count):
    before = source_digest(root)
    output = subprocess.check_output(
        ["go", "test", "-list", "^(Test|Example|Fuzz)", "./internal/server"],
        cwd=root / "hub", text=True, timeout=180,
    )
    names = []
    for line in output.splitlines():
        if line.startswith(("Test", "Example", "Fuzz")):
            names.append(line)
        elif not re.fullmatch(r"ok\s+" + re.escape(PACKAGE) + r"\s+.*", line):
            raise ValueError("unexpected Go inventory output")
    shards = partition(names, count)
    if source_digest(root) != before:
        raise ValueError("source changed while collecting the complete inventory")
    return {"schema_version": 1, "package": PACKAGE, "source_sha256": before, "shards": shards}


def run_expression(names):
    # Exact top-level names select their complete subtest trees.
    return "^(?:" + "|".join(re.escape(name) for name in names) + ")$"


def completed_tests(log, expected):
    completed = {}
    package_passed = False
    for line in log.splitlines():
        event = json.loads(line)
        if event.get("Package") != PACKAGE:
            raise ValueError("unexpected package in server test evidence")
        name, action = event.get("Test", ""), event.get("Action", "")
        if not name:
            package_passed |= action == "pass"
        elif "/" not in name and action in ("pass", "skip", "fail"):
            if name in completed or name not in expected or action == "fail":
                raise ValueError("duplicate, unselected or failed top-level test")
            completed[name] = action
    if not package_passed or set(completed) != set(expected):
        raise ValueError("server shard did not complete every selected test")
    return completed


def atomic_json(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_bytes(canonical(value) + b"\n")
    temp.replace(path)


def run_shard(root, output, inventory, index, timeout):
    if not 0 <= index < len(inventory["shards"]):
        raise ValueError("shard index outside inventory")
    folder = output / f"shard-{index}"
    folder.mkdir(parents=True, exist_ok=True)
    profile, log = folder / "coverage.out", folder / "go-test.jsonl"
    for old in (profile, folder / "shard.json"):
        old.unlink(missing_ok=True)
    atomic_json(folder / "plan.json", inventory)
    # HTTP tests exercise live store/authorization/runtime controls. Measure
    # those dependencies with the same scope as the integration coverage job.
    command = ["go", "test", "-json", "-race", "-count=1", f"-timeout={timeout}s", "-covermode=atomic", "-coverpkg=./internal/...", f"-coverprofile={profile.resolve()}", "-run", run_expression(inventory["shards"][index]), "./internal/server"]
    started = time.monotonic()
    with log.open("w") as stream:
        process = subprocess.Popen(command, cwd=root / "hub", stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout + 300)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise ValueError("server shard exceeded its test and build deadline") from None
    if code != 0 or source_digest(root) != inventory["source_sha256"]:
        raise ValueError(f"server shard {index} failed or source changed; inspect {log}")
    completed = completed_tests(log.read_text(), inventory["shards"][index])
    read_profile(profile)
    evidence = {"schema_version": 1, "index": index, "plan_sha256": digest(canonical(inventory)), "profile_sha256": digest(profile.read_bytes()), "log_sha256": digest(log.read_bytes()), "completed": completed, "elapsed_seconds": round(time.monotonic() - started, 3)}
    atomic_json(folder / "shard.json", evidence)
    print(f"server shard {index}: {len(completed)} top-level tests passed in {evidence['elapsed_seconds']}s", flush=True)


def read_profile(path):
    lines = path.read_text().splitlines()
    if not lines or lines[0] != "mode: atomic" or len(lines) == 1:
        raise ValueError("complete atomic coverage profile required")
    blocks = {}
    for line in lines[1:]:
        match = re.fullmatch(r"(\S+:\d+\.\d+,\d+\.\d+) (\d+) (\d+)", line)
        if not match:
            raise ValueError("invalid Go coverage block")
        key, statements, count = match.group(1), int(match.group(2)), int(match.group(3))
        if key in blocks and blocks[key][0] != statements:
            raise ValueError("incompatible coverage block shape")
        blocks[key] = (statements, blocks.get(key, (0, 0))[1] + count)
    return blocks


def merge(root, input_dir, output, inventory, includes=()):
    evidence_paths = sorted(input_dir.rglob("shard.json"))
    if len(evidence_paths) != len(inventory["shards"]):
        raise ValueError("missing or extra shard evidence")
    profiles, indexes = [], set()
    for path in evidence_paths:
        evidence = json.loads(path.read_text())
        index = evidence["index"]
        if index in indexes or not 0 <= index < len(inventory["shards"]) or evidence["schema_version"] != 1:
            raise ValueError("duplicate or invalid shard evidence")
        indexes.add(index)
        stored_plan = json.loads((path.parent / "plan.json").read_text())
        if stored_plan != inventory or evidence["plan_sha256"] != digest(canonical(inventory)):
            raise ValueError("shard source or complete inventory differs")
        profile, log = path.parent / "coverage.out", path.parent / "go-test.jsonl"
        if evidence["profile_sha256"] != digest(profile.read_bytes()) or evidence["log_sha256"] != digest(log.read_bytes()):
            raise ValueError("shard profile or execution evidence changed")
        if completed_tests(log.read_text(), inventory["shards"][index]) != evidence["completed"]:
            raise ValueError("reported shard execution differs from actual Go evidence")
        profiles.append(profile)
    blocks = {}
    for profile in profiles + list(includes):
        for key, (statements, count) in read_profile(profile).items():
            if key in blocks and blocks[key][0] != statements:
                raise ValueError("coverage profiles use different source shapes")
            blocks[key] = (statements, blocks.get(key, (0, 0))[1] + count)
    if source_digest(root) != inventory["source_sha256"]:
        raise ValueError("source changed during coverage merge")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(".tmp")
    temp.write_text("mode: atomic\n" + "".join(f"{key} {statements} {count}\n" for key, (statements, count) in sorted(blocks.items())))
    temp.replace(output)
    print(f"merged {len(indexes)} shards: {sum(map(len, inventory['shards']))} unique top-level tests", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "run", "run-all", "merge"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--shards", type=int, default=DEFAULT_SHARDS)
    parser.add_argument("--index", type=int)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=1800, help="per-shard test deadline in seconds")
    parser.add_argument("--input", type=Path, default=Path("coverage-server"))
    parser.add_argument("--output", type=Path, default=Path("coverage-server"))
    parser.add_argument("--include", type=Path, action="append", default=[])
    args = parser.parse_args()
    if not 1 <= args.jobs <= args.shards or not 1 <= args.timeout <= 1800:
        parser.error("bounded jobs and per-shard timeout required")
    inventory = plan(args.root.resolve(), args.shards)
    if args.action == "plan":
        args.output.mkdir(parents=True, exist_ok=True)
        atomic_json(args.output / "plan.json", inventory)
        print(json.dumps({"source_sha256": inventory["source_sha256"], "shard_test_counts": [len(s) for s in inventory["shards"]], "total": sum(map(len, inventory["shards"]))}))
    elif args.action == "run":
        if args.index is None:
            parser.error("run requires --index")
        run_shard(args.root.resolve(), args.output, inventory, args.index, args.timeout)
    elif args.action == "run-all":
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(run_shard, args.root.resolve(), args.output, inventory, index, args.timeout) for index in range(args.shards)]
            errors = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except (ValueError, OSError, subprocess.SubprocessError) as error:
                    errors.append(str(error))
            if errors:
                raise ValueError("; ".join(errors))
        merge(args.root.resolve(), args.output, args.output / "coverage-server.out", inventory)
    else:
        merge(args.root.resolve(), args.input, args.output, inventory, args.include)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"server test evidence refused: {error}")
