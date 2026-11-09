#!/usr/bin/env python3
"""Reproduce generated Go and check schemas against an exact Git base commit."""

import argparse
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile

from tools import install


ROOT = Path(__file__).resolve().parents[2]


def run(arguments, *, root=None, capture=False):
    return subprocess.run([str(value) for value in arguments], cwd=root or ROOT, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None).stdout


def generate(tools, source, output):
    schemas = sorted(source.glob("proto/**/*.proto"))
    if not schemas:
        raise ValueError("no protobuf schemas found")
    run([tools / "protoc", f"--proto_path={source}",
         f"--plugin=protoc-gen-go={tools / 'protoc-gen-go'}",
         f"--plugin=protoc-gen-go-grpc={tools / 'protoc-gen-go-grpc'}",
         f"--go_out={output}", "--go_opt=paths=source_relative",
         f"--go-grpc_out={output}", "--go-grpc_opt=paths=source_relative",
         *[path.relative_to(source) for path in schemas]], root=source)


def generated_check(tools, source):
    with tempfile.TemporaryDirectory(prefix="veyport-proto-generated-") as directory:
        output = Path(directory)
        generate(tools, source, output)
        expected = {path.relative_to(output): path.read_bytes() for path in output.rglob("*.pb.go")}
        actual = {path.relative_to(source): path.read_bytes() for path in (source / "proto").rglob("*.pb.go")}
        drift = sorted(str(path) for path in expected.keys() | actual.keys()
                       if expected.get(path) != actual.get(path))
        if drift:
            raise ValueError("generated protobuf drift; run make proto: " + ", ".join(drift))
    print("Generated protobuf files reproduce exactly", flush=True)


def resolve_base(requested):
    if not requested:
        # Local runs/reusable non-PR callers resolve only the upstream main ref,
        # freeze its SHA, then fetch that SHA. PR CI always supplies base.sha.
        requested = run(["git", "ls-remote", "--exit-code", "origin", "refs/heads/main"], capture=True).decode().split()[0]
    if not re.fullmatch(r"[0-9a-f]{40}", requested) or requested == "0" * 40:
        raise ValueError("PROTO_BASE_SHA must be a full nonzero Git commit SHA")
    present = subprocess.run(["git", "cat-file", "-e", requested + "^{commit}"], cwd=ROOT,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not present:
        # Supports shallow checkouts; never fetch a PR-supplied ref or URL.
        run(["git", "fetch", "--no-tags", "--depth=1", "origin", requested])
    resolved = run(["git", "rev-parse", "--verify", requested + "^{commit}"], capture=True).decode().strip()
    if resolved != requested:
        raise ValueError("comparison commit did not resolve to the requested SHA")
    print(f"Protobuf comparison base: {resolved}", flush=True)
    return resolved


def snapshot(base, output):
    # Never check out or execute baseline code, generation hooks, or Buf config.
    # Only regular .proto blobs under proto/ are copied, rejecting symlinks.
    listing = run(["git", "ls-tree", "-rz", "--full-tree", base, "--", "proto/"], capture=True)
    count = 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = PurePosixPath(os.fsdecode(raw_path))
        if path.suffix != ".proto":
            continue
        mode, kind, blob = metadata.decode().split()
        if mode not in ("100644", "100755") or kind != "blob" or path.is_absolute() or ".." in path.parts:
            raise ValueError("baseline schema must be a regular file under proto/")
        destination = output.joinpath(*path.parts[1:])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(run(["git", "cat-file", "blob", blob], capture=True))
        count += 1
    if count == 0:
        raise ValueError("comparison base contains no protobuf schemas; refusing an empty baseline")
    shutil.copyfile(ROOT / "proto/buf.yaml", output / "buf.yaml")


def breaking(tools, current, baseline, *, capture=False):
    config = ROOT / "proto/buf.yaml"
    run([tools / "buf", "build", current, "--config", config], capture=capture)
    return run([tools / "buf", "breaking", current, "--config", config, "--against", baseline], capture=capture)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check", "breaking", "ci"))
    parser.add_argument("--base", default=os.environ.get("PROTO_BASE_SHA", ""))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="veyport-proto-tools-") as directory:
        tools = install(Path(directory) / "bin", need_buf=args.command in ("breaking", "ci"))
        if args.command == "generate":
            generate(tools, ROOT, ROOT)
        if args.command in ("check", "ci"):
            generated_check(tools, ROOT)
        if args.command in ("breaking", "ci"):
            baseline = Path(directory) / "baseline"
            baseline.mkdir()
            snapshot(resolve_base(args.base), baseline)
            breaking(tools, ROOT / "proto", baseline)
            print("Protobuf schema compatibility passed", flush=True)
        if args.command == "ci":
            from test_controls import exercise_controls
            exercise_controls(tools)


if __name__ == "__main__":
    main()
