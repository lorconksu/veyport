"""Pinned, verified development tools; no dependency on system protoc/plugins."""

import hashlib
import json
import os
import platform
import subprocess
import urllib.request
import zipfile


# protoc 21.12 reports 3.21.12, matching the committed generated headers.
# These are SHA256s of the official release archives downloaded from:
# https://github.com/protocolbuffers/protobuf/releases/tag/v21.12
# This historical release has no publisher checksum manifest/API asset digest.
PROTOC = {
    "Linux-x86_64": ("linux-x86_64", "3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8"),
    "Linux-aarch64": ("linux-aarch_64", "2dd17f75d66a682640b136e31848da9fb2eefe68d55303baf8b32617374f6711"),
    "Darwin-x86_64": ("osx-universal_binary", "1acab3d1f774d120d5a38bccb78fd379d35226b254dc258978bc45593478ca4c"),
    "Darwin-arm64": ("osx-universal_binary", "1acab3d1f774d120d5a38bccb78fd379d35226b254dc258978bc45593478ca4c"),
}
# Verified against the official v1.61.0 sha256.txt and GitHub asset digests:
# https://github.com/bufbuild/buf/releases/tag/v1.61.0
BUF = {
    "Linux-x86_64": "d82849eca790bacb5b8885a027f31bbfbfdf72b2d93bc82bda8cb2ca20e4faca",
    "Linux-aarch64": "37bfa47e6ede6ac1b78b3e3c93a0911b7c71d5bb9ed9c684dfc0164167619bc1",
    "Darwin-x86_64": "20323fa889d55893b67d402b714b04efe8916358ab29ccd2f70203439dc67b42",
    "Darwin-arm64": "b7878d0c88673e067c3a5ac60fabf133b29be71ae3a37598f2e99ee5d3c5fd22",
}
# Module sums authenticated by the public Go checksum database; transitive
# modules also remain subject to checksum database verification during install.
PLUGINS = (
    ("google.golang.org/protobuf", "cmd/protoc-gen-go", "v1.36.11", "h1:fV6ZwhNocDyBLK0dj+fg8ektcVegBBuEolpbTQyBNVE="),
    ("google.golang.org/grpc/cmd/protoc-gen-go-grpc", "", "v1.6.2", "h1:rgSNvqscFZ1JgV/4wH5GOsZFSFkR2Eua9As3KIr2LlM="),
)


def download(url, expected, destination):
    """Verify before writing or executing any downloaded artifact."""
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA256 mismatch for {url}: {actual}")
    destination.write_bytes(data)
    print(f"Verified SHA256 {actual} {url}", flush=True)


def install(destination, *, need_buf=True):
    """Always create fresh executables in a caller-owned temporary directory."""
    machine = platform.machine()
    if platform.system() == "Linux" and machine == "arm64":
        machine = "aarch64"
    host = f"{platform.system()}-{machine}"
    if host not in PROTOC:
        raise ValueError(f"unsupported protobuf tool platform: {host}")
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / "protoc.zip"
    target, checksum = PROTOC[host]
    download(f"https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-{target}.zip", checksum, archive)
    with zipfile.ZipFile(archive) as release:
        # Only the verified compiler is needed; no archive-controlled paths.
        (destination / "protoc").write_bytes(release.read("bin/protoc"))
    if need_buf:
        download(f"https://github.com/bufbuild/buf/releases/download/v1.61.0/buf-{host}", BUF[host], destination / "buf")
    for name in (("protoc", "buf") if need_buf else ("protoc",)):
        (destination / name).chmod(0o755)
    environment = dict(os.environ, GOENV="off", GOWORK="off", GOTOOLCHAIN="local",
                       GOPROXY="https://proxy.golang.org", GOSUMDB="sum.golang.org",
                       GOPRIVATE="", GONOSUMDB="", GONOPROXY="", GOFLAGS="",
                       GOBIN=str(destination.resolve()))
    for module, package, version, expected in PLUGINS:
        info = json.loads(subprocess.check_output(
            ["go", "mod", "download", "-json", f"{module}@{version}"], env=environment))
        if info.get("Sum") != expected:
            raise ValueError(f"unexpected Go module checksum for {module}@{version}")
        print(f"Verified Go checksum {expected} {module}@{version}", flush=True)
        executable = f"{module}/{package}" if package else module
        subprocess.run(["go", "install", "-trimpath", f"{executable}@{version}"], env=environment, check=True)
    names = ["protoc", "protoc-gen-go", "protoc-gen-go-grpc"]
    if need_buf:
        names.append("buf")
    for name in names:
        subprocess.run([str(destination / name), "--version"], check=True)
    return destination
