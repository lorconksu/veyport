#!/usr/bin/env python3
"""Generate synthetic passwords and short-lived CA/server identities privately.

All files are created exclusively with mode 0600; never run inside a repository.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess


def write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(data)


def openssl(directory, *args):
    result = subprocess.run(["openssl", *args], cwd=directory, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Private certificate preparation failed; details withheld")


def prepare(directory):
    directory = directory.resolve()
    for parent in [directory, *directory.parents]:
        if (parent / ".git").exists():
            raise RuntimeError("Private credential destination must be outside a repository")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    previous = os.umask(0o077)
    try:
        write(directory / "native-credentials.json", json.dumps({"username": "app-fixture", "password": secrets.token_urlsafe(36)}) + "\n")
        for label in ("ca", "wrong-ca"):
            openssl(directory, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "14", "-subj", "/CN=Veyport isolated application fixture " + label,
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", label + ".key", "-out", label + ".crt")
        for name, addresses in (("direct", ["10.10.1.66"]), ("node", ["127.0.0.1", "10.10.1.67"]), ("wrong-name", ["192.0.2.123"])):
            folder = directory / name
            folder.mkdir(mode=0o700)
            write(folder / "extensions.cnf", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=" + ",".join("IP:" + str(ipaddress.ip_address(address)) for address in addresses) + "\n")
            openssl(directory, "req", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", "/CN=isolated-" + name + "-fixture", "-keyout", name + "/server.key", "-out", name + "/server.csr")
            openssl(directory, "x509", "-req", "-in", name + "/server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", str(secrets.randbits(128) or 1), "-days", "7", "-sha256", "-extfile", name + "/extensions.cnf", "-out", name + "/server.crt")
            write(folder / "native-credentials.json", (directory / "native-credentials.json").read_text())
        for path in directory.rglob("*"):
            if path.is_file():
                path.chmod(0o600)
    finally:
        os.umask(previous)
    print("Private synthetic credential and TLS identities prepared")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    prepare(parser.parse_args().directory)
