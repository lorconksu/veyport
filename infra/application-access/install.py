#!/usr/bin/env python3
"""Install private Compose fixtures only on the two newly provisioned guests.

Default mode verifies readiness and prints concrete operations. Synthetic native
passwords and keys are transferred by pinned SSH stdin and never enter logs.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile

import provision as lab
from resume import KNOWN_HOSTS, ssh_ready

PRIVATE = Path.home() / ".cache/veyport-app-access/fixture-private"
IMAGE_TAG = "veyport-application-fixture:local"


def build_image():
    with tempfile.TemporaryDirectory(prefix="veyport-app-fixture-") as temp:
        folder = Path(temp)
        subprocess.run(["go", "build", "-trimpath", "-o", str(folder / "application-fixture"), "."],
                       cwd=Path(__file__).parent / "fixture", env={**os.environ, "CGO_ENABLED": "0"},
                       check=True, capture_output=True)
        (folder / "Dockerfile").write_text('FROM scratch\nCOPY application-fixture /application-fixture\nENTRYPOINT ["/application-fixture"]\n')
        subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", "build", "-q", "-t", IMAGE_TAG, str(folder)],
                       check=True, capture_output=True)
    image = subprocess.check_output(["docker", "--host", "unix:///var/run/docker.sock", "image", "inspect",
                                     IMAGE_TAG, "--format", "{{.Id}}"], text=True).strip()
    raw = subprocess.check_output(["docker", "--host", "unix:///var/run/docker.sock", "save", IMAGE_TAG])
    return raw, {"image_id": image, "archive_sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    state = json.loads(lab.STATE.read_text())
    if state["status"] != "vms_started_fixture_install_pending":
        raise RuntimeError("Expected new VM provision journal")
    ready = [ssh_ready(vm) for vm in lab.CANDIDATES]
    if not args.apply:
        print(json.dumps({"ready": ready, "operations": [
            "disable inherited tailscale/agent services only in the new guests",
            "add owned guest firewall table before listening; preserve Docker tables",
            "load exact local fixture image and Compose over pinned SSH",
            "direct .66:8080/8443 accepts Hub .96; node 127.0.0.1:8080/8443",
            "verify HTTP and private-CA HTTPS health; secrets remain 0600"]}, indent=2))
        return
    raw, identity = build_image()
    evidence = []
    for vm in lab.CANDIDATES:
        assets = {"image.tar": raw, "compose.yml": Path(__file__).with_name("compose.yml").read_bytes(),
                  "image-identity.json": json.dumps(identity).encode()}
        for name in ("native-credentials.json", "server.crt", "server.key"):
            assets["private/" + name] = (PRIVATE / vm["mode"] / name).read_bytes()
        assets["private/ca.crt"] = (PRIVATE / "ca.crt").read_bytes()
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:gz") as archive:
            for name, value in assets.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(value), 0o600
                archive.addfile(member, io.BytesIO(value))
        source = Path(__file__).with_name("guest-install.py").read_text()
        command = "sudo -n python3 -c " + shlex.quote(source) + " " + shlex.quote(json.dumps(vm))
        response = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS), "-i", str(lab.SSH_KEY),
            "cloud-user@" + vm["ip"], command], input=payload.getvalue(), capture_output=True, timeout=120)
        if response.returncode:
            # The captured output may contain private inputs. Do not forward it.
            raise RuntimeError("New fixture installation failed; inspect additive paths; private details withheld")
        result = json.loads(response.stdout)
        evidence.append(result)
        lab.private_write(Path.home() / f'.cache/veyport-app-access/infra/fixture-{vm["vmid"]}-installed.json', result)
        print("Fixture installed and locally verified", vm["vmid"], vm["ip"], flush=True)
    lab.private_write(Path.home() / ".cache/veyport-app-access/infra/fixture-installed.json",
                      {"fixtures": evidence, "ready": ready})


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit("Fixture install stopped: " + (str(error) if isinstance(error, RuntimeError)
                         else type(error).__name__ + "; private details withheld"))
