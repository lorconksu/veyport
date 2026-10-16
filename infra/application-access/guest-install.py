"""Root-only installer, invoked over pinned SSH on the two new guests only."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

vm = json.loads(sys.argv[1])
base = Path("/etc/veyport-app-fixture")
if vm not in [
    {"vmid": 126, "ip": "10.10.1.66", "name": "veyport-app-direct-lab", "mode": "direct"},
    {"vmid": 127, "ip": "10.10.1.67", "name": "veyport-app-node-lab", "mode": "node"},
]:
    raise SystemExit("Exact new fixture guest identity required")
if subprocess.check_output(["hostname"], text=True).strip() != vm["name"]:
    raise SystemExit("Guest hostname differs")
if base.exists() or Path("/etc/systemd/system/veyport-app-fixture-firewall.service").exists():
    raise SystemExit("Fixture paths already exist: inspect instead of overwrite")
if subprocess.run(["nft", "list", "table", "inet", "veyport_app_fixture"], capture_output=True).returncode == 0:
    raise SystemExit("Fixture table already exists")
if subprocess.check_output(["docker", "--host", "unix:///var/run/docker.sock", "ps", "-aq"], text=True).strip():
    raise SystemExit("Unexpected inherited containers")
services = json.loads(subprocess.check_output(["systemctl", "list-unit-files", "--type=service", "--output=json"], text=True))
inherited = [entry["unit_file"] for entry in services if entry["unit_file"] == "tailscaled.service"
             or "veyport" in entry["unit_file"] or entry["unit_file"].startswith(("vey-", "vey."))]
for service in inherited:
    # Do not log out/revoke shared identities or change the source template.
    subprocess.run(["systemctl", "disable", "--now", service], check=True, capture_output=True)

archive = tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()), mode="r:gz")
expected = {"image.tar", "compose.yml", "private/native-credentials.json",
            "private/server.crt", "private/server.key", "private/ca.crt", "image-identity.json"}
members = archive.getmembers()
if {member.name for member in members} != expected or len(members) != len(expected) or any(not member.isfile() for member in members):
    raise SystemExit("Unexpected fixture payload")
if any(member.size > 32 << 20 for member in members):
    raise SystemExit("Fixture payload exceeded bound")
os.umask(0o077)
base.mkdir(mode=0o700)
(base / "private").mkdir(mode=0o700)
for name in expected:
    with (base / name).open("xb") as file:
        file.write(archive.extractfile(archive.getmember(name)).read())
    (base / name).chmod(0o600)
# The scratch image has no passwd database. Use the same fixed, unprivileged
# numeric identity for the directory and every private file it must read.
os.chown(base / "private", 65532, 65532)
for private_file in (base / "private").iterdir():
    os.chown(private_file, 65532, 65532)
identity = json.loads((base / "image-identity.json").read_text())
if hashlib.sha256((base / "image.tar").read_bytes()).hexdigest() != identity["archive_sha256"]:
    raise SystemExit("Fixture image archive changed")

allowed = "ip saddr 10.10.1.96 tcp dport { 8080, 8443 } accept" if vm["mode"] == "direct" else ""
# Add only an owned table. Docker's own iptables/nft tables are preserved.
rules = """table inet veyport_app_fixture {
 chain input {
  type filter hook input priority -10; policy drop;
  iifname "lo" accept
  ct state established,related accept
  ip saddr 10.10.1.95 tcp dport 22 accept
  ip saddr { 10.10.1.95, 10.10.1.96 } ip protocol icmp accept
  ALLOW_DIRECT
 }
}""".replace("ALLOW_DIRECT", allowed)
(base / "firewall.nft").write_text(rules)
unit = """[Unit]
Description=Private application fixture firewall
Before=docker.service
After=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/veyport-app-fixture/firewall.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
"""
Path("/etc/systemd/system/veyport-app-fixture-firewall.service").write_text(unit)
subprocess.run(["nft", "-c", "-f", str(base / "firewall.nft")], check=True, capture_output=True)
subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
subprocess.run(["systemctl", "enable", "--now", "veyport-app-fixture-firewall.service"], check=True, capture_output=True)
with (base / "image.tar").open("rb") as source:
    subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", "load"], stdin=source, check=True, capture_output=True)
actual = subprocess.check_output(["docker", "--host", "unix:///var/run/docker.sock", "image", "inspect",
                                  "veyport-application-fixture:local", "--format", "{{.Id}}"], text=True).strip()
if actual != identity["image_id"]:
    raise SystemExit("Loaded image identity differs")
bind = vm["ip"] if vm["mode"] == "direct" else "127.0.0.1"
env = {**os.environ, "LAB_BIND_IP": bind, "LAB_PRIVATE_DIR": str(base / "private"),
       "LAB_UID": "65532", "LAB_GID": "65532"}
subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", "compose", "-f", str(base / "compose.yml"),
                "up", "-d", "--no-build", "--pull", "never", "--wait"], env=env, check=True, capture_output=True)
for scheme, port in (("http", 8080), ("https", 8443)):
    response = subprocess.check_output(["curl", "--fail", "--silent", "--show-error", "--max-time", "5",
                                       "--cacert", str(base / "private/ca.crt"), f"{scheme}://{bind}:{port}/health"], text=True)
    if json.loads(response).get("status") != "ok":
        raise SystemExit("Local fixture health failed")
(base / "image.tar").unlink()
print(json.dumps({"vmid": vm["vmid"], "ip": vm["ip"], "bind": bind, "ports": [8080, 8443],
                  "image_id": actual, "disabled_inherited_services": inherited, "http_https_health": True,
                  "private_credentials_mode": "0600", "firewall_installed_before_listeners": True}))
