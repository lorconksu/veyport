#!/usr/bin/env python3
"""Plan-only by default; create only two absent, owner-authorized fixture VMs.

Apply requires the exact reviewed plan hash and reruns every collision check.
Credentials never appear in plans or command arguments. API TLS is verified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import urllib.parse
import urllib.request

CANDIDATES = [
    {"vmid": 126, "ip": "10.10.1.66", "name": "veyport-app-direct-lab", "mode": "direct"},
    {"vmid": 127, "ip": "10.10.1.67", "name": "veyport-app-node-lab", "mode": "node"},
]
TAG = "veyport-application-access-lab"
STATE = Path.home() / ".cache/veyport-app-access/infra/provision-state.json"
SSH_KEY = Path.home() / ".ssh/yiucloud"
BASE = "https://proxmox1.yiucloud.com:8006/api2/json"


def private_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = json.dumps(value, indent=2, sort_keys=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(raw)


def credentials():
    values = {key: os.environ.get(key) for key in ("PROXMOX_TOKEN_ID", "PROXMOX_SECRET")}
    if not all(values.values()):
        # Read data, never source shell code from the fallback dotenv file.
        for line in (Path.home() / "personal/gridwires/.env").read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and key in values and not values[key]:
                values[key] = value.strip().strip("\"'")
    if not all(values.values()):
        raise RuntimeError("Proxmox credentials unavailable")
    return "PVEAPIToken=" + values["PROXMOX_TOKEN_ID"] + "=" + values["PROXMOX_SECRET"]


def api(method, path, **params):
    if method == "GET" and params:
        path += "?" + urllib.parse.urlencode(params)
        params = {}
    data = urllib.parse.urlencode(params).encode() if params else None
    request = urllib.request.Request(BASE + path, method=method, data=data,
                                     headers={"Authorization": credentials()})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)["data"]


def remote(host, command, source=None):
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10", "-i", str(SSH_KEY), "root@" + host, command],
        input=source, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError("Private remote check failed on " + host + "; details withheld")
    return result.stdout


def netbox(source):
    output = remote("10.10.1.47", "docker --host unix:///var/run/docker.sock exec -i netbox-docker-netbox-1 "
        "python /opt/netbox/netbox/manage.py shell -c " + shlex.quote("import sys; exec(sys.stdin.read())"), source)
    records = [line[len("VEYPORT_PLAN="):] for line in output.splitlines() if line.startswith("VEYPORT_PLAN=")]
    if len(records) != 1:
        raise RuntimeError("Expected exactly one NetBox result")
    return json.loads(records[0])


def netbox_source(apply=False):
    source = Path(__file__).with_name("reserve-netbox.py").read_text()
    return "CANDIDATES=" + repr(CANDIDATES) + "\nAPPLY=" + repr(apply) + "\nTAG=" + repr(TAG) + "\n" + source


def plan(candidates=None, netbox_check=None):
    candidates = CANDIDATES if candidates is None else candidates
    resources = api("GET", "/cluster/resources")
    ids = {entry.get("vmid") for entry in resources}
    names = {entry.get("name") for entry in resources}
    if any(vm["vmid"] in ids or vm["name"] in names for vm in candidates):
        raise RuntimeError("Existing VMID or name; refusing all mutations")
    nodes = api("GET", "/nodes")
    ips = {vm["ip"] for vm in candidates}
    guest_checks = 0
    for node in nodes:
        # Look for orphan backing volumes as well as assigned VMIDs.
        for storage in api("GET", "/nodes/" + node["node"] + "/storage"):
            if storage.get("enabled") and storage.get("active") and "images" in storage.get("content", "").split(","):
                volumes = api("GET", "/nodes/" + node["node"] + "/storage/" + storage["storage"] + "/content")
                if any(volume.get("vmid") in {vm["vmid"] for vm in candidates} for volume in volumes):
                    raise RuntimeError("Existing candidate backing volume; refusing")
    for entry in resources:
        if entry.get("type") == "qemu" and entry.get("status") == "running":
            interfaces = api("GET", f'/nodes/{entry["node"]}/qemu/{entry["vmid"]}/agent/network-get-interfaces')
            for interface in interfaces.get("result", []):
                if any(address.get("ip-address") in ips for address in interface.get("ip-addresses", [])):
                    raise RuntimeError("Candidate assigned to running guest; refusing")
            guest_checks += 1
    source = '''import pathlib,json,re
ips=PLACEHOLDER
hits=[]
for kind in ("qemu-server", "lxc"):
 for p in pathlib.Path("/etc/pve/nodes").glob("*/"+kind+"/*.conf"):
  if ips.intersection(re.findall(r"(?<![0-9.])10\\.10\\.1\\.[0-9]+(?![0-9.])",p.read_text())): hits.append(str(p))
print(json.dumps(hits))
'''
    source = source.replace("PLACEHOLDER", repr(ips))
    hits = json.loads(remote("proxmox1.yiucloud.com", "python3 -", source))
    if hits:
        raise RuntimeError("Candidate in existing cluster configuration; refusing")
    net = netbox_check() if netbox_check else netbox(netbox_source())
    probe = '''import subprocess,json
results={}
for ip in PLACEHOLDER:
 ping=subprocess.run(["ping","-c","2","-W","1",ip],capture_output=True)
 neighbor=subprocess.run(["ip","-j","neighbor","show",ip],capture_output=True,check=True)
 entries=json.loads(neighbor.stdout)
 if ping.returncode==0 or any(e.get("lladdr") or "REACHABLE" in e.get("state",[]) for e in entries): raise SystemExit(1)
 results[ip]={"ping_reply":False,"neighbor_has_mac":False}
print(json.dumps(results))
'''
    probe = probe.replace("PLACEHOLDER", repr(tuple(sorted(ips))))
    neighbors = json.loads(remote("10.10.1.27", "python3 -", probe))
    template = api("GET", "/nodes/proxmox1/qemu/9103/config")
    if template.get("template") != 1 or template.get("name") != "ubuntu-2404-template" or "size=32G" not in template.get("scsi0", ""):
        raise RuntimeError("Unexpected template identity or disk size")
    return {"candidates": candidates, "node": "proxmox1", "template": 9103,
        "template_digest": template["digest"], "storage": "vm-storage", "cores": 2,
        "memory_mib": 2048, "disk_gib": 32, "ssh_user": "cloud-user",
        "gateway": "10.10.1.1", "dns": "10.10.1.12", "tag": TAG,
        "ssh_public_key_sha256": hashlib.sha256(SSH_KEY.with_suffix(".pub").read_bytes()).hexdigest(),
        "netbox": net, "neighbors": neighbors, "running_guest_interfaces_checked": guest_checks,
        "backend_network": {"direct": "only Hub 10.10.1.96 and guest loopback", "node": "guest loopback only"},
        "public_edge_mutations": False}


def plan_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


EFI_ADVISORY = [
 "WARN: EFI disk without 'ms-cert=2023k' option, suggesting that not all UEFI 2023",
 "certificates from Microsoft are enrolled yet.",
 "The UEFI 2011 certificates expire in June 2026! The new certificates are required",
 "for secure boot update for Windows and common Linux distributions.",
 "Use 'Disk Action > Enroll Updated Certificates' in the UI or, while the VM is",
 "shut down, run 'qm enroll-efi-keys VMID' to enroll the new certificates.",
 "For Windows with BitLocker, run the following command inside Powershell:",
 "  manage-bde -protectors -disable <drive>",
 "for each drive with BitLocker (for example, <drive> could be 'C:').",
 "This is required for each drive with BitLocker before proceeding with enrollment.",
 "Otherwise, you will be prompted for the BitLocker recovery key on the next boot.",
 "TASK WARNINGS: 1",
]


def wait(task, start_vmid=None):
    if not task:
        return
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        path = "/nodes/proxmox1/tasks/" + urllib.parse.quote(task, safe="")
        status = api("GET", path + "/status")
        if status["status"] == "stopped":
            if status.get("exitstatus") == "OK":
                return
            if start_vmid and status.get("exitstatus") == "WARNINGS: 1" and f":qmstart:{start_vmid}:" in task:
                lines = [entry["t"] for entry in api("GET", path + "/log")]
                warning = [line.replace(f"qm enroll-efi-keys {start_vmid}", "qm enroll-efi-keys VMID") for line in lines if line and line != "generating cloud-init ISO"]
                running = api("GET", f"/nodes/proxmox1/qemu/{start_vmid}/status/current")["status"] == "running"
                if warning == EFI_ADVISORY and running:
                    return {"start_only_template_efi_advisory": True, "vmid": start_vmid, "task": task, "running_independently_verified": True}
            raise RuntimeError("New fixture VM task did not complete successfully")
        time.sleep(2)
    raise TimeoutError("New fixture VM task exceeded bounded deadline")


def apply(value, reviewed):
    if reviewed != plan_hash(value):
        raise RuntimeError("Reviewed plan hash differs from fresh collision preflight")
    if STATE.exists():
        raise RuntimeError("Existing provision state: inspect instead of retrying")
    state = {"plan_sha256": reviewed, "plan": value, "steps": [], "status": "in_progress"}
    private_write(STATE, state)
    def record(step):
        state["steps"].append(step)
        # Preserve a private step journal; never overwrite unrelated files.
        with STATE.open("w") as file:
            json.dump(state, file, indent=2)
    record({"netbox": netbox(netbox_source(True))})
    key = SSH_KEY.with_suffix(".pub").read_text().strip()
    if not key.startswith("ssh-ed25519 "):
        raise RuntimeError("Unexpected lab public key type")
    for vm in CANDIDATES:
        prefix = f'/nodes/proxmox1/qemu/{vm["vmid"]}'
        wait(api("POST", "/nodes/proxmox1/qemu/9103/clone", newid=vm["vmid"], name=vm["name"], full=1, storage="vm-storage"))
        record({"cloned_vmid": vm["vmid"]})
        api("PUT", prefix + "/config", cores=2, memory=2048, ciuser="cloud-user",
            sshkeys=urllib.parse.quote(key, safe=""), ipconfig0="ip=" + vm["ip"] + "/24,gw=10.10.1.1",
            nameserver="10.10.1.12", searchdomain="yiucloud.com", onboot=0,
            tags=TAG + ";os-ubuntu-24-04", description="Owner-authorized isolated application fixture; feature 010; no public backend")
        warning = wait(api("POST", prefix + "/status/start"), start_vmid=vm["vmid"])
        if warning:
            record(warning)
        record({"started_vmid": vm["vmid"], "ip": vm["ip"]})
        print("Started new fixture VM", vm["vmid"], vm["ip"], flush=True)
    state["status"] = "vms_started_fixture_install_pending"
    record({"complete": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--reviewed-plan-sha256")
    args = parser.parse_args()
    if args.apply and not re.fullmatch(r"[0-9a-f]{64}", args.reviewed_plan_sha256 or ""):
        parser.error("Apply requires an exact reviewed plan hash")
    value = plan()
    if args.apply:
        apply(value, args.reviewed_plan_sha256)
    else:
        print(json.dumps({"plan": value, "sha256": plan_hash(value)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # HTTP/SSH errors may contain credential-bearing diagnostic data.
        raise SystemExit("Fixture provisioning stopped: " + (str(error) if isinstance(error, (RuntimeError, TimeoutError)) else type(error).__name__ + "; private details withheld"))
