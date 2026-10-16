#!/usr/bin/env python3
"""Narrow reviewed continuation after inherited EFI start advisory for VM126.

Only the exact journal-owned VM126 may already exist. Never re-clone, stop or
modify it. Clone127 only if all fresh checks and exact NetBox reservations pass.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import urllib.parse

import provision as lab

KNOWN_HOSTS = Path.home() / ".cache/veyport-app-access/infra/new-vm-known-hosts"


def ssh_ready(vm):
    # Read SSH host key over the already trusted Proxmox control channel.
    output = lab.remote("proxmox1.yiucloud.com", f'qm guest exec {vm["vmid"]} -- /usr/bin/cat /etc/ssh/ssh_host_ed25519_key.pub')
    result = json.loads(output)
    if result.get("exitcode") != 0:
        raise RuntimeError("New guest SSH key unavailable")
    public = result["out-data"].strip().split()
    if len(public) != 3 or public[0] != "ssh-ed25519":
        raise RuntimeError("Unexpected new guest SSH key")
    line = vm["ip"] + " " + " ".join(public[:2]) + "\n"
    existing = KNOWN_HOSTS.read_text() if KNOWN_HOSTS.exists() else ""
    prior = [entry for entry in existing.splitlines() if entry.startswith(vm["ip"] + " ")]
    if prior and prior != [line.strip()]:
        raise RuntimeError("New guest SSH identity changed")
    if not prior:
        fd = os.open(KNOWN_HOSTS, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(line)
    command = "test " + shlex.quote(vm["name"]) + ' = "$(hostname)" && sudo -n true && cloud-init status --format json'
    response = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
        "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS), "-i", str(lab.SSH_KEY), "cloud-user@" + vm["ip"], command], capture_output=True, text=True, timeout=20)
    try:
        status = json.loads(response.stdout)
    except ValueError:
        raise RuntimeError("New guest SSH/hostname/sudo/readiness response invalid") from None
    deprecation = "'user' of type string is deprecated in 22.2 and scheduled to be removed in 27.2. Use 'users' list instead."
    recoverable = status.get("recoverable_errors", {})
    warnings_ok = not recoverable or (set(recoverable) == {"DEPRECATED"} and set(recoverable["DEPRECATED"]) == {deprecation})
    if response.returncode not in (0, 2) or status.get("status") != "done" or status.get("errors") or not warnings_ok:
        raise RuntimeError("New guest SSH, sudo, hostname or cloud-init readiness not yet verified")
    return {"vmid": vm["vmid"], "ssh_host_key_sha256": __import__("hashlib").sha256(" ".join(public[:2]).encode()).hexdigest(), "ssh_hostname_sudo_cloud_init_verified": True}


def reservations(state):
    expected = state["steps"][0]["netbox"]["created"]
    source = 'EXPECTED=' + repr(expected) + '\n' + 'CANDIDATES=' + repr(lab.CANDIDATES) + '\n' + 'TAG=' + repr(lab.TAG) + '\n' + '''
import json
from ipam.models import IPAddress
from virtualization.models import VirtualMachine
for expected,vm in zip(EXPECTED,CANDIDATES,strict=True):
 guest=VirtualMachine.objects.get(pk=expected["vm_record"],name=vm["name"],cluster__name="home",status="planned")
 address=IPAddress.objects.get(pk=expected["ip_record"],address=vm["ip"]+"/24",status="reserved")
 if guest.primary_ip4_id!=address.pk or not guest.tags.filter(slug=TAG).exists() or address.assigned_object.virtual_machine_id!=guest.pk: raise RuntimeError("Owned reservation differs")
 if IPAddress.objects.filter(address__net_host=vm["ip"]).count()!=1: raise RuntimeError("Duplicate reservation")
print("VEYPORT_PLAN="+json.dumps({"exact_owned_reservations_verified":True}))
'''
    return lab.netbox(source)


def main():
    state = json.loads(lab.STATE.read_text())
    if state["plan_sha256"] != "164798ebecc82830de7f564809388532cf8969711e8795c7be79b0fb7175b4d0" or state["status"] != "in_progress" or state["steps"][1] != {"cloned_vmid": 126}:
        raise RuntimeError("Expected exact reviewed partial-state journal")
    vm126,vm127=lab.CANDIDATES
    config=lab.api("GET","/nodes/proxmox1/qemu/126/config")
    key=lab.SSH_KEY.with_suffix(".pub").read_text().strip()
    if config["name"]!=vm126["name"] or lab.TAG not in config.get("tags","").split(";") or str(config["cores"])!="2" or str(config["memory"])!="2048" or "size=32G" not in config["scsi0"] or config["ipconfig0"]!="ip=10.10.1.66/24,gw=10.10.1.1" or urllib.parse.unquote(config["sshkeys"]).strip()!=key:
        raise RuntimeError("VM126 exact authorized identity differs")
    ready=ssh_ready(vm126)
    value=lab.plan([vm127], lambda: reservations(state))
    # Every .67 check remains mandatory even though .66 is already ours.
    def record(step):
        state["steps"].append(step)
        with lab.STATE.open("w") as file: json.dump(state,file,indent=2)
    tasks=lab.api("GET","/nodes/proxmox1/tasks",vmid=126,limit=5)
    starts=[task for task in tasks if task.get("type")=="qmstart"]
    if len(starts)!=1: raise RuntimeError("Expected exactly one VM126 start task")
    advisory=lab.wait(starts[0]["upid"],start_vmid=126)
    record({"existing_vm126_verified":ready,"start_advisory":advisory,"remaining_preflight":value})
    prefix="/nodes/proxmox1/qemu/127"
    lab.wait(lab.api("POST","/nodes/proxmox1/qemu/9103/clone",newid=127,name=vm127["name"],full=1,storage="vm-storage"))
    record({"cloned_vmid":127})
    lab.api("PUT",prefix+"/config",cores=2,memory=2048,ciuser="cloud-user",sshkeys=urllib.parse.quote(key,safe=""),
        ipconfig0="ip=10.10.1.67/24,gw=10.10.1.1",nameserver="10.10.1.12",searchdomain="yiucloud.com",onboot=0,
        tags=lab.TAG+";os-ubuntu-24-04",description="Owner-authorized isolated application fixture; feature 010; no public backend")
    advisory=lab.wait(lab.api("POST",prefix+"/status/start"),start_vmid=127)
    record({"started_vmid":127,"advisory":advisory})
    state["status"]="vms_started_fixture_install_pending"
    record({"complete":True})
    print("Existing VM126 verified; new VM127 cloned and started; private journal retained")


if __name__ == "__main__":
    try: main()
    except Exception as error:
        raise SystemExit("Narrow lab continuation stopped: " + (str(error) if isinstance(error,RuntimeError) else type(error).__name__ + "; private details withheld"))
