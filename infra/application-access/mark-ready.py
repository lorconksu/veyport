#!/usr/bin/env python3
"""Audit only the exact new NetBox records after actual fixture readiness."""
import json
from pathlib import Path

import provision as lab

state = json.loads(lab.STATE.read_text())
evidence = json.loads((Path.home() / ".cache/veyport-app-access/infra/fixture-installed.json").read_text())
if {item["vmid"] for item in evidence["fixtures"]} != {126, 127} or not all(item["http_https_health"] for item in evidence["fixtures"]):
    raise SystemExit("Actual isolated fixture readiness evidence required")
expected = state["steps"][0]["netbox"]["created"]
source = "EXPECTED=" + repr(expected) + "\nCANDIDATES=" + repr(lab.CANDIDATES) + "\nTAG=" + repr(lab.TAG) + "\n" + '''
import json,uuid
from django.contrib.auth import get_user_model
from django.db import transaction
from ipam.models import IPAddress
from virtualization.models import VirtualMachine
actor=get_user_model().objects.get(username="wyiu",is_superuser=True)
request_id=uuid.uuid4()
reason="Observed new isolated application fixture VM readiness and HTTP/verified private-CA HTTPS health."
def save(obj):
 obj._changelog_message=reason
 obj.full_clean();obj.save()
 change=obj.to_objectchange("update");change.user=actor;change.user_name=actor.username;change.request_id=request_id;change.full_clean();change.save()
changed=[]
with transaction.atomic():
 for allocation,vm in zip(EXPECTED,CANDIDATES,strict=True):
  guest=VirtualMachine.objects.get(pk=allocation["vm_record"],name=vm["name"],cluster__name="home")
  address=IPAddress.objects.get(pk=allocation["ip_record"],address=vm["ip"]+"/24")
  if guest.primary_ip4_id!=address.pk or not guest.tags.filter(slug=TAG).exists() or address.assigned_object.virtual_machine_id!=guest.pk: raise RuntimeError("Owned allocation differs")
  if guest.status not in ("planned","active") or address.status not in ("reserved","active"): raise RuntimeError("Unexpected owned allocation state")
  # Preserve descriptions/comments; reflect the observed template NIC name.
  interface=address.assigned_object
  if interface.name not in ("ens18","eth0"): raise RuntimeError("Unexpected new fixture interface")
  if interface.name!="eth0":
   interface.snapshot();interface.name="eth0";save(interface)
  if guest.status!="active":
   guest.snapshot();guest.status="active";save(guest)
  if address.status!="active":
   address.snapshot();address.status="active";save(address)
  changed.append({"vm_record":guest.pk,"ip_record":address.pk,"vmid":vm["vmid"],"status":guest.status,"ip_status":address.status})
print("VEYPORT_PLAN="+json.dumps({"records":changed,"request_id":str(request_id)}))
'''
result = lab.netbox(source)
lab.private_write(Path.home() / ".cache/veyport-app-access/infra/netbox-ready.json", result)
print("Exact new NetBox VM/IP records marked active with native audit")
