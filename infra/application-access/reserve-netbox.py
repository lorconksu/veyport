"""Execute only through provision.py in NetBox's Django management shell.

Default is read-only. A transaction adds new records and native change audits;
existing VM, interface, tag or address descriptions are never edited.
"""
import json
import uuid
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q
from extras.models import Tag
from virtualization.models import Cluster, VirtualMachine, VMInterface
from ipam.models import IPAddress

actor = get_user_model().objects.get(username="wyiu", is_superuser=True)
cluster = Cluster.objects.get(name="home")
reason = "Owner-authorized Veyport application-access prototype: isolated new private fixtures, VM126/127."
request_id = uuid.uuid4()


def save(obj, action="create"):
    obj._changelog_message = reason
    obj.full_clean()
    obj.save()
    change = obj.to_objectchange(action)
    change.user = actor
    change.user_name = actor.username
    change.request_id = request_id
    change.full_clean()
    change.save()


with transaction.atomic():
    ip_query = Q()
    for vm in CANDIDATES:
        ip_query |= Q(address__net_host=vm["ip"])
    if IPAddress.objects.filter(ip_query).exists() or VirtualMachine.objects.filter(name__in=[vm["name"] for vm in CANDIDATES]).exists():
        raise RuntimeError("Existing candidate NetBox IP or VM record; refusing")
    tag = Tag.objects.filter(slug=TAG).first()
    # An existing lab tag may be reused, never rewritten.
    if tag and tag.name != TAG:
        raise RuntimeError("Existing tag name differs; refusing")
    result = {"cluster_id": cluster.pk, "cluster_name": cluster.name, "candidate_ips_absent": True, "candidate_names_absent": True}
    if APPLY:
        if tag is None:
            tag = Tag(name=TAG, slug=TAG, color="0369a1")
            save(tag)
        created = []
        for vm in CANDIDATES:
            guest = VirtualMachine(name=vm["name"], cluster=cluster, status="planned", vcpus=2, memory=2048, disk=32768,
                description=f'Application fixture VMID {vm["vmid"]} on proxmox1; {vm["mode"]}; backend private', comments=reason)
            save(guest)
            guest.tags.add(tag)
            interface = VMInterface(virtual_machine=guest, name="ens18", description="Private fixtures: Hub-only direct or node loopback")
            save(interface)
            address = IPAddress(address=vm["ip"] + "/24", status="reserved", assigned_object_type=ContentType.objects.get_for_model(VMInterface),
                assigned_object_id=interface.pk, description=reason)
            save(address)
            address.tags.add(tag)
            guest.snapshot()
            guest.primary_ip4 = address
            save(guest, "update")
            created.append({"vm_record": guest.pk, "ip_record": address.pk, "vmid": vm["vmid"], "ip": vm["ip"]})
        result["created"] = created
        result["request_id"] = str(request_id)
    print("VEYPORT_PLAN=" + json.dumps(result, sort_keys=True))
