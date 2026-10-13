"""Execute inside the authorized NetBox Django shell with LAB_INVENTORY JSON.

Validated ORM writes, transaction, snapshots and native ObjectChange audit records.
No existing unrelated records may be updated; a repeated reservation is read-only.
"""
import json
import os
import uuid
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from extras.models import Tag
from virtualization.models import Cluster, VirtualMachine, VMInterface
from ipam.models import IPAddress

inv = json.loads(os.environ['LAB_INVENTORY'])
actor = get_user_model().objects.get(username=os.environ.get('NETBOX_ACTOR', 'wyiu'), is_superuser=True)
request_id = uuid.uuid4()
reason = 'Codex on behalf of owner: requested six isolated Veyport feature 011 audit prototype VMs and NetBox allocation.'


def save(obj, action='create'):
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
    cluster = Cluster.objects.get(name=inv['cluster'])
    tag = Tag.objects.filter(slug=inv['tag']).first()
    if tag is None:
        tag = Tag(name=inv['tag'], slug=inv['tag'], color='0369a1')
        save(tag)
    for vm in inv['vms']:
        name, address = vm['name'], vm['address']
        existing = VirtualMachine.objects.filter(name=name, cluster=cluster).first()
        ip = IPAddress.objects.filter(address=address).first()
        if existing:
            if not existing.tags.filter(pk=tag.pk).exists() or not ip or existing.primary_ip4_id != ip.pk:
                raise RuntimeError('Conflicting existing lab record: ' + name)
            print('existing', name, existing.pk, ip.pk)
            continue
        if ip or IPAddress.objects.filter(address__net_host=address.split('/')[0]).exists():
            raise RuntimeError('Address conflict: ' + address)
        guest = VirtualMachine(name=name, cluster=cluster, status='planned', vcpus=vm['cores'],
            memory=vm['memory_mib'], disk=vm['disk_gib']*1024,
            description=f"Veyport audit lab VMID {vm['vmid']} on {vm['node']}", comments=reason)
        save(guest)
        guest.tags.add(tag)
        interface = VMInterface(virtual_machine=guest, name='ens18', description='Lab LAN; guest firewall restricts role paths')
        save(interface)
        ip = IPAddress(address=address, status='reserved', assigned_object_type=ContentType.objects.get_for_model(VMInterface),
            assigned_object_id=interface.pk, dns_name=name+'.yiucloud.com', description=reason)
        save(ip)
        ip.tags.add(tag)
        guest.snapshot()
        guest.primary_ip4 = ip
        save(guest, 'update')
        print('reserved', name, guest.pk, ip.pk, address)
print('request_id', request_id)
