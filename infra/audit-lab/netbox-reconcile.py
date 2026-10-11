"""Run in authorized NetBox Django shell after successful guest bootstrap.

Requires LAB_INVENTORY, NETBOX_ACTOR optional (default owner account wyiu).
"""
import json
import os
import uuid
from django.contrib.auth import get_user_model
from django.db import transaction
from virtualization.models import Cluster, VirtualMachine, VMInterface
from ipam.models import IPAddress

inv=json.loads(os.environ['LAB_INVENTORY'])
actor=get_user_model().objects.get(username=os.environ.get('NETBOX_ACTOR','wyiu'),is_superuser=True)
request_id=uuid.uuid4()

def save(obj, action):
    obj._changelog_message='Codex on behalf of owner: reconcile verified Veyport feature 011 lab VMID, interface and address allocation.'
    obj.full_clean();obj.save()
    change=obj.to_objectchange(action)
    change.user=actor;change.user_name=actor.username;change.request_id=request_id
    change.full_clean();change.save()
with transaction.atomic():
    cluster=Cluster.objects.get(name=inv['cluster'])
    for vm in inv['vms']:
        guest=VirtualMachine.objects.get(cluster=cluster,name=vm['name'],tags__slug=inv['tag'])
        ip=IPAddress.objects.get(pk=guest.primary_ip4_id)
        if str(ip.address)!=vm['address']:
            raise RuntimeError('Unexpected IP mapping')
        description=f"Veyport audit lab VMID {vm['vmid']} on {vm['node']}; guest nftables isolation; manual-unlock encrypted services"
        if guest.description!=description or guest.status!='active':
            guest.snapshot();guest.description=description;guest.status='active';save(guest,'update')
        interface=VMInterface.objects.get(virtual_machine=guest,pk=ip.assigned_object_id)
        if interface.name!='eth0':
            interface.snapshot();interface.name='eth0';save(interface,'update')
        if ip.status!='active':
            ip.snapshot();ip.status='active';save(ip,'update')
        print('active',guest.name,'vmid',vm['vmid'],'NetBox',guest.pk,'IP',ip.pk)
print('request_id',request_id)
