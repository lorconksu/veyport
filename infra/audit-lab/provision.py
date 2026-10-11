#!/usr/bin/env python3
"""Idempotent creation of the authorized lab only; TLS verification stays enabled.

Run after NetBox reservation and duplicate-address detection. Authentication is
read from environment, never serialized. Existing guests must match name/tag.
"""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', default=str(Path(__file__).with_name('inventory.example.json')))
    parser.add_argument('--ssh-public-key', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    inv = json.loads(Path(args.inventory).read_text())
    key = Path(args.ssh_public_key).read_text().strip()
    if not key.startswith(('ssh-ed25519 ', 'ssh-rsa ', 'ecdsa-')):
        raise SystemExit('Expected public SSH key')
    base = 'https://proxmox1.yiucloud.com:8006/api2/json'

    def api(method, path, **params):
        data = urllib.parse.urlencode(params).encode() if params else None
        request = urllib.request.Request(base + path, data=data, method=method,
            headers={'Authorization': 'PVEAPIToken=' + os.environ['PROXMOX_TOKEN_ID'] + '=' + os.environ['PROXMOX_SECRET']})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)['data']

    def wait(node, task):
        if not task:
            return
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            status = api('GET', f'/nodes/{node}/tasks/{urllib.parse.quote(task,safe="")}/status')
            if status['status'] == 'stopped':
                if status.get('exitstatus') != 'OK' and not status.get('exitstatus','').startswith('WARNINGS:'):
                    raise RuntimeError('Proxmox task failed: ' + status.get('exitstatus', 'unknown'))
                return
            time.sleep(2)
        raise TimeoutError('Proxmox task deadline')

    resources = {r['vmid']: r for r in api('GET', '/cluster/resources') if 'vmid' in r}
    volumes = api('GET', '/nodes/proxmox3/storage/' + inv['storage'] + '/content')
    for vm in inv['vms']:
        existing = resources.get(vm['vmid'])
        if not existing and any(v.get('vmid') == vm['vmid'] for v in volumes):
            raise RuntimeError(f"VMID {vm['vmid']} has existing backing volumes; refusing collision")
        if existing and (existing.get('name') != vm['name'] or inv['tag'] not in existing.get('tags', '').split(';')):
            raise RuntimeError(f"VMID {vm['vmid']} collision; refusing mutation")
    for vm in inv['vms']:
        node, vmid = vm['node'], vm['vmid']
        prefix = f'/nodes/{node}/qemu/{vmid}'
        if not args.apply:
            print('planned', vmid, vm['name'], node, vm['address'])
            continue
        if vmid not in resources:
            print('cloning', vmid, vm['name'], flush=True)
            wait(node, api('POST', f"/nodes/{node}/qemu/{vm['template']}/clone",
                newid=vmid, name=vm['name'], full=1, storage=inv['storage']))
            api('PUT', prefix + '/config', tags=inv['tag'] + ';os-ubuntu-24-04')
        config = api('GET', prefix + '/config')
        # Never reset a running guest or alter its credentials on rerun.
        if api('GET', prefix + '/status/current')['status'] == 'running':
            print('already running', vmid, vm['name'], flush=True)
            continue
        disk = config['scsi0'].split(',')[0]
        api('PUT', prefix + '/config', cores=vm['cores'], memory=vm['memory_mib'],
            ciuser=inv['ssh_user'], sshkeys=urllib.parse.quote(key, safe=''), ipconfig0='ip=' + vm['address'] + ',gw=' + inv['gateway'],
            nameserver=inv['dns'], searchdomain=inv['searchdomain'], tags=inv['tag'] + ';os-ubuntu-24-04',
            description='Owner-authorized isolated synthetic audit prototype; feature 011', onboot=0,
            scsi0=disk + ',cache=writethrough,iothread=1,discard=on')
        if vm['disk_gib'] > 32:
            wait(node, api('PUT', prefix + '/resize', disk='scsi0', size=str(vm['disk_gib']) + 'G'))
        wait(node, api('POST', prefix + '/status/start'))
        print('started', vmid, vm['name'], vm['address'], flush=True)


if __name__ == '__main__':
    main()
