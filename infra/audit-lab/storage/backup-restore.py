#!/usr/bin/env python3
"""Encrypted consistent archive/key backup and actual restoration qualification.

Only the two authorized synthetic lab guests are affected. Original encrypted
directories remain preserved after restoration; no locked originals are deleted.
Plain archive bytes travel via SSH and memory, never a controller plaintext file.
AES-256-GCM authenticates the whole backup before extraction. Keep its separate
0600 controller backup key and the LUKS/unseal recovery material safely.
"""
import hashlib
import importlib.util
from pathlib import Path
import secrets
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('deploy',HERE/'deploy.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
KEY=d.PRIVATE/'backup-aes-gcm.key'
if not KEY.exists():KEY.write_bytes(secrets.token_bytes(32));KEY.chmod(0o600)
key=KEY.read_bytes()
MAGIC=b'VEYPORT-GCM-001\x00\x00'


def guarded(ip):
    d.remote(ip,'sudo mountpoint -q /srv/veyport')
    if ip=='10.10.1.62':d.remote(ip,'sudo /usr/local/sbin/veyport-archive-volume-check')


def encrypt_backup(ip,name):
    guarded(ip)
    path=d.PRIVATE/(name+'.backup.gcm')
    nonce=secrets.token_bytes(12)
    encryptor=Cipher(algorithms.AES(key),modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    proc=subprocess.Popen(d.SSH+['cloud-user@'+ip,'sudo tar -C /srv/veyport -czf - data config tls'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with path.open('wb') as output:
        output.write(MAGIC+nonce)
        while chunk:=proc.stdout.read(256*1024):output.write(encryptor.update(chunk))
        output.write(encryptor.finalize());output.write(encryptor.tag)
    if proc.wait()!=0:raise RuntimeError('Consistent archive stream failed')
    path.chmod(0o600)
    print('encrypted backup',name,path.stat().st_size,'bytes sha256',hashlib.sha256(path.read_bytes()).hexdigest(),flush=True)
    return path


def restore(ip,name,path):
    guarded(ip)
    d.remote(ip,'sudo mountpoint -q /srv/veyport && sudo mkdir -m700 -p /srv/veyport/restore')
    with path.open('rb') as source:
        assert source.read(len(MAGIC))==MAGIC
        nonce=source.read(12)
        source.seek(-16,2);tag=source.read(16)
        remaining=path.stat().st_size-len(MAGIC)-12-16
        source.seek(len(MAGIC)+12)
        decryptor=Cipher(algorithms.AES(key),modes.GCM(nonce,tag)).decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        # Anonymous RAM-only file: verify authentication before remote extraction.
        import os
        descriptor=os.memfd_create('veyport-verified-restore',os.MFD_CLOEXEC)
        with os.fdopen(descriptor,'w+b') as plain:
            while remaining:
                chunk=source.read(min(256*1024,remaining));remaining-=len(chunk)
                if not chunk:raise RuntimeError('Truncated encrypted backup')
                plain.write(decryptor.update(chunk))
            plain.write(decryptor.finalize());plain.seek(0)
            proc=subprocess.Popen(d.SSH+['cloud-user@'+ip,'sudo mountpoint -q /srv/veyport && sudo tar -C /srv/veyport/restore -xzf -'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            while chunk:=plain.read(256*1024):proc.stdin.write(chunk)
            proc.stdin.close()
            if proc.wait()!=0:raise RuntimeError('Encrypted-mount restore extraction failed')
    preserved='/srv/veyport/before-restore-'+secrets.token_hex(6)
    d.remote(ip,'sudo mountpoint -q /srv/veyport && sudo mkdir -m700 '+preserved+' && for directory in data config tls; do sudo mv /srv/veyport/$directory '+preserved+'/$directory && sudo mv /srv/veyport/restore/$directory /srv/veyport/$directory || exit 1; done')
    print('PASS authenticated encrypted backup restored',name,'original directories preserved',preserved,flush=True)


archive_units='nginx veyport-seaweed-s3 veyport-seaweed-filer veyport-seaweed-volume veyport-seaweed-master postgresql@16-audit'
for ip,name,units in [('10.10.1.62','audit-store-lab',archive_units),('10.10.1.63','audit-keys-lab','veyport-openbao')]:
    guarded(ip)
    d.remote(ip,'sudo mountpoint -q /srv/veyport && sudo systemctl stop '+units)
    try:
        backup=encrypt_backup(ip,name)
        restore(ip,name,backup)
    finally:
        guarded(ip)
        d.remote(ip,'sudo mountpoint -q /srv/veyport && sudo systemctl start '+units)
    if name=='audit-keys-lab':d.keys()
spec=importlib.util.spec_from_file_location('qualify',HERE/'qualify.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
import json,time
control=json.loads(q.STATE.read_text())['objects'][0]
started=time.monotonic()
deadline=started+180
while time.monotonic()<deadline:
    try:
        response=q.client('admin').get_object(Bucket=control.get('bucket',q.BUCKET),Key=control['key'],VersionId=control['version'])
        assert hashlib.sha256(response['Body'].read()).hexdigest()==control['sha256'],'Restored control integrity failure'
        print('restored exact-version startup readiness seconds',round(time.monotonic()-started,3),flush=True)
        break
    except AssertionError:raise
    except Exception as error:
        print('restored startup unavailable',type(error).__name__,'elapsed',round(time.monotonic()-started,3),flush=True)
        time.sleep(1)
else:raise RuntimeError('Restored archive exact-version readiness deadline')
q.verify(q.client('admin'),json.loads(q.STATE.read_text()))
print('PASS restored archive metadata, encrypted data, exact versions, retention and independently restored OpenBao key decrypt all synthetic originals',flush=True)
