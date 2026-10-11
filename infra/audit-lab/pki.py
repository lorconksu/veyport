#!/usr/bin/env python3
"""Create private synthetic-lab CA, IP SAN certificates and manual LUKS keys."""
import json
import os
from pathlib import Path
import secrets
import subprocess

os.umask(0o077)
private=Path.home()/'.local/share/veyport-audit-lab/secrets'
private.mkdir(parents=True,exist_ok=True);private.chmod(0o700)
inventory=json.loads(Path(__file__).with_name('inventory.example.json').read_text())

def run(*args):
    subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if not (private/'ca.key').exists():
    run('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',private/'ca.key')
if not (private/'ca.crt').exists():
    run('req','-new','-x509','-key',private/'ca.key','-sha256','-days','365','-subj','/CN=Veyport synthetic lab CA',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',private/'ca.crt')
for vm in inventory['vms']:
    name=vm['name'];ip=vm['address'].split('/')[0]
    unlock=private/(name+'.luks.key')
    if not unlock.exists():unlock.write_bytes(secrets.token_bytes(64))
    if (private/(name+'.crt')).exists():continue
    key=private/(name+'.key');csr=private/(name+'.csr');ext=private/(name+'.ext')
    run('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',key)
    run('req','-new','-key',key,'-subj','/CN='+name,'-out',csr)
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:'+name+',DNS:'+name+'.yiucloud.com,IP:'+ip+',IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n')
    run('x509','-req','-in',csr,'-CA',private/'ca.crt','-CAkey',private/'ca.key','-CAcreateserial','-days','90',
        '-sha256','-extfile',ext,'-out',private/(name+'.crt'))
print('Private controller PKI and unlock keys ready; no secret material printed')
