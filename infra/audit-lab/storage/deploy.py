#!/usr/bin/env python3
"""Controller-only pinned storage bootstrap. Private state lives outside repo.

Run after bootstrap.sh on all guests. No secret values are printed. No Docker
context is used. Every command addresses an explicit authorized guest IP.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tarfile
import time
import urllib.request
import urllib.error

HERE = Path(__file__).resolve().parent
PRIVATE = Path.home() / '.local/share/veyport-audit-lab/secrets'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=5', '-i', str(Path.home()/'.ssh/yiucloud')]
os.umask(0o077)


def remote(ip, command, data=None, capture=True):
    result = subprocess.run(SSH + ['cloud-user@'+ip, command], input=data, capture_output=capture)
    if result.returncode:
        raise RuntimeError(f'{ip}: remote command failed ({result.returncode}); inspect guest service journal')
    return result.stdout


def write(ip, path, data):
    if not path.startswith('/srv/veyport/'):
        raise ValueError('Private files must be on encrypted volume')
    remote(ip, 'sudo mountpoint -q /srv/veyport && sudo tee '+path+' >/dev/null && sudo chmod 600 '+path, data.encode() if isinstance(data,str) else data)


def mounted(ip):
    deadline=time.monotonic()+900
    while time.monotonic()<deadline:
        try:
            remote(ip,'sudo mountpoint -q /srv/veyport');return
        except RuntimeError:time.sleep(3)
    raise RuntimeError(ip+': encrypted bootstrap mount deadline')


def tls(ip, name):
    for source, dest in [('ca.crt','ca.crt'),(name+'.crt','server.crt'),(name+'.key','server.key')]:
        write(ip, '/srv/veyport/tls/'+dest, (PRIVATE/source).read_bytes())


def binary(ip, archive_name, name, sha):
    archive = Path('/tmp/veyport-lab-binaries')/archive_name
    if hashlib.sha256(archive.read_bytes()).hexdigest() != sha:
        raise RuntimeError('Pinned artifact digest mismatch')
    with tarfile.open(archive) as tar:
        data = tar.extractfile(name).read()
    expected=hashlib.sha256(data).hexdigest()
    existing=remote(ip,'if test -f /usr/local/bin/'+name+'; then sha256sum /usr/local/bin/'+name+'; fi').decode().split()
    if existing and existing[0]==expected:
        return
    remote(ip, 'sudo tee /usr/local/bin/'+name+'.new >/dev/null && sudo chmod 755 /usr/local/bin/'+name+'.new && sudo mv /usr/local/bin/'+name+'.new /usr/local/bin/'+name, data)


def bao(method, path, data=None, token=None):
    payload=json.dumps(data).encode() if data is not None else None
    headers={'Content-Type':'application/json'}
    if token: headers['X-Vault-Token']=token
    request=urllib.request.Request('https://10.10.1.63:8200/v1/'+path, data=payload, method=method, headers=headers)
    with urllib.request.urlopen(request,context=ssl.create_default_context(cafile=str(PRIVATE/'ca.crt')),timeout=20) as response:
        return json.load(response) if response.status!=204 else None


def keys():
    ip='10.10.1.63'
    mounted(ip)
    tls(ip,'audit-keys-lab')
    lock=json.loads((HERE/'deployment-lock.json').read_text())
    binary(ip,'openbao-2.7.1.tar.gz','bao',lock['openbao']['sha256'])
    remote(ip, 'sudo bash -s', (HERE/'install-openbao.sh').read_bytes())
    for _ in range(30):
        try:
            initialized=bao('GET','sys/init')['initialized'];break
        except Exception:time.sleep(1)
    else:raise RuntimeError('OpenBao TLS startup deadline')
    state_path=PRIVATE/'openbao-init.json'
    if not initialized:
        state_path.write_text(json.dumps(bao('PUT','sys/init',{'secret_shares':5,'secret_threshold':3})))
        state_path.chmod(0o600)
    state=json.loads(state_path.read_text())
    seal=bao('GET','sys/seal-status')
    if seal['sealed']:
        for key in state['keys_base64'][:3]:
            try:bao('PUT','sys/unseal',{'key':key})
            except urllib.error.HTTPError as error:
                if error.code != 500 or bao('GET','sys/seal-status')['sealed']:
                    raise
    for _ in range(30):
        try:
            bao('GET','sys/health');break
        except urllib.error.HTTPError:time.sleep(1)
    else:raise RuntimeError('OpenBao active readiness deadline')
    token=state['root_token']
    mounts=bao('GET','sys/mounts',token=token)
    if 'transit/' not in mounts:bao('POST','sys/mounts/transit',{'type':'transit'},token)
    bao('POST','transit/keys/audit-archive',{'type':'aes256-gcm96'},token)
    policy='path "transit/encrypt/audit-archive" { capabilities=["update"] }\npath "transit/decrypt/audit-archive" { capabilities=["update"] }\npath "transit/keys/audit-archive" { capabilities=["read"] }'
    bao('PUT','sys/policies/acl/seaweed-kms',{'policy':policy},token)
    token_file=PRIVATE/'seaweed-kms-token.json'
    if not token_file.exists():
        issued=bao('POST','auth/token/create',{'policies':['seaweed-kms'],'no_default_policy':True,'ttl':'168h','renewable':True},token)
        token_file.write_text(json.dumps({'token':issued['auth']['client_token']}));token_file.chmod(0o600)
    print('OpenBao TLS initialized/unsealed; restricted transit credential preserved privately',flush=True)


def storage():
    ip='10.10.1.62'
    mounted(ip)
    tls(ip,'audit-store-lab')
    lock=json.loads((HERE/'deployment-lock.json').read_text())
    binary(ip,'seaweedfs-4.48.tar.gz','weed',lock['seaweedfs']['sha256'])
    secret_file=PRIVATE/'s3-credentials.json'
    if not secret_file.exists():
        secret_file.write_text(json.dumps({name:{'access_key':secrets.token_hex(12),'secret_key':secrets.token_hex(32)} for name in ['admin','writer','reader']}));secret_file.chmod(0o600)
    creds=json.loads(secret_file.read_text())
    pg_file=PRIVATE/'postgres-secret.json'
    if not pg_file.exists():pg_file.write_text(json.dumps({'password':secrets.token_hex(32)}));pg_file.chmod(0o600)
    pg=json.loads(pg_file.read_text())
    write(ip,'/srv/veyport/config/postgres-secret.json',pg_file.read_bytes())
    write(ip,'/srv/veyport/config/filer.toml','[postgres]\nenabled=true\ncreateTable=true\nhostname="127.0.0.1"\nport=5433\nusername="seaweed"\npassword="'+pg['password']+'"\ndatabase="seaweed"\nsslmode="disable"\nconnection_max_idle=4\nconnection_max_open=8\n')
    identities=[]
    for name,c in creds.items():
        actions={'admin':['Admin','Read','List','Write','Tagging'],
                 'writer':[],
                 'reader':['Read:audit-originals/*','GetObjectRetention:audit-originals/*','Read:audit-governance/*','GetObjectRetention:audit-governance/*']}[name]
        identity={'name':name,'credentials':[{'accessKey':c['access_key'],'secretKey':c['secret_key']}],'actions':actions}
        if name=='writer':identity['policyNames']=['archive-writer']
        identities.append(identity)
    token=json.loads((PRIVATE/'seaweed-kms-token.json').read_text())['token']
    kms={'default_provider':'openbao','providers':{'openbao':{'type':'openbao','address':'https://10.10.1.63:8200','token':token,'transit_path':'transit','ca_cert':'/srv/veyport/tls/ca.crt','tls_skip_verify':False,'cache_enabled':False,'request_timeout':5}}}
    writer_policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['s3:PutObject','s3:GetObject','s3:GetObjectVersion','s3:GetObjectRetention'],'Resource':['arn:aws:s3:::audit-originals/*','arn:aws:s3:::audit-governance/*']},{'Effect':'Allow','Action':['s3:ListBucket','s3:GetBucketVersioning','s3:GetBucketObjectLockConfiguration'],'Resource':['arn:aws:s3:::audit-originals','arn:aws:s3:::audit-governance']},{'Effect':'Deny','Action':['s3:DeleteObject','s3:DeleteObjectVersion','s3:PutObjectRetention','s3:PutObjectLegalHold'],'Resource':['arn:aws:s3:::audit-originals/*','arn:aws:s3:::audit-governance/*']}]}
    write(ip,'/srv/veyport/config/s3.json',json.dumps({'identities':identities,'policies':[{'name':'archive-writer','content':json.dumps(writer_policy)}],'kms':kms}))
    remote(ip, 'sudo bash -s', (HERE/'install-seaweed.sh').read_bytes())
    print('SeaweedFS pinned binary, PostgreSQL synchronous metadata and TLS S3 installed',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('role',choices=['keys','storage'])
    args=parser.parse_args()
    {'keys':keys,'storage':storage}[args.role]()
