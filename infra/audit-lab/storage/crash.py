#!/usr/bin/env python3
"""Inject faults only into the new archive VM121 and verify exact versions.

Each fault follows a fresh acknowledged PUT. QEMU stop is an unclean guest power
loss; the Proxmox/Ceph hosts remain healthy and are not faulted by this test.
"""
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('qualify',HERE/'qualify.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=3','-i',str(Path.home()/'.ssh/yiucloud')]


def put():
    state=json.loads(q.STATE.read_text())
    body=secrets.token_bytes(512*1024)
    key='qualification/crash-'+secrets.token_hex(12)
    until=datetime.now(timezone.utc).replace(microsecond=0)+timedelta(hours=24,minutes=1)
    response=q.client('admin').put_object(Bucket=q.BUCKET,Key=key,Body=body,ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive',ObjectLockMode='COMPLIANCE',ObjectLockRetainUntilDate=until)
    ack=time.monotonic()
    state['objects'].append({'key':key,'version':response['VersionId'],'sha256':hashlib.sha256(body).hexdigest(),'retain_until':until.isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
    q.STATE.write_text(json.dumps(state,indent=2))
    print('acknowledged',response['VersionId'],hashlib.sha256(body).hexdigest(),flush=True)
    manifest_key='qualification/crash-manifest-'+secrets.token_hex(12)
    manifest=json.dumps({'key':key,'version':response['VersionId'],'sha256':hashlib.sha256(body).hexdigest()},sort_keys=True).encode()
    manifest_response=q.client('writer').put_object(Bucket=q.BUCKET,Key=manifest_key,Body=manifest,IfNoneMatch='*',ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive')
    ack=time.monotonic()
    retention=q.client('admin').get_object_retention(Bucket=q.BUCKET,Key=manifest_key,VersionId=manifest_response['VersionId'])['Retention']
    state['objects'].append({'key':manifest_key,'version':manifest_response['VersionId'],'sha256':hashlib.sha256(manifest).hexdigest(),'retain_until':retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
    governance_key='qualification/policy.crash-'+secrets.token_hex(12)
    governance_body=json.dumps({'event_type':'policy.synthetic_crash','policy_hash':secrets.token_hex(32),'raw_payloads':False},sort_keys=True).encode()
    governance=q.client('writer').put_object(Bucket='audit-governance',Key=governance_key,Body=governance_body,IfNoneMatch='*',ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive',Metadata={'sha256':hashlib.sha256(governance_body).hexdigest()})
    ack=time.monotonic()
    governance_retention=q.client('writer').get_object_retention(Bucket='audit-governance',Key=governance_key,VersionId=governance['VersionId'])['Retention']
    assert governance_retention['Mode']=='COMPLIANCE' and governance_retention['RetainUntilDate']>=datetime.now(timezone.utc)+timedelta(days=3650)-timedelta(seconds=2)
    state['objects'].append({'bucket':'audit-governance','key':governance_key,'version':governance['VersionId'],'sha256':hashlib.sha256(governance_body).hexdigest(),'retain_until':governance_retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
    q.STATE.write_text(json.dumps(state,indent=2))
    return ack


def ready():
    # HEAD bucket only proves metadata availability. During bounded startup,
    # exact-version read of a pre-existing control must also succeed. Once this
    # gate opens, verification of every fresh object runs without retries.
    started=time.monotonic();deadline=started+180
    control=json.loads(q.STATE.read_text())['objects'][0]
    while time.monotonic()<deadline:
        try:
            response=q.client('admin').get_object(Bucket=q.BUCKET,Key=control['key'],VersionId=control['version'])
            body=response['Body'].read()
            assert hashlib.sha256(body).hexdigest()==control['sha256'],'Control object integrity failure'
            print('exact-version startup readiness seconds',round(time.monotonic()-started,3),flush=True)
            return
        except AssertionError:raise
        except Exception as error:
            print('startup unavailable',type(error).__name__,'elapsed',round(time.monotonic()-started,3),flush=True)
            time.sleep(1)
    raise RuntimeError('Archive exact-version readiness deadline')


def verify(label,acknowledged_at=None):
    ready();q.verify(q.client('admin'),json.loads(q.STATE.read_text()))
    print('PASS',label,'verified_at',datetime.now(timezone.utc).isoformat(),'recovery_seconds',round(time.monotonic()-acknowledged_at,3) if acknowledged_at else None,flush=True)


ready()
for unit in ['veyport-seaweed-filer veyport-seaweed-volume','postgresql@16-audit']:
    ack=put()
    subprocess.run(ssh+['cloud-user@10.10.1.62','sudo systemctl kill --signal=SIGKILL --kill-whom=main '+unit],check=True)
    print('fault',unit,'seconds after acknowledgement',round(time.monotonic()-ack,3),flush=True)
    subprocess.run(ssh+['cloud-user@10.10.1.62','sudo systemctl reset-failed '+unit+'; sudo systemctl restart '+unit],check=True)
    verify('acknowledged versions survive SIGKILL '+unit,ack)

for cycle in range(1,4):
    ack=put()
    subprocess.run(['ssh','-o','BatchMode=yes','root@proxmox3.yiucloud.com','qm stop 121'],check=True)
    print('fault unclean QEMU stop cycle',cycle,'seconds after last protected PUT acknowledgement',round(time.monotonic()-ack,3),flush=True)
    subprocess.run(['ssh','-o','BatchMode=yes','root@proxmox3.yiucloud.com','qm start 121'],check=True)
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        if subprocess.run(ssh+['cloud-user@10.10.1.62','sudo -n true'],capture_output=True).returncode==0:break
        time.sleep(1)
    else:raise RuntimeError('Reboot SSH readiness deadline')
    subprocess.run(['bash',str(HERE.parent/'unlock.sh'),'10.10.1.62',str(q.PRIVATE/'audit-store-lab.luks.key')],check=True)
    subprocess.run(ssh+['cloud-user@10.10.1.62','sudo systemctl reset-failed; sudo systemctl start postgresql@16-audit veyport-seaweed-master veyport-seaweed-volume veyport-seaweed-filer veyport-seaweed-s3 nginx'],check=True)
    verify('acknowledged versions survive unclean guest power loss',ack)
