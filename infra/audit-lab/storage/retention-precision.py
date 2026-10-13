#!/usr/bin/env python3
"""Verify backend margins preserve exact fractional application promises."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
from datetime import datetime,timedelta,timezone

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('qualify',HERE/'qualify.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
state=json.loads(q.STATE.read_text())
for bucket,minimum_days,storage_days in [('audit-originals',1,2),('audit-governance',3650,3651)]:
    actual=q.client('writer').get_object_lock_configuration(Bucket=bucket)['ObjectLockConfiguration']['Rule']['DefaultRetention']
    assert actual=={'Mode':'COMPLIANCE','Days':storage_days}
    key='qualification/policy.precision-'+secrets.token_hex(8)
    body=b'{"synthetic":"retention timestamp precision","raw_payloads":false}'
    promised=datetime.now(timezone.utc)+timedelta(days=minimum_days)
    response=q.client('writer').put_object(Bucket=bucket,Key=key,Body=body,ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive',Metadata={'sha256':hashlib.sha256(body).hexdigest(),'retain-until':promised.isoformat()})
    head=q.client('writer').head_object(Bucket=bucket,Key=key,VersionId=response['VersionId'])
    retention=q.client('writer').get_object_retention(Bucket=bucket,Key=key,VersionId=response['VersionId'])['Retention']
    assert retention['Mode']=='COMPLIANCE'
    assert head['ObjectLockRetainUntilDate']==retention['RetainUntilDate']>=promised,'Fractional minimum promise undershot'
    assert head['Metadata']['retain-until']==promised.isoformat(),'Canonical promised deadline changed'
    assert head['Metadata']['sha256']==hashlib.sha256(body).hexdigest()
    print('PASS',bucket,'version',response['VersionId'],'promised',promised.isoformat(),'HEAD/GetRetention',retention['RetainUntilDate'].isoformat(),'margin_seconds',(retention['RetainUntilDate']-promised).total_seconds(),flush=True)
    state['objects'].append({'bucket':bucket,'key':key,'version':response['VersionId'],'sha256':hashlib.sha256(body).hexdigest(),'promised_minimum':promised.isoformat(),'metadata_sha256':hashlib.sha256(body).hexdigest(),'retain_until':retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
    q.STATE.write_text(json.dumps(state,indent=2))
