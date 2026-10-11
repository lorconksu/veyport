#!/usr/bin/env python3
"""Qualify the prototype long-lived synthetic policy/ledger metadata bucket only.

3650 days is the lab policy-anchor setting, not a regulatory retention default.
Never put raw payloads or execution/original-read records in this bucket.
"""
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
from botocore.exceptions import ClientError

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('qualify',HERE/'qualify.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
BUCKET='audit-governance'
admin=q.client('admin');writer=q.client('writer')
try:admin.head_bucket(Bucket=BUCKET)
except ClientError as error:
    assert error.response['ResponseMetadata']['HTTPStatusCode']==404
    admin.create_bucket(Bucket=BUCKET,ObjectLockEnabledForBucket=True)
admin.put_bucket_versioning(Bucket=BUCKET,VersioningConfiguration={'Status':'Enabled'})
admin.put_object_lock_configuration(Bucket=BUCKET,ObjectLockConfiguration={'ObjectLockEnabled':'Enabled','Rule':{'DefaultRetention':{'Mode':'COMPLIANCE','Days':3651}}})
admin.put_bucket_encryption(Bucket=BUCKET,ServerSideEncryptionConfiguration={'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'aws:kms','KMSMasterKeyID':'audit-archive'}}]})
assert writer.get_bucket_versioning(Bucket=BUCKET)['Status']=='Enabled'
assert writer.get_object_lock_configuration(Bucket=BUCKET)['ObjectLockConfiguration']['Rule']['DefaultRetention']=={'Mode':'COMPLIANCE','Days':3651}
state=json.loads(q.STATE.read_text())
key='qualification/policy.'+secrets.token_hex(12)
body=json.dumps({'event_type':'policy.synthetic_qualification','policy_hash':secrets.token_hex(32),'raw_payloads':False},sort_keys=True).encode()
before=datetime.now(timezone.utc)
response=writer.put_object(Bucket=BUCKET,Key=key,Body=body,IfNoneMatch='*',ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive',Metadata={'sha256':hashlib.sha256(body).hexdigest()})
version=response['VersionId']
retention=writer.get_object_retention(Bucket=BUCKET,Key=key,VersionId=version)['Retention']
assert retention['Mode']=='COMPLIANCE' and retention['RetainUntilDate']>=before+timedelta(days=3650)
state['objects'].append({'bucket':BUCKET,'key':key,'version':version,'sha256':hashlib.sha256(body).hexdigest(),'retain_until':retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
q.STATE.write_text(json.dumps(state,indent=2))
try:writer.put_object(Bucket=BUCKET,Key=key,Body=b'changed',IfNoneMatch='*')
except ClientError as error:assert error.response['ResponseMetadata']['HTTPStatusCode']==412
else:raise AssertionError('Governance conditional replacement permitted')
versions=[v for v in admin.list_object_versions(Bucket=BUCKET,Prefix=key)['Versions'] if v['Key']==key]
assert len(versions)==1
q.denied('governance writer delete marker',lambda:writer.delete_object(Bucket=BUCKET,Key=key))
q.denied('governance writer exact deletion',lambda:writer.delete_object(Bucket=BUCKET,Key=key,VersionId=version))
q.denied('governance writer retention reduction',lambda:writer.put_object_retention(Bucket=BUCKET,Key=key,VersionId=version,Retention={'Mode':'COMPLIANCE','RetainUntilDate':before+timedelta(days=1)}))
q.denied('governance admin compliance deletion',lambda:admin.delete_object(Bucket=BUCKET,Key=key,VersionId=version))
q.denied('governance admin compliance shortening',lambda:admin.put_object_retention(Bucket=BUCKET,Key=key,VersionId=version,Retention={'Mode':'COMPLIANCE','RetainUntilDate':before+timedelta(days=1)}))
q.verify(admin,{'objects':[state['objects'][-1]]})
print('PASS governance versioning/SSE-KMS/default COMPLIANCE3651days; promised minimum3650days/conditional immutable synthetic policy',version,flush=True)
