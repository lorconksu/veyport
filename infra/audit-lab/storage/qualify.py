#!/usr/bin/env python3
"""Real TLS S3 qualification using private controller credentials.

Creates synthetic versions with the qualified 2-day backend default (24h application minimum). Never delete qualification evidence before
retention expiry. --verify-existing verifies saved exact versions after faults.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sys
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

PRIVATE=Path.home()/'.local/share/veyport-audit-lab/secrets'
STATE=PRIVATE/'qualification-objects.json'
BUCKET='audit-originals'


def client(identity):
    creds=json.loads((PRIVATE/'s3-credentials.json').read_text())[identity]
    return boto3.client('s3',endpoint_url='https://10.10.1.62:8333',region_name='us-east-1',
        aws_access_key_id=creds['access_key'],aws_secret_access_key=creds['secret_key'],
        verify=str(PRIVATE/'ca.crt'),config=Config(s3={'addressing_style':'path'},retries={'max_attempts':0},connect_timeout=5,read_timeout=10))


def denied(label,call):
    try:call()
    except ClientError as exc:
        if exc.response['ResponseMetadata']['HTTPStatusCode'] !=403:raise
        print('PASS',label,exc.response['Error']['Code']);return
    raise AssertionError(label+' unexpectedly permitted')


def verify(s3,state):
    for obj in state['objects']:
        bucket=obj.get('bucket',BUCKET)
        response=s3.get_object(Bucket=bucket,Key=obj['key'],VersionId=obj['version'])
        body=response['Body'].read()
        assert hashlib.sha256(body).hexdigest()==obj['sha256'],'Exact-version bytes changed or lost'
        assert response.get('ServerSideEncryption')=='aws:kms','SSE-KMS metadata absent'
        assert response.get('SSEKMSKeyId')=='audit-archive','Independent KMS key identifier changed'
        if 'promised_minimum' in obj:
            assert response['Metadata']['retain-until']==obj['promised_minimum'],'Canonical promised deadline changed after fault'
            assert response['Metadata']['sha256']==obj['metadata_sha256'],'Persisted content hash metadata changed'
            assert response['ObjectLockRetainUntilDate']>=datetime.fromisoformat(obj['promised_minimum']),'Exact fractional promise undershot after fault'
        retention=s3.get_object_retention(Bucket=bucket,Key=obj['key'],VersionId=obj['version'])['Retention']
        assert retention['Mode']=='COMPLIANCE'
        assert retention['RetainUntilDate'].isoformat()==obj['retain_until'],'Retention changed after fault'
        print('PASS exact-version',bucket,obj['version'],obj['sha256'],retention['RetainUntilDate'].isoformat())


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--verify-existing',action='store_true')
    args=parser.parse_args()
    s3=client('admin')
    if args.verify_existing:
        verify(s3,json.loads(STATE.read_text()));return
    try:s3.head_bucket(Bucket=BUCKET)
    except ClientError as exc:
        if exc.response['ResponseMetadata']['HTTPStatusCode']!=404:raise
        s3.create_bucket(Bucket=BUCKET,ObjectLockEnabledForBucket=True)
    s3.put_bucket_versioning(Bucket=BUCKET,VersioningConfiguration={'Status':'Enabled'})
    s3.put_object_lock_configuration(Bucket=BUCKET,ObjectLockConfiguration={'ObjectLockEnabled':'Enabled','Rule':{'DefaultRetention':{'Mode':'COMPLIANCE','Days':2}}})
    s3.put_bucket_encryption(Bucket=BUCKET,ServerSideEncryptionConfiguration={'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'aws:kms','KMSMasterKeyID':'audit-archive'}}]})
    assert s3.get_bucket_versioning(Bucket=BUCKET)['Status']=='Enabled'
    assert s3.get_object_lock_configuration(Bucket=BUCKET)['ObjectLockConfiguration']['Rule']['DefaultRetention']=={'Mode':'COMPLIANCE','Days':2}
    denied('writer bucket retention administration',lambda:client('writer').put_object_lock_configuration(Bucket=BUCKET,ObjectLockConfiguration={'ObjectLockEnabled':'Enabled','Rule':{'DefaultRetention':{'Mode':'COMPLIANCE','Days':2}}}))
    state=json.loads(STATE.read_text()) if STATE.exists() else {'created_at':datetime.now(timezone.utc).isoformat(),'objects':[],'endpoint':'https://10.10.1.62:8333','boto3':boto3.__version__}
    key='qualification/'+secrets.token_hex(12)
    for i in range(4):
        # Synthetic canary and binary bytes force non-inline object storage.
        body=b'VEYPORT_SYNTHETIC_ORIGINAL_CANARY\n'+secrets.token_bytes(256*1024)
        before=datetime.now(timezone.utc)
        response=client('writer').put_object(Bucket=BUCKET,Key=key,Body=body,ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive')
        version=response.get('VersionId')
        assert version and version!='null','Immutable version ID absent'
        retention=s3.get_object_retention(Bucket=BUCKET,Key=key,VersionId=version)['Retention']
        assert retention['Mode']=='COMPLIANCE' and retention['RetainUntilDate']>=before+timedelta(hours=24)
        obj={'key':key,'version':version,'sha256':hashlib.sha256(body).hexdigest(),'retain_until':retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()}
        state['objects'].append(obj);STATE.write_text(json.dumps(state,indent=2));STATE.chmod(0o600)
        print('PASS acknowledged encrypted version',version,obj['sha256'],flush=True)
    first=state['objects'][-4]
    denied('admin version deletion',lambda:s3.delete_object(Bucket=BUCKET,Key=key,VersionId=first['version']))
    denied('writer delete marker creation',lambda:client('writer').delete_object(Bucket=BUCKET,Key=key))
    denied('writer retention reduction',lambda:client('writer').put_object_retention(Bucket=BUCKET,Key=key,VersionId=first['version'],Retention={'Mode':'COMPLIANCE','RetainUntilDate':datetime.now(timezone.utc)+timedelta(hours=1)}))
    denied('writer version deletion',lambda:client('writer').delete_object(Bucket=BUCKET,Key=key,VersionId=first['version']))
    denied('admin retention shortening',lambda:s3.put_object_retention(Bucket=BUCKET,Key=key,VersionId=first['version'],Retention={'Mode':'COMPLIANCE','RetainUntilDate':datetime.now(timezone.utc)+timedelta(hours=1)}))
    denied('compliance governance bypass',lambda:s3.delete_object(Bucket=BUCKET,Key=key,VersionId=first['version'],BypassGovernanceRetention=True))
    marker=s3.delete_object(Bucket=BUCKET,Key=key)
    assert marker.get('DeleteMarker') is True,'Delete marker absent'
    verify(s3,state)
    print('PASS delete marker leaves all exact receipt-bound versions readable')


if __name__=='__main__':main()
