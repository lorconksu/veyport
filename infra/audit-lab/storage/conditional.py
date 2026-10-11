#!/usr/bin/env python3
"""Conditional manifest creation, concurrent first-write and lost-reply recovery."""
from concurrent.futures import ThreadPoolExecutor
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import ssl
import time
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('qualify',HERE/'qualify.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
parser=argparse.ArgumentParser()
parser.add_argument('--bucket',choices=['audit-originals','audit-governance'],default='audit-originals')
q.BUCKET=parser.parse_args().bucket

def versions(key):
    return [v for v in q.client('admin').list_object_versions(Bucket=q.BUCKET,Prefix=key).get('Versions',[]) if v['Key']==key]

key='qualification/conditional-'+secrets.token_hex(12)
body=b'{"event_id":"synthetic-conditional","record_hash":"'+secrets.token_hex(32).encode()+b'"}'
first=q.client('writer').put_object(Bucket=q.BUCKET,Key=key,Body=body,IfNoneMatch='*',ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive')
try:q.client('writer').put_object(Bucket=q.BUCKET,Key=key,Body=b'changed',IfNoneMatch='*')
except ClientError as error:
    assert error.response['ResponseMetadata']['HTTPStatusCode']==412
else:raise AssertionError('Conditional replacement succeeded')
assert len(versions(key))==1
assert q.client('reader').get_object(Bucket=q.BUCKET,Key=key,VersionId=first['VersionId'])['Body'].read()==body
print('PASS sequential If-None-Match:* returns412 without a new version',first['VersionId'],flush=True)

race_key='qualification/race-'+secrets.token_hex(12)
def contender(i):
    try:
        response=q.client('writer').put_object(Bucket=q.BUCKET,Key=race_key,Body=('candidate-'+str(i)).encode(),IfNoneMatch='*',ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive')
        return i,response['VersionId']
    except ClientError as error:
        assert error.response['ResponseMetadata']['HTTPStatusCode'] in [409,412]
        return i,None
with ThreadPoolExecutor(max_workers=8) as pool:result=list(pool.map(contender,range(16)))
winners=[x for x in result if x[1]]
assert len(winners)==1 and len(versions(race_key))==1,'Conditional race admitted multiple manifests'
print('PASS16 contenders yield one immutable manifest',winners[0][1],flush=True)

lost_key='qualification/lost-reply-'+secrets.token_hex(12)
lost_body=b'{"synthetic":"lost reply","digest":"'+secrets.token_hex(32).encode()+b'"}'
c=json.loads((q.PRIVATE/'s3-credentials.json').read_text())['writer']
request=AWSRequest(method='PUT',url='https://10.10.1.62:8333/'+q.BUCKET+'/'+lost_key,data=lost_body,
    headers={'Host':'10.10.1.62:8333','Content-Length':str(len(lost_body)),'If-None-Match':'*','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':'audit-archive'})
S3SigV4Auth(Credentials(c['access_key'],c['secret_key']),'s3','us-east-1').add_auth(request)
wire=('PUT /'+q.BUCKET+'/'+lost_key+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in request.headers.items())+'\r\n').encode()+lost_body
context=ssl.create_default_context(cafile=str(q.PRIVATE/'ca.crt'))
with socket.create_connection(('10.10.1.62',8333),timeout=5) as tcp:
    with context.wrap_socket(tcp,server_hostname='10.10.1.62') as tls:
        tls.sendall(wire)
        # Never read the response; keep transport open until another connection
        # observes committed metadata, then discard the buffered reply.
        for _ in range(100):
            found=versions(lost_key)
            if found:break
            time.sleep(.1)
        else:raise RuntimeError('Lost-reply write did not commit; caller remains uncertain')
assert len(found)==1
assert q.client('reader').get_object(Bucket=q.BUCKET,Key=lost_key,VersionId=found[0]['VersionId'])['Body'].read()==lost_body
print('PASS reply discarded; one exact manifest version reconciles matching bytes',found[0]['VersionId'],flush=True)

state=json.loads(q.STATE.read_text())
for object_key,version,payload in [(key,first['VersionId'],body),(race_key,winners[0][1],('candidate-'+str(winners[0][0])).encode()),(lost_key,found[0]['VersionId'],lost_body)]:
    retention=q.client('admin').get_object_retention(Bucket=q.BUCKET,Key=object_key,VersionId=version)['Retention']
    state['objects'].append({'bucket':q.BUCKET,'key':object_key,'version':version,'sha256':hashlib.sha256(payload).hexdigest(),'retain_until':retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
q.STATE.write_text(json.dumps(state,indent=2))

# Long-lived governance tests contain small synthetic metadata only.
if q.BUCKET=='audit-governance':
    print('PASS governance conditional/race/discarded-reply metadata only',flush=True)
    raise SystemExit(0)

payload=secrets.token_bytes(16*1024*1024)
large_key='qualification/16mib-'+secrets.token_hex(12)
start=time.monotonic()
response=q.client('writer').put_object(Bucket=q.BUCKET,Key=large_key,Body=payload,ServerSideEncryption='aws:kms',SSEKMSKeyId='audit-archive')
elapsed=time.monotonic()-start
retention=q.client('admin').get_object_retention(Bucket=q.BUCKET,Key=large_key,VersionId=response['VersionId'])['Retention']
assert elapsed<10,'16MiB PUT exceeds proposed10s admission budget'
state['objects'].append({'key':large_key,'version':response['VersionId'],'sha256':hashlib.sha256(payload).hexdigest(),'retain_until':retention['RetainUntilDate'].isoformat(),'put_ack_at':datetime.now(timezone.utc).isoformat()})
q.STATE.write_text(json.dumps(state,indent=2))
assert hashlib.sha256(q.client('reader').get_object(Bucket=q.BUCKET,Key=large_key,VersionId=response['VersionId'])['Body'].read()).hexdigest()==hashlib.sha256(payload).hexdigest()
print('PASS16MiB synchronous encrypted PUT seconds',round(elapsed,3),'version',response['VersionId'],flush=True)
