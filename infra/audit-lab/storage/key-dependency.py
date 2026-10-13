#!/usr/bin/env python3
"""Verify archived ciphertext requires independent, uncached OpenBao keys."""
import importlib.util
import json
from pathlib import Path
from botocore.exceptions import ClientError

HERE=Path(__file__).resolve().parent
def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
d=module('deploy');q=module('qualify')
obj=json.loads(q.STATE.read_text())['objects'][0]
q.client('reader').get_object(Bucket=q.BUCKET,Key=obj['key'],VersionId=obj['version'])['Body'].read()
d.remote('10.10.1.63','sudo mountpoint -q /srv/veyport && sudo systemctl stop veyport-openbao')
try:
    try:
        q.client('reader').get_object(Bucket=q.BUCKET,Key=obj['key'],VersionId=obj['version'])['Body'].read()
    except ClientError as error:
        assert error.response['ResponseMetadata']['HTTPStatusCode']>=500
        print('PASS exact encrypted original unavailable without independent OpenBao key service',error.response['Error']['Code'],flush=True)
    else:raise AssertionError('Original decrypted while independent key service unavailable')
finally:
    d.remote('10.10.1.63','sudo mountpoint -q /srv/veyport && sudo systemctl start veyport-openbao')
    d.keys()
q.verify(q.client('admin'),json.loads(q.STATE.read_text()))
print('PASS restored key availability recovers every exact original',flush=True)
