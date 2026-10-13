#!/usr/bin/env python3
"""Operator-only private credential expiry check/renewal; never print tokens."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('deploy',HERE/'deploy.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
parser=argparse.ArgumentParser()
parser.add_argument('--renew',action='store_true',help='Renew through the private operator root credential')
args=parser.parse_args()
operator=json.loads((d.PRIVATE/'openbao-init.json').read_text())['root_token']
credential=json.loads((d.PRIVATE/'seaweed-kms-token.json').read_text())['token']
status=d.bao('POST','auth/token/lookup',{'token':credential},operator)['data']
assert status['policies']==['seaweed-kms'],'Unexpected KMS token policy set'
if args.renew:
    assert status['renewable'] and status['ttl']>0,'KMS credential cannot be renewed; fail closed and rotate through the operator'
    d.bao('POST','auth/token/renew',{'token':credential,'increment':'168h'},operator)
    status=d.bao('POST','auth/token/lookup',{'token':credential},operator)['data']
print(json.dumps({'expires_at':status['expire_time'],'remaining_seconds':status['ttl'],'renewable':status['renewable'],'policies':status['policies']},sort_keys=True))
if status['ttl']<24*3600:
    raise SystemExit('KMS credential has less than24h remaining; operator renewal/rotation required')
