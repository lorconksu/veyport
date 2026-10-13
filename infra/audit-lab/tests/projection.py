#!/usr/bin/env python3
"""Actual TLS archive -> independent redactor -> Logstash -> ES qualification.

Synthetic archive records never dispatch processes or represent real approvals.
Only a disposable search index is deleted; immutable archive versions survive.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE=Path(__file__).resolve().parent
PRIVATE=Path.home()/'.local/share/veyport-audit-lab/secrets'
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-i',str(Path.home()/'.ssh/yiucloud')]
os.umask(0o077)
spec=importlib.util.spec_from_file_location('elk_deployment',HERE.parent/'elk/deploy.py')
elk=importlib.util.module_from_spec(spec)
spec.loader.exec_module(elk)


def remote(ip,command,data=None):
    result=subprocess.run(SSH+['cloud-user@'+ip,command],input=data,capture_output=True)
    if result.returncode:raise RuntimeError('Qualification remote command failed')
    return result.stdout


def receipt(method,path,body=None,identity='hub-ingest',content_type='application/json'):
    context=ssl.create_default_context(cafile=str(PRIVATE/'ca.crt'))
    context.load_cert_chain(str(PRIVATE/(identity+'.crt')),str(PRIVATE/(identity+'.key')))
    req=urllib.request.Request('https://10.10.1.60:8443'+path,data=body,method=method,headers={'Content-Type':content_type})
    with urllib.request.urlopen(req,context=context,timeout=15) as response:return json.load(response)


def stamp(value):return value.isoformat().replace('+00:00','Z')
def digest(body):return hashlib.sha256(body).hexdigest()


def fixture(command,event_id,script=None):
    now=datetime.now(timezone.utc)
    binding=dict(execution_id='exec-'+event_id,preparation_id='prep-'+event_id,boot_id='synthetic-boot',node_id='synthetic-node',node_name='Synthetic projection fixture',identity=dict(username='root',uid=0,gid=0,groups=[0],groups_sha256=digest(b'groups'),identity_sha256=digest(b'identity'),home='/root',shell='/bin/sh',cwd='/root'),command_sha256=digest(command),command_bytes=len(command),prepared_until=stamp(now+timedelta(seconds=60)),limits=dict(max_frame_bytes=65536,max_buffer_bytes=2097152,runtime_seconds=60,term_grace_seconds=5,blocked_consumer_seconds=30))
    record=dict(schema_version=1,event_id=event_id,event_type='execution.admission',actor=dict(user_id='synthetic-operator',person_id='synthetic-person',name='Synthetic operator',provider='local',subject='projection-test'),execution=binding,policy_version=1,policy_sha256=digest(b'synthetic-policy'),occurred_at=stamp(now),command=base64.b64encode(command).decode())
    if script is not None:
        binding.update(script_sha256=digest(script),script_bytes=len(script))
        record['attachments']=[dict(id='script',sha256=digest(script),bytes=len(script))]
    raw=json.dumps(record,separators=(',',':')).encode()
    if script is None:return receipt('POST','/v1/records',raw),raw
    boundary='veyport-'+uuid.uuid4().hex
    body=(('--'+boundary+'\r\nContent-ID: envelope\r\nContent-Type: application/json\r\n\r\n').encode()+raw+('\r\n--'+boundary+'\r\nContent-ID: script\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+script+('\r\n--'+boundary+'--\r\n').encode())
    return receipt('POST','/v1/records',body,content_type='multipart/mixed; boundary='+boundary),raw


def checkpoint():return json.loads(remote('10.10.1.60','sudo -n cat /srv/veyport/spool/redactor/checkpoint.json'))


def wait_for(callback,seconds=90):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            result=callback()
            if result:return result
        except Exception:pass
        time.sleep(2)
    raise RuntimeError('Bounded qualification wait expired')


def search(index,ids):
    elk.request('POST','/'+index+'/_refresh',identity='veyport_admin')
    response=elk.request('POST','/'+index+'/_search',dict(size=100,query=dict(terms=dict(event_id=ids))),identity='veyport_search')
    return response['hits']['hits']


def assert_documents(hits,ids,canary):
    assert {h['_id'] for h in hits}==set(ids),'Stable IDs absent/duplicated'
    serialized=json.dumps(hits)
    assert canary not in serialized,'Raw canary reached actual search'
    for hit in hits:
        p=hit['_source']
        assert p['redaction_rule_version']=='structured-omit-arguments-v1'
        assert p['evidence_state']=='archived'
        if p.get('execution_id'):
            assert p.get('uid')==0 and p.get('run_as')=='root','Real UID0 identity omitted'
        else:
            assert 'uid' not in p and 'gid' not in p and 'run_as' not in p,'Absent execution identity presented as root'
        assert 'command' not in p and 'attachments' not in p and 'approved_change' not in p


def main():
    run=uuid.uuid4().hex[:12]
    canary='VEYPORT_SYNTHETIC_PRIVATE_CANARY_'+run
    commands=[('env API_TOKEN='+canary+' curl --password '+canary+' https://user:'+canary+'@example.invalid').encode(),('curl -H "Authorization: Bearer '+canary+'" --token="'+canary+'"').encode(),('echo first\necho "'+canary+'"').encode(),b'sh -s']
    ids=[];originals=[]
    for n,command in enumerate(commands):
        event_id='projection-'+run+'-'+str(n)
        preserved,raw=fixture(command,event_id,('echo '+canary+'\n').encode() if n==3 else None)
        ids.append(event_id);originals.append(dict(receipt=preserved,sha256=digest(raw)))
    # These are projection-only synthetic result records, with no policy change
    # request, quorum simulation or remote process dispatch.
    lifecycle=json.loads(raw)
    lifecycle.pop('command',None);lifecycle.pop('attachments',None)
    lifecycle.update(event_id='projection-'+run+'-lifecycle',event_type='execution.lifecycle',details=dict(correlation_id='synthetic-correlation',state='completed',exit_code=0,reason=canary))
    policy=dict(schema_version=1,event_id='projection-'+run+'-policy',event_type='policy.result',actor=lifecycle['actor'],policy_version=1,policy_sha256=digest(b'synthetic-policy'),occurred_at=stamp(datetime.now(timezone.utc)),details=dict(request_id='synthetic-projection-request',request_sha256=digest(b'synthetic-projection-request'),correlation_id='synthetic-correlation',state='completed',reason=canary,approved_change=base64.b64encode(canary.encode()).decode()))
    for record in [lifecycle,policy]:
        encoded=json.dumps(record,separators=(',',':')).encode()
        preserved=receipt('POST','/v1/records',encoded)
        ids.append(record['event_id']);originals.append(dict(receipt=preserved,sha256=digest(encoded)))
    assert receipt('GET','/v1/ready',identity='hub-admin')['ready']
    print('PASS actual qualified receipt preservation (synthetic records only)',flush=True)
    hits=wait_for(lambda:search('veyport-audit-*',ids) if len(search('veyport-audit-*',ids))==len(ids) else None)
    assert_documents(hits,ids,canary)
    print('PASS actual indexed canary absence and stable IDs',flush=True)
    # Replay with a separate private config/checkpoint; it has the same read-only
    # identity and reads originals from their immutable object versions.
    replay='veyport-replay-'+run
    elk.request('PUT','/'+replay,{},identity='veyport_admin')
    assert elk.request('GET','/'+replay+'/_count',identity='veyport_search')['count']==0
    script='''import json,os
from pathlib import Path
os.umask(0o077)
c=json.loads(Path('/srv/veyport/redactor/config.json').read_text())
c['replay_index']=REPLAY
c['checkpoint_path']='/srv/veyport/spool/redactor/replay-checkpoint.json'
Path('/srv/veyport/redactor/replay.json').write_text(json.dumps(c))
Path('/srv/veyport/redactor/replay.json').chmod(0o600)
'''.replace('REPLAY',repr(replay))
    program=base64.b64encode(script.encode()).decode()
    remote('10.10.1.60',"sudo -n -u veyport-redactor python3 -c \"import base64;exec(base64.b64decode('"+program+"'))\"")
    def replay_pass():
        for _ in range(128):
            remote('10.10.1.60','sudo -n -u veyport-redactor /usr/local/bin/veyport-audit-export --config /srv/veyport/redactor/replay.json --once')
            state=json.loads(remote('10.10.1.60','sudo -n cat /srv/veyport/spool/redactor/replay-checkpoint.json'))
            if not state['cursor']:return
            time.sleep(5)
        raise RuntimeError('Replay page limit reached')
    replay_pass()
    hits=wait_for(lambda:search(replay,ids) if len(search(replay,ids))==len(ids) else None)
    assert_documents(hits,ids,canary)
    elk.request('DELETE','/'+replay,identity='veyport_admin')
    elk.request('PUT','/'+replay,{},identity='veyport_admin')
    assert elk.request('GET','/'+replay+'/_count',identity='veyport_search')['count']==0
    time.sleep(6);replay_pass()
    hits=wait_for(lambda:search(replay,ids) if len(search(replay,ids))==len(ids) else None)
    assert_documents(hits,ids,canary)
    print('PASS empty test index and deletion replay from exact external archives',flush=True)
    outage_result=None
    try:
        remote('10.10.1.61','sudo -n systemctl stop logstash')
        state=wait_for(lambda:checkpoint() if checkpoint().get('failure')=='search_unavailable' else None,seconds=45)
        assert state['failures']>0 and state['pending_occurred_at']!='0001-01-01T00:00:00Z'
        assert receipt('GET','/v1/ready',identity='hub-admin')['ready']
        outage_id='projection-'+run+'-outage'
        outage_result,_=fixture(b'true',outage_id)
        assert outage_result['token'] and outage_result['manifest']['version_id']
        print('PASS visible search failure/lag while archive admission remains available',flush=True)
    finally:remote('10.10.1.61','sudo -n systemctl start logstash')
    wait_for(lambda:checkpoint().get('failure','')=='',seconds=180)
    hits=wait_for(lambda:search('veyport-audit-*',[outage_id]) if len(search('veyport-audit-*',[outage_id]))==1 else None,seconds=180)
    # Authenticate direct exact-version reads using the privileged reader only;
    # verify original data still contains the canaries after search deletion.
    sys.path.insert(0,str(HERE.parent/'storage'))
    from qualify import client
    s3=client('reader')
    for entry in originals:
        ref=entry['receipt']['manifest']
        manifest=json.loads(s3.get_object(Bucket=ref['bucket'],Key=ref['key'],VersionId=ref['version_id'])['Body'].read())
        obj=manifest['envelope']
        raw=s3.get_object(Bucket=obj['bucket'],Key=obj['key'],VersionId=obj['version_id'])['Body'].read()
        assert digest(raw)==entry['sha256']
        record=json.loads(raw)
        assert canary in base64.b64decode(record.get('command','')).decode() or record.get('details',{}).get('reason')==canary or manifest.get('attachments')
    # Search credentials cannot mutate; ingest credentials cannot read.
    assert elk.request('DELETE','/'+replay,identity='veyport_search',expected_status=403)['http_status']==403,'Search role deletion was not denied with403'
    assert elk.request('GET','/'+replay+'/_search',identity='veyport_ingest',expected_status=403)['http_status']==403,'Ingest role search was not denied with403'
    report=dict(schema_version=1,verified_at=stamp(datetime.now(timezone.utc)),fixture_count=len(ids),fixture_event_types=['execution.admission','execution.lifecycle','policy.result'],elasticsearch_version=elk.request('GET','/')['version']['number'],license=elk.request('GET','/_license')['license']['type'],qualification_sha256=receipt('GET','/v1/ready',identity='hub-admin')['qualification_sha256'],governance_qualification_sha256=receipt('GET','/v1/ready',identity='hub-admin')['governance_qualification_sha256'],checks=['actual_canary_absence','stable_document_ids','empty_index_replay','deleted_index_replay','exact_original_versions_survive','visible_search_failure_lag','archive_admission_during_logstash_outage','search_recovery','least_privilege_search_ingest_http403'],limitations=['Synthetic records only; no remote process dispatch','Logstash HTTP ACK is acceptance, not an indexing receipt','No real human approvals simulated','Single guest for ELK and shared hypervisor administrator boundary'])
    (HERE.parent/'elk/projection-qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS exact originals survive and scoped search/ingest authorization; sanitized evidence written',flush=True)


if __name__=='__main__':
    try:main()
    except Exception:
        print('Projection qualification failed; no original or credential values emitted',file=sys.stderr)
        raise SystemExit(1)
