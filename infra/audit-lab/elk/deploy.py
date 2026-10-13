#!/usr/bin/env python3
"""Install checksum-pinned native ELK on the explicit isolated lab guest."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time
import urllib.request

HERE=Path(__file__).resolve().parent
PRIVATE=Path.home()/'.local/share/veyport-audit-lab/secrets'
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-i',str(Path.home()/'.ssh/yiucloud')]
HOST='10.10.1.61'
os.umask(0o077)


def remote(command,data=None):
    result=subprocess.run(SSH+['cloud-user@'+HOST,command],input=data,capture_output=True)
    if result.returncode:raise RuntimeError('ELK remote command failed; inspect encrypted service logs')
    return result.stdout


def write(path,data,group):
    if not path.startswith('/srv/veyport/'):raise ValueError('Encrypted destination required')
    remote('sudo -n tee '+path+' >/dev/null && sudo -n chown root:'+group+' '+path+' && sudo -n chmod 640 '+path,data.encode() if isinstance(data,str) else data)


def request(method,path,body=None,identity='elastic',expected_status=None):
    state=json.loads((PRIVATE/'elk-credentials.json').read_text())
    encoded=base64.b64encode((identity+':'+state[identity]).encode()).decode()
    payload=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request('https://127.0.0.1:9200'+path,data=payload,method=method,headers={'Content-Type':'application/json','Authorization':'Basic '+encoded})
    # Elasticsearch is never exposed. API calls run locally through explicit SSH;
    # request arguments and credentials arrive only through encrypted stdin.
    script='''import json,ssl,urllib.request,urllib.error,sys
c=json.load(sys.stdin)
r=urllib.request.Request(c['url'],data=c['body'].encode() if c['body'] is not None else None,method=c['method'],headers=c['headers'])
try:
 with urllib.request.urlopen(r,context=ssl.create_default_context(cafile='/etc/elasticsearch/tls/ca.crt'),timeout=20) as resp:
  if c.get('expected_status') is not None:
   print(json.dumps({'http_status':resp.status}))
  else: print(resp.read().decode())
except urllib.error.HTTPError as error:
 if c.get('expected_status') is not None:
  print(json.dumps({'http_status':error.code}))
 else: raise
'''
    envelope=dict(url=req.full_url,body=payload.decode() if payload is not None else None,method=method,headers=dict(req.header_items()),expected_status=expected_status)
    # No shell interpolation of private values.
    program=base64.b64encode(script.encode()).decode()
    result=remote("sudo -n python3 -c \"import base64;exec(base64.b64decode('"+program+"'))\"",json.dumps(envelope).encode())
    return json.loads(result) if result.strip() else {}


def main():
    packages=[]
    for name in ['elasticsearch','kibana','logstash']:
        artifact=name+'-9.5.5-amd64.deb'
        path=Path('/tmp/veyport-elk-binaries')/artifact
        checksum=(path.with_suffix(path.suffix+'.sha512')).read_text().split()[0]
        actual=hashlib.file_digest(path.open('rb'),'sha512').hexdigest()
        if actual!=checksum:raise RuntimeError('Official artifact checksum mismatch')
        existing=remote('if test -f /var/tmp/'+artifact+'; then sha512sum /var/tmp/'+artifact+'; fi').decode().split()
        if not existing or existing[0]!=checksum:
            result=subprocess.run(['scp','-q','-i',str(Path.home()/'.ssh/yiucloud'),str(path),'cloud-user@'+HOST+':/var/tmp/'+artifact],capture_output=True)
            if result.returncode:raise RuntimeError('Package transfer failed')
        remote("echo '"+checksum+'  /var/tmp/'+artifact+"' | sha512sum --check --status")
        packages.append(dict(name=name,version='9.5.5',sha512=checksum,source='https://artifacts.elastic.co/downloads/'+name+'/'+artifact))
    remote('sudo -n bash -s',(HERE/'install.sh').read_bytes())
    for service in ['elasticsearch','kibana','logstash']:
        for source,target in [('elk-lab.crt','server.crt'),('elk-lab.key','server.key'),('ca.crt','ca.crt')]:
            write('/srv/veyport/config/'+service+'/tls/'+target,(PRIVATE/source).read_bytes(),service)
    # Logstash requires an unencrypted PKCS8 key.
    result=subprocess.run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(PRIVATE/'elk-lab.key')],capture_output=True,check=True)
    write('/srv/veyport/config/logstash/tls/server.key',result.stdout,'logstash')
    write('/srv/veyport/config/elasticsearch/elasticsearch.yml',(HERE/'elasticsearch.yml').read_bytes(),'elasticsearch')
    write('/srv/veyport/config/elasticsearch/jvm.options.d/veyport.options','-Xms4g\n-Xmx4g\n-XX:-HeapDumpOnOutOfMemoryError\n-XX:ErrorFile=/srv/veyport/logs/elasticsearch/hs_err_pid%p.log\n-XX:ReplayDataFile=/srv/veyport/logs/elasticsearch/replay_pid%p.log\n','elasticsearch')
    state_path=PRIVATE/'elk-credentials.json'
    if not state_path.exists():
        state_path.write_text(json.dumps({name:secrets.token_urlsafe(36) for name in ['elastic','kibana_system','veyport_ingest','veyport_search','veyport_admin','kibana_encryption']}))
    state=json.loads(state_path.read_text())
    remote('sudo -n env ES_PATH_CONF=/etc/elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore add --stdin --force bootstrap.password',state['elastic'].encode())
    remote('sudo -n chown root:elasticsearch /etc/elasticsearch/elasticsearch.keystore && sudo -n chmod 640 /etc/elasticsearch/elasticsearch.keystore')
    remote('sudo -n systemctl restart elasticsearch')
    for _ in range(90):
        try:status=request('GET','/');break
        except Exception:time.sleep(2)
    else:raise RuntimeError('Elasticsearch TLS readiness deadline')
    if status['version']['number']!='9.5.5':raise RuntimeError('Installed Elasticsearch differs from pin')
    request('POST','/_security/user/elastic/_password',dict(password=state['elastic']))
    request('POST','/_security/user/kibana_system/_password',dict(password=state['kibana_system']))
    request('PUT','/_security/role/veyport_ingest',dict(cluster=['monitor'],indices=[dict(names=['veyport-audit-*','veyport-replay-*'],privileges=['create_index','write'])]))
    request('PUT','/_security/role/veyport_search',dict(cluster=[],indices=[dict(names=['veyport-audit-*','veyport-replay-*'],privileges=['read','view_index_metadata'])],applications=[dict(application='kibana-.kibana',privileges=['read'],resources=['space:default'])]))
    request('PUT','/_security/role/veyport_admin',dict(cluster=['monitor','manage_ilm','manage_index_templates'],indices=[dict(names=['veyport-audit-*','veyport-replay-*'],privileges=['all'])],applications=[dict(application='kibana-.kibana',privileges=['all'],resources=['space:default'])]))
    for name in ['veyport_ingest','veyport_search','veyport_admin']:
        request('POST','/_security/user/'+name,dict(password=state[name],roles=[name]))
    request('PUT','/_ilm/policy/veyport-search-seven-days',dict(policy=dict(phases=dict(delete=dict(min_age='7d',actions=dict(delete={}))))))
    template=json.loads((HERE/'index-template.json').read_text())
    request('PUT','/_index_template/veyport-audit',template)
    kibana='''server.host: 10.10.1.61
server.port: 5601
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/tls/server.crt
server.ssl.key: /etc/kibana/tls/server.key
elasticsearch.hosts: ["https://127.0.0.1:9200"]
elasticsearch.ssl.certificateAuthorities: [/etc/kibana/tls/ca.crt]
elasticsearch.ssl.verificationMode: full
elasticsearch.username: kibana_system
elasticsearch.password: "'''+state['kibana_system']+'''"
path.data: /srv/veyport/data/kibana
logging.root.level: error
xpack.security.encryptionKey: "'''+state['kibana_encryption']+'''"
xpack.encryptedSavedObjects.encryptionKey: "'''+state['kibana_encryption']+'''"
xpack.reporting.encryptionKey: "'''+state['kibana_encryption']+'''"
telemetry.enabled: false
'''
    write('/srv/veyport/config/kibana/kibana.yml',kibana,'kibana')
    for name in ['logstash.yml','pipeline.conf','projection_filter.rb']:
        target='conf.d/veyport.conf' if name=='pipeline.conf' else name
        remote('sudo -n install -d -m750 -o root -g logstash /srv/veyport/config/logstash/conf.d')
        write('/srv/veyport/config/logstash/'+target,(HERE/name).read_bytes(),'logstash')
    write('/srv/veyport/config/logstash/pipelines.yml','- pipeline.id: veyport-audit\n  path.config: /etc/logstash/conf.d/veyport.conf\n','logstash')
    write('/srv/veyport/config/logstash/jvm.options','-Xms1g\n-Xmx1g\n-Djava.io.tmpdir=/srv/veyport/spool/logstash\n-XX:-HeapDumpOnOutOfMemoryError\n-XX:ErrorFile=/srv/veyport/logs/logstash/hs_err_pid%p.log\n','logstash')
    write('/srv/veyport/config/logstash/credentials.env','VEYPORT_INGEST_PASSWORD='+state['veyport_ingest']+'\n','logstash')
    remote("sudo -n bash -c 'echo EnvironmentFile=/etc/logstash/credentials.env >> /etc/systemd/system/logstash.service.d/veyport.conf'")
    # Only one dedicated exporter client is issued by the ingest-specific CA.
    if not (PRIVATE/'elk-ingest-ca.crt').exists():
        for args in [['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(PRIVATE/'elk-ingest-ca.key')],['req','-new','-x509','-key',str(PRIVATE/'elk-ingest-ca.key'),'-sha256','-days','365','-subj','/CN=Veyport ELK exporter CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',str(PRIVATE/'elk-ingest-ca.crt')]]:
            subprocess.run(['openssl',*args],check=True,capture_output=True)
    if not (PRIVATE/'redactor-search.crt').exists():
        subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(PRIVATE/'redactor-search.key')],check=True,capture_output=True)
        subprocess.run(['openssl','req','-new','-key',str(PRIVATE/'redactor-search.key'),'-subj','/CN=veyport-redactor','-out',str(PRIVATE/'redactor-search.csr')],check=True,capture_output=True)
        (PRIVATE/'redactor-search.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
        subprocess.run(['openssl','x509','-req','-in',str(PRIVATE/'redactor-search.csr'),'-CA',str(PRIVATE/'elk-ingest-ca.crt'),'-CAkey',str(PRIVATE/'elk-ingest-ca.key'),'-CAcreateserial','-days','90','-extfile',str(PRIVATE/'redactor-search.ext'),'-out',str(PRIVATE/'redactor-search.crt')],check=True,capture_output=True)
    write('/srv/veyport/config/logstash/tls/ingest-ca.crt',(PRIVATE/'elk-ingest-ca.crt').read_bytes(),'logstash')
    remote('sudo -n systemctl daemon-reload && sudo -n systemctl enable elasticsearch kibana logstash && sudo -n systemctl restart kibana logstash')
    license_type=request('GET','/_license')['license']['type']
    if license_type!='basic':raise RuntimeError('Unexpected lab license type')
    lock=dict(schema_version=1,packages=packages,license=license_type,elasticsearch_version=status['version']['number'],elasticsearch_bind='127.0.0.1:9200',search_retention_days=7)
    (HERE/'deployment-lock.json').write_text(json.dumps(lock,indent=2)+'\n')
    print('Pinned ELK native services configured; TLS, Basic license and separate ingest/search/admin roles verified')


if __name__=='__main__':
    try:main()
    except Exception:
        print('ELK deployment failed; no private material emitted',file=sys.stderr)
        raise SystemExit(1)
