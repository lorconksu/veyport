#!/usr/bin/env python3
"""Capture the actual qualified configuration, excluding every secret value."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('deploy',HERE/'deploy.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

def read(ip,path):
    return d.remote(ip,'sudo cat '+path).decode()

def redacted(value):
    if isinstance(value,dict):
        return {k:('[REDACTED]' if k in {'password','token','credentials','accessKey','secretKey'} else redacted(v)) for k,v in value.items()}
    if isinstance(value,list):return [redacted(v) for v in value]
    return value

spec=importlib.util.spec_from_file_location('qualify',HERE/'qualify.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
s3=q.client('admin')
bucket_properties={}
for bucket,days in [('audit-originals',2),('audit-governance',3651)]:
    versioning=s3.get_bucket_versioning(Bucket=bucket)['Status']
    retention=s3.get_object_lock_configuration(Bucket=bucket)['ObjectLockConfiguration']
    encryption=s3.get_bucket_encryption(Bucket=bucket)['ServerSideEncryptionConfiguration']
    assert versioning=='Enabled' and retention['Rule']['DefaultRetention']=={'Mode':'COMPLIANCE','Days':days},'Bucket qualification drift'
    assert encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']=={'SSEAlgorithm':'aws:kms','KMSMasterKeyID':'audit-archive'},'Bucket encryption drift'
    bucket_properties[bucket]={'versioning':versioning,'object_lock':retention,'encryption':encryption}
lock=json.loads((HERE/'deployment-lock.json').read_text())
lock.pop('qualification',None)
ip='10.10.1.62'
d.remote(ip,'sudo /usr/local/sbin/veyport-archive-volume-check')
filer=read(ip,'/srv/veyport/config/filer.toml')
filer='\n'.join('password="[REDACTED]"' if line.startswith('password=') else line for line in filer.splitlines())+'\n'
units={}
for name in ['veyport-seaweed-master','veyport-seaweed-volume','veyport-seaweed-filer','veyport-seaweed-s3']:
    units[name]=read(ip,'/etc/systemd/system/'+name+'.service')
units['postgresql@16-audit']=read(ip,'/etc/systemd/system/postgresql@16-audit.service.d/veyport-lab.conf')
units['nginx']=read(ip,'/etc/systemd/system/nginx.service.d/veyport-lab.conf')
configuration={
    'schema_version':1,'deployment':lock,
    'bucket_properties':bucket_properties,
    's3':redacted(json.loads(read(ip,'/srv/veyport/config/s3.json'))),
    'filer':filer,'archive_units':units,
    'nginx':read(ip,'/etc/nginx/sites-available/veyport-s3'),
    'postgres_settings':d.remote(ip,"sudo -u postgres psql -p5433 -tAc 'SHOW server_version; SHOW fsync; SHOW synchronous_commit; SHOW full_page_writes;' ").decode().strip().splitlines(),
    'mount_options':d.remote(ip,'sudo findmnt -n -o OPTIONS /srv/veyport').decode().strip(),
    'filer_durability':d.remote(ip,"printf 'fs.configure\\n' | sudo /usr/local/bin/weed shell -filer=127.0.0.1:8888 -master=127.0.0.1:9333").decode(),
    'archive_packages':d.remote(ip,"dpkg-query -W postgresql-16 nginx cryptsetup nftables openssl").decode(),
    'key_packages':d.remote('10.10.1.63',"dpkg-query -W cryptsetup nftables openssl").decode(),
    'archive_binary_sha256':d.remote(ip,'sha256sum /usr/local/bin/weed').decode().split()[0],
    'kms_policy':d.bao('GET','sys/policies/acl/seaweed-kms',token=json.loads((d.PRIVATE/'openbao-init.json').read_text())['root_token'])['data']['policy'],
    'kms_token_policy_names':d.bao('POST','auth/token/lookup',{'token':json.loads((d.PRIVATE/'seaweed-kms-token.json').read_text())['token']},json.loads((d.PRIVATE/'openbao-init.json').read_text())['root_token'])['data']['policies'],
    'openbao_config':read('10.10.1.63','/srv/veyport/config/openbao.hcl'),
    'openbao_unit':read('10.10.1.63','/etc/systemd/system/veyport-openbao.service'),
    'openbao_binary_sha256':d.remote('10.10.1.63','sha256sum /usr/local/bin/bao').decode().split()[0],
    'ca_certificate_sha256':hashlib.sha256((d.PRIVATE/'ca.crt').read_bytes()).hexdigest(),
}
durability=json.loads(configuration['filer_durability'])
assert any(x.get('locationPrefix')=='/buckets/' and x.get('fsync') is True for x in durability['locations']),'Required persisted filer fsync policy absent'
assert configuration['kms_token_policy_names']==['seaweed-kms'],'KMS credential privilege drift'
assert configuration['postgres_settings'][-3:]==['on','on','on'],'PostgreSQL durability drift'
path=HERE/'configuration.json'
path.write_text(json.dumps(configuration,indent=2,sort_keys=True)+'\n')
print('configuration_sha256',hashlib.sha256(path.read_bytes()).hexdigest())
