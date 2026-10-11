#!/usr/bin/env python3
"""Separate OS identity + archive read-only credentials for privileged redaction."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
PRIVATE=Path.home()/'.local/share/veyport-audit-lab/secrets'
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-i',str(Path.home()/'.ssh/yiucloud')]
os.umask(0o077)


def remote(command,data=None):
    result=subprocess.run(SSH+['cloud-user@10.10.1.60',command],input=data,capture_output=True)
    if result.returncode:raise RuntimeError('Exporter remote command failed')
    return result.stdout


def write(name,data):
    remote('sudo -n tee /srv/veyport/redactor/'+name+' >/dev/null && sudo -n chown veyport-redactor:veyport-redactor /srv/veyport/redactor/'+name+' && sudo -n chmod 600 /srv/veyport/redactor/'+name,data.encode() if isinstance(data,str) else data)


def main():
    remote('sudo -n bash -s',(HERE/'install-exporter.sh').read_bytes())
    for name in ['ca.crt','redactor-index.crt','redactor-index.key','redactor-search.crt','redactor-search.key']:
        write(name,(PRIVATE/name).read_bytes())
    reader=json.loads((PRIVATE/'s3-credentials.json').read_text())['reader']
    write('archive-reader.json',json.dumps(reader))
    paths=[];hashes=[]
    for kind in ['originals','governance']:
        name='qualification-'+kind+'.json'
        body=(HERE.parent/'storage'/name).read_bytes()
        write(name,body);paths.append('/srv/veyport/redactor/'+name);hashes.append(hashlib.sha256(body).hexdigest())
    def connection(endpoint,client):
        return dict(endpoint=endpoint,ca_path='/srv/veyport/redactor/ca.crt',certificate_path='/srv/veyport/redactor/'+client+'.crt',key_path='/srv/veyport/redactor/'+client+'.key',allowed_hosts=[endpoint.split('://')[1]],allowed_addresses=[endpoint.split('://')[1].split(':')[0]])
    config=dict(index=connection('https://10.10.1.60:8443','redactor-index'),search=connection('https://10.10.1.61:5044','redactor-search'),archive_endpoint='https://10.10.1.62:8333',archive_ca_path='/srv/veyport/redactor/ca.crt',archive_credentials_path='/srv/veyport/redactor/archive-reader.json',qualification_paths=paths,qualification_sha256s=hashes,checkpoint_path='/srv/veyport/spool/redactor/checkpoint.json')
    write('config.json',json.dumps(config))
    body=(PRIVATE.parent/'veyport-audit-export').read_bytes()
    remote('sudo -n tee /usr/local/bin/veyport-audit-export.new >/dev/null && sudo -n chmod 755 /usr/local/bin/veyport-audit-export.new && sudo -n mv /usr/local/bin/veyport-audit-export.new /usr/local/bin/veyport-audit-export',body)
    remote('sudo -n systemctl restart veyport-audit-export && sudo -n systemctl is-active --quiet veyport-audit-export')
    print('Privileged redactor deployed independently with read-only archive and scoped mTLS search/index credentials')


if __name__=='__main__':
    try:main()
    except Exception:
        print('Exporter deployment failed; no private material emitted',file=sys.stderr)
        raise SystemExit(1)
