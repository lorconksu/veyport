#!/usr/bin/env python3
"""Explicit-host receipt deployment. Credentials remain outside the repository."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PRIVATE = Path.home() / '.local/share/veyport-audit-lab/secrets'
HOST = '10.10.1.60'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-i', str(Path.home()/'.ssh/yiucloud')]
os.umask(0o077)


def remote(command, data=None):
    result = subprocess.run(SSH+['cloud-user@'+HOST, command], input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError('Receipt deployment command failed; inspect sanitized service status')
    return result.stdout


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True)
    if result.returncode:
        raise RuntimeError('Receipt PKI creation failed')
    return result.stdout


def client(name):
    key, cert = PRIVATE/(name+'.key'), PRIVATE/(name+'.crt')
    if not cert.exists():
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key)
        csr, ext = PRIVATE/(name+'.csr'), PRIVATE/(name+'.ext')
        openssl('req', '-new', '-key', key, '-subj', '/CN='+name, '-out', csr)
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
        openssl('x509', '-req', '-in', csr, '-CA', PRIVATE/'ca.crt', '-CAkey', PRIVATE/'ca.key', '-CAcreateserial', '-days', '90', '-sha256', '-extfile', ext, '-out', cert)
    return hashlib.sha256(openssl('x509', '-in', cert, '-outform', 'DER')).hexdigest()


def write(name, data):
    remote('sudo -n tee /srv/veyport/receipt/'+name+' >/dev/null && sudo -n chown veyport-receipt:veyport-receipt /srv/veyport/receipt/'+name+' && sudo -n chmod 600 /srv/veyport/receipt/'+name, data)


def main():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    PRIVATE.chmod(0o700)
    remote('sudo -n bash -s', (HERE/'install.sh').read_bytes())
    signing = PRIVATE/'receipt-signing.key'
    if not signing.exists():
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', signing)
    openssl('pkey', '-in', signing, '-pubout', '-out', PRIVATE/'receipt-signing-public.pem')
    credentials = [dict(id=name, certificate_sha256=client(name), scope=scope) for name, scope in [('hub-ingest','ingest'), ('hub-admin','admin'), ('hub-original-reader','original-read'), ('redactor-index','export-index')]]
    config = dict(listen='10.10.1.60:8443', issuer='https://10.10.1.60:8443', audience='veyport-audit-lab', tls_certificate_path='/srv/veyport/receipt/server.crt', tls_key_path='/srv/veyport/receipt/server.key', client_ca_path='/srv/veyport/receipt/ca.crt', allow_bearer=False, credentials=credentials, signing_key_id='lab-receipt-20261011', signing_key_path='/srv/veyport/receipt/signing.key', archive_endpoint='https://10.10.1.62:8333', archive_allowed_hosts=['10.10.1.62:8333'], archive_allowed_addresses=['10.10.1.62'], archive_region='us-east-1', archive_bucket='audit-originals', archive_kms_key_id='audit-archive', archive_ca_path='/srv/veyport/receipt/ca.crt', archive_credentials_path='/srv/veyport/receipt/archive-writer.json', retention_seconds=86400, receipt_ttl_seconds=120, concurrency=4, governance_bucket='audit-governance', governance_retention_seconds=315360000)
    for kind, prefix in [('originals',''),('governance','governance_')]:
        body = (HERE.parent/'storage'/('qualification-'+kind+'.json')).read_bytes()
        name='qualification-'+kind+'.json'
        config[prefix+'qualification_path']='/srv/veyport/receipt/'+name
        config[prefix+'qualification_sha256']=hashlib.sha256(body).hexdigest()
        write(name, body)
    for source, target in [('audit-ingest-lab.crt','server.crt'),('audit-ingest-lab.key','server.key'),('ca.crt','ca.crt'),('receipt-signing.key','signing.key')]:
        write(target,(PRIVATE/source).read_bytes())
    writer=json.loads((PRIVATE/'s3-credentials.json').read_text())['writer']
    write('archive-writer.json',json.dumps(writer).encode())
    write('config.json',json.dumps(config).encode())
    binary=PRIVATE.parent/'veyport-audit-ingest'
    remote('sudo -n tee /usr/local/bin/veyport-audit-ingest.new >/dev/null && sudo -n chmod 755 /usr/local/bin/veyport-audit-ingest.new && sudo -n mv /usr/local/bin/veyport-audit-ingest.new /usr/local/bin/veyport-audit-ingest',binary.read_bytes())
    remote('sudo -n systemctl restart veyport-audit-ingest && sudo -n systemctl is-active --quiet veyport-audit-ingest')
    runtime=dict(endpoint=config['issuer'],issuer=config['issuer'],audience=config['audience'],signing_key_id=config['signing_key_id'],signing_public_key_path=str(PRIVATE/'receipt-signing-public.pem'),ca_path=str(PRIVATE/'ca.crt'),qualification_sha256=config['qualification_sha256'],governance_qualification_sha256=config['governance_qualification_sha256'],clients={c['id']:dict(certificate_path=str(PRIVATE/(c['id']+'.crt')),key_path=str(PRIVATE/(c['id']+'.key'))) for c in credentials})
    (PRIVATE/'receipt-runtime.json').write_text(json.dumps(runtime,indent=2))
    print('Receipt service deployed with separate mTLS identities and independent ES256 signer; runtime reference preserved privately')


if __name__=='__main__':
    try: main()
    except Exception:
        print('Receipt deployment failed; no private material emitted',file=sys.stderr)
        raise SystemExit(1)
