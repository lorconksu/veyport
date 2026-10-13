#!/usr/bin/env python3
"""Import the reviewed examples into the actual TLS Kibana lab."""
import base64
import json
from pathlib import Path
import ssl
import sys
import urllib.request
import uuid

HERE=Path(__file__).resolve().parent
PRIVATE=Path.home()/'.local/share/veyport-audit-lab/secrets'


def main():
    creds=json.loads((PRIVATE/'elk-credentials.json').read_text())
    token=base64.b64encode(('veyport_admin:'+creds['veyport_admin']).encode()).decode()
    boundary='veyport-'+uuid.uuid4().hex
    body=(('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="dashboards.ndjson"\r\nContent-Type: application/x-ndjson\r\n\r\n').encode()+(HERE/'dashboards.ndjson').read_bytes()+('\r\n--'+boundary+'--\r\n').encode())
    headers={'Authorization':'Basic '+token,'kbn-xsrf':'veyport-dashboard-import','Content-Type':'multipart/form-data; boundary='+boundary}
    req=urllib.request.Request('https://10.10.1.61:5601/api/saved_objects/_import?overwrite=true',data=body,headers=headers,method='POST')
    context=ssl.create_default_context(cafile=str(PRIVATE/'ca.crt'))
    with urllib.request.urlopen(req,context=context,timeout=30) as response:result=json.load(response)
    if not result.get('success') or result.get('successCount')!=4:raise RuntimeError('Dashboard import did not complete')
    req=urllib.request.Request('https://10.10.1.61:5601/api/saved_objects/dashboard/veyport-investigation',headers={'Authorization':'Basic '+token,'kbn-xsrf':'verification'})
    with urllib.request.urlopen(req,context=context,timeout=20) as response:verified=json.load(response)
    assert verified['attributes']['title']=='Veyport redacted audit investigation'
    print('PASS actual Kibana saved dashboard import and authenticated retrieval (four objects)')


if __name__=='__main__':
    try:main()
    except Exception:
        print('Dashboard import failed; no private material emitted',file=sys.stderr)
        raise SystemExit(1)
