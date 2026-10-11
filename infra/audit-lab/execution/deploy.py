#!/usr/bin/env python3
"""Build and deploy only the isolated .59 hub and .64 target, with explicit TLS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PRIVATE = Path.home() / '.local/share/veyport-audit-lab/secrets'
ARTIFACTS = PRIVATE.parent / 'execution-build'
HOSTS = {'hub': '10.10.1.59', 'agent': '10.10.1.64'}
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-i', str(Path.home() / '.ssh/yiucloud')]
os.umask(0o077)


def private_bytes(path, maximum=1 << 20):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum:
            raise RuntimeError('Private input permissions or size rejected')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            return stream.read(maximum + 1)
    finally:
        os.close(descriptor)


def remote(role, command, data=None, timeout=120):
    if role not in HOSTS:
        raise RuntimeError('Host outside isolated execution inventory')
    result = subprocess.run(SSH + ['cloud-user@' + HOSTS[role], command], input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Isolated ' + role + ' command failed; inspect private service status')
    return result.stdout


def write_remote(role, path, data, executable=False):
    # Paths are constant deployment locations, never operator or API strings.
    if not path.startswith(('/srv/veyport/config/', '/usr/local/lib/veyport-lab/')) or any(c not in '/._-abcdefghijklmnopqrstuvwxyz0123456789' for c in path):
        raise RuntimeError('Deployment path rejected')
    mode = '755' if executable else '600'
    remote(role, 'set -eu\nsudo -n tee ' + path + '.new >/dev/null\nsudo -n chmod ' + mode + ' ' + path + '.new\nsudo -n mv ' + path + '.new ' + path, data)


def build():
    ARTIFACTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = dict(os.environ, GOTOOLCHAIN='go1.26.9', GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
    for module, package, name in [('hub', './cmd/veyport', 'veyport-hub'), ('agent', './cmd/veyport-agent', 'veyport-agent'), ('cli', './cmd/vey', 'vey')]:
        result = subprocess.run(['go', 'build', '-trimpath', '-o', str(ARTIFACTS / name), package], cwd=REPO / module, env=environment, capture_output=True)
        if result.returncode:
            raise RuntimeError('Patched ' + module + ' build failed; no private material emitted')
    metadata = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(), 'toolchain': 'go1.26.9', 'binaries': {name: hashlib.sha256((ARTIFACTS / name).read_bytes()).hexdigest() for name in ['veyport-hub', 'veyport-agent', 'vey']}}
    (ARTIFACTS / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('Patched hub, agent and CLI artifacts built; public digests recorded')


def deploy():
    runtime = json.loads(private_bytes(PRIVATE / 'receipt-runtime.json'))
    if runtime['endpoint'] != 'https://10.10.1.60:8443':
        raise RuntimeError('Fixed receipt authority changed; continuity review required')
    runtime['allowed_addresses'] = ['10.10.1.60']
    runtime['clients'].pop('redactor-index', None)
    remote('hub', 'sudo -n bash -s', (HERE / 'install-hub.sh').read_bytes())
    remote('agent', 'sudo -n bash -s', (HERE / 'install-agent.sh').read_bytes())
    for field, filename in [('ca_path', 'ca.pem'), ('signing_public_key_path', 'receipt-public.pem')]:
        target = '/srv/veyport/config/audit-runtime/' + filename
        write_remote('hub', target, private_bytes(runtime[field]))
        runtime[field] = target
    for client in ['hub-ingest', 'hub-admin', 'hub-original-reader']:
        for field, suffix in [('certificate_path', '.crt'), ('key_path', '.key')]:
            target = '/srv/veyport/config/audit-runtime/' + client + suffix
            write_remote('hub', target, private_bytes(runtime['clients'][client][field]))
            runtime['clients'][client][field] = target
    write_remote('hub', '/srv/veyport/config/audit-runtime/runtime.json', json.dumps(runtime).encode())
    for role, binary in [('hub', 'veyport-hub'), ('agent', 'veyport-agent')]:
        write_remote(role, '/usr/local/lib/veyport-lab/' + binary, (ARTIFACTS / binary).read_bytes(), True)
    remote('hub', 'sudo -n systemctl restart veyport-lab-hub veyport-lab-https\nsudo -n systemctl is-active --quiet veyport-lab-hub veyport-lab-https')
    print('Isolated .59 HTTPS hub deployed; .64 awaits normal one-use enrollment')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.build:
        build()
    if args.apply:
        deploy()
    if not args.build and not args.apply:
        print('Plan: build go1.26.9 artifacts; deploy only .59 hub/.64 agent; trust existing lab HTTPS CA; preserve all databases, installation IDs and anchors')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Isolated execution deployment failed; private inputs and outputs withheld', file=sys.stderr)
        raise SystemExit(1)
