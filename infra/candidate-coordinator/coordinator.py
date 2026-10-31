#!/usr/bin/env python3
"""Deploy bounded trusted candidate bytes to an isolated native qualification runtime."""
import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence-collector' / 'evidence.py'
if not EVIDENCE.is_file():
    EVIDENCE = Path('/opt/veyport-evidence/evidence.py')
spec = importlib.util.spec_from_file_location('trusted_evidence', EVIDENCE)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
MAX_TOTAL = 4 << 30
MAX_FILE = 512 << 20
MAX_METADATA = 1 << 20
MAX_WIRE = MAX_TOTAL + (16 << 20)
LABEL = 'dev.veyport.ssdf'
NAMESPACE = 'private-candidate'
RETAINED = {'veyport.oci.tar', 'bin/veyport-agent-linux-amd64', 'bin/vey-linux-amd64', 'reports/veyport.scan-binding.json', 'reports/veyport.config.json'}


def file_hash(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_file(root, name):
    e.safe_name(name)
    path = Path(root)
    for component in name.split('/'):
        path = path / component
        e.require(not path.is_symlink(), 'candidate symlink forbidden')
    return path


def validate_manifest(m):
    e.require(isinstance(m, dict) and m.get('schema_version') == 1, 'invalid candidate manifest')
    for key in ('repository', 'workflow', 'run_id', 'run_attempt', 'revision', 'candidate_id'):
        e.require(key in m, 'missing candidate identity')
    e.require(isinstance(m['repository'], str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', m['repository']), 'invalid candidate repository')
    e.require(type(m['run_id']) is int and m['run_id'] > 0 and type(m['run_attempt']) is int and m['run_attempt'] > 0 and e.SHA.fullmatch(m['revision']), 'invalid candidate run identity')
    e.require(isinstance(m['candidate_id'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', m['candidate_id']), 'invalid candidate identity')
    e.require(isinstance(m.get('version'), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}', m['version']), 'invalid candidate version')
    e.require(m.get('audit_profile') in ('standard', 'enhanced'), 'invalid candidate audit profile')
    files = m.get('files')
    e.require(isinstance(files, list) and 1 <= len(files) <= 1024, 'invalid candidate inventory')
    total, names = 0, set()
    for item in files:
        e.require(isinstance(item, dict) and set(item) == {'name', 'size', 'sha256'}, 'invalid candidate file')
        name = e.safe_name(item['name'])
        e.require(re.fullmatch(r'[A-Za-z0-9._/-]{1,240}', name) and name not in names, 'invalid candidate file name')
        names.add(name)
        e.require(type(item['size']) is int and 0 <= item['size'] <= MAX_FILE and isinstance(item['sha256'], str) and e.HEX.fullmatch(item['sha256']), 'invalid candidate file size/digest')
        total += item['size']
    e.require(total <= MAX_TOTAL and len(e.canonical(m)) <= MAX_METADATA, 'candidate exceeds bound')
    return m


def bind_manifest(m, run, config):
    validate_manifest(m)
    e.trusted_run(run, config)
    e.require((m['repository'], m['workflow'], m['run_id'], m['run_attempt'], m['revision']) == (config['repository'], run['path'], run['id'], run['run_attempt'], run['head_sha']), 'candidate source binding mismatch')


class BoundedReader:
    def __init__(self, source, deadline):
        self.source, self.deadline, self.total = source, deadline, 0

    def read(self, size):
        # Prevent tarfile's PAX/GNU metadata parser from allocating attacker-sized headers.
        e.require(0 <= size <= MAX_METADATA, 'candidate metadata read exceeds bound')
        e.require(time.monotonic() < self.deadline, 'candidate decryption deadline exceeded')
        data = self.source.read(size)
        self.total += len(data)
        e.require(self.total <= MAX_WIRE, 'candidate plaintext exceeds bound')
        return data


def extract_stream(source, destination, deadline, retained=None):
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    reader = BoundedReader(source, deadline)
    manifest, expected, seen = None, {}, set()
    try:
        with tarfile.open(fileobj=reader, mode='r|') as archive:
            for index, member in enumerate(archive):
                e.require(index <= 1024 and member.isfile() and not member.issparse(), 'invalid candidate TAR member')
                e.require(0 <= member.size <= MAX_FILE and member.name not in seen, 'invalid candidate TAR size/name')
                seen.add(member.name)
                content = archive.extractfile(member)
                if index == 0:
                    e.require(member.name == 'candidate.json' and member.size <= MAX_METADATA, 'candidate manifest must be first')
                    manifest = validate_manifest(e.parse_json(content.read(MAX_METADATA + 1)))
                    expected = {'delivery/' + x['name']: x for x in manifest['files']}
                    continue
                e.require(member.name in expected, 'unexpected candidate TAR member')
                item = expected[member.name]
                e.require(member.size == item['size'], 'candidate TAR size mismatch')
                keep = retained is None or item['name'] in retained
                target = safe_file(destination, item['name'])
                if keep:
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                # Reports are hashed and verified in flight, then discarded rather than written as plaintext.
                with (target.open('xb') if keep else contextlib.nullcontext(None)) as output:
                    remaining = member.size
                    h = hashlib.sha256()
                    while remaining:
                        block = content.read(min(1 << 20, remaining))
                        e.require(block, 'truncated candidate payload')
                        if output:
                            output.write(block)
                        h.update(block)
                        remaining -= len(block)
                e.require(h.hexdigest() == item['sha256'], 'candidate file digest mismatch')
                if keep and item['name'] in ('bin/veyport-agent-linux-amd64', 'bin/vey-linux-amd64'):
                    os.chmod(target, 0o700)  # Ignore supplied TAR modes; grant only reviewed native execution.
        e.require(manifest is not None and seen == set(expected) | {'candidate.json'}, 'candidate inventory incomplete')
        # Consume all ciphertext and require age's final authentication check before deployment.
        while reader.read(MAX_METADATA):
            pass
        return manifest
    except (tarfile.TarError, EOFError, ValueError) as exc:
        raise e.EvidenceError('invalid candidate TAR') from exc


def decrypt_candidate(ciphertext, identity, destination):
    deadline = time.monotonic() + 300
    with subprocess.Popen(['age', '-d', '-i', str(identity), str(ciphertext)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            result = extract_stream(process.stdout, destination, deadline, retained=RETAINED)
            e.require(process.wait(timeout=max(1, deadline - time.monotonic())) == 0, 'candidate encryption authentication failed')
            return result
        except BaseException:
            process.kill()
            process.wait()
            raise


def trusted_blob_url(url):
    parsed = urllib.parse.urlparse(url)
    e.require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and parsed.port in (None, 443) and (parsed.hostname.endswith('.blob.core.windows.net') or parsed.hostname.endswith('.actions.githubusercontent.com')), 'untrusted candidate artifact redirect')
    return url


def download_candidate(api, artifact, run, output):
    e.require(artifact.get('name') == f"ssdf-candidate-v1-{run['id']}-{run['run_attempt']}" and not artifact.get('expired'), 'candidate artifact identity mismatch')
    e.require(type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_WIRE, 'candidate artifact exceeds bound')
    ref = artifact.get('workflow_run', {})
    e.require(ref.get('id') == run['id'] and ref.get('head_sha') == run['head_sha'], 'candidate artifact source mismatch')
    expected = artifact.get('digest', '')
    e.require(re.fullmatch(r'sha256:[a-f0-9]{64}', expected), 'candidate artifact digest unavailable')
    url = 'https://api.github.com' + api.prefix + '/actions/artifacts/' + str(artifact['id']) + '/zip'
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + api.token, 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'veyport-private-candidate'})
    try:
        with urllib.request.build_opener(e.NoRedirect()).open(request, timeout=30):
            raise e.EvidenceError('candidate API did not issue an authenticated download redirect')
    except urllib.error.HTTPError as exc:
        e.require(exc.code == 302, 'candidate download URL unavailable')
        blob_url = trusted_blob_url(exc.headers.get('Location', ''))
    with urllib.request.build_opener(e.NoRedirect()).open(urllib.request.Request(blob_url), timeout=60) as response, Path(output).open('xb') as destination:
        total, h, deadline = 0, hashlib.sha256(), time.monotonic() + 600
        while True:
            e.require(time.monotonic() < deadline, 'candidate download deadline exceeded')
            data = response.read(1 << 20)
            if not data:
                break
            total += len(data)
            e.require(total <= MAX_WIRE, 'candidate download exceeds bound')
            h.update(data)
            destination.write(data)
        e.require('sha256:' + h.hexdigest() == expected, 'candidate artifact archive digest mismatch')


def unwrap_candidate(archive_path, destination):
    with zipfile.ZipFile(archive_path) as archive:
        e.require(archive.namelist() == ['candidate.age'], 'unexpected candidate artifact contents')
        member = archive.getinfo('candidate.age')
        e.require(stat.S_IFMT(member.external_attr >> 16) != stat.S_IFLNK and 0 < member.file_size <= MAX_WIRE, 'invalid encrypted candidate entry')
        total = 0
        with archive.open(member) as source, Path(destination).open('xb') as output:
            while True:
                data = source.read(1 << 20)
                if not data:
                    break
                total += len(data)
                e.require(total <= MAX_WIRE, 'candidate ciphertext exceeds bound')
                output.write(data)


def command(args, timeout=120, limit=4 << 20):
    # stdout uses a bounded pipe; a small RLIMIT_FSIZE would also break legitimate OCI/Docker archive writes.
    def bounded_files():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_WIRE, MAX_WIRE))
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, preexec_fn=bounded_files)
    result, deadline = bytearray(), time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                e.require(time.monotonic() < deadline, 'trusted coordinator command deadline exceeded')
                for event, _ in selector.select(min(1, max(0, deadline - time.monotonic()))):
                    block = os.read(event.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(event.fileobj)
                        continue
                    result.extend(block)
                    e.require(len(result) <= limit, 'trusted coordinator command output exceeds bound')
        e.require(process.wait(timeout=max(1, deadline - time.monotonic())) == 0, 'trusted coordinator command failed')
        return bytes(result)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()


def config_conversion_binding(source_config, imported_config, source_digest, runtime_id):
    e.require(re.fullmatch(r'sha256:[a-f0-9]{64}', source_digest) and re.fullmatch(r'sha256:[a-f0-9]{64}', runtime_id), 'invalid image conversion identity')
    e.require(e.canonical(source_config) == e.canonical(imported_config), 'Docker conversion changed image configuration/rootfs')
    return {'source_config_digest': source_digest, 'runtime_image_id': runtime_id, 'canonical_config_sha256': e.digest(e.canonical(source_config))}


def validate_network(value, config):
    expected_id = config.get('docker_network_id', '')
    subnet = config.get('docker_network_subnet', '')
    e.require(re.fullmatch(r'[a-f0-9]{64}', expected_id), 'operator candidate network identity is not pinned')
    expected_subnet = ipaddress.ip_network(subnet, strict=True)
    e.require(expected_subnet.version == 4 and expected_subnet.is_private and expected_subnet.prefixlen >= 28, 'invalid operator candidate subnet')
    e.require(value.get('Id') == expected_id and value.get('Name') == config['docker_network'] and value.get('Driver') == 'bridge' and value.get('Internal') is True and value.get('Labels', {}).get('io.veyport.ssdf') == 'qualification', 'candidate network identity/isolation mismatch')
    e.require(value.get('Options', {}).get('com.docker.network.bridge.name') == 'br-vey-cand', 'candidate network is not the firewall-protected bridge')
    entries = value.get('IPAM', {}).get('Config', [])
    e.require(len(entries) == 1 and entries[0].get('Subnet') == str(expected_subnet), 'candidate network subnet differs from tested configuration')
    return expected_subnet


class DockerRuntime:
    def __init__(self, config, candidate, delivery, work):
        self.config, self.candidate, self.delivery, self.work = config, candidate, Path(delivery), Path(work)
        self.name = 'veyport-ssdf-' + str(candidate['run_id']) + '-' + str(candidate['run_attempt'])
        self.image = None
        self.container = None

    def inspect(self):
        values = e.parse_json(command(['docker', 'inspect', self.container]))
        e.require(len(values) == 1, 'candidate container unavailable')
        value = values[0]
        labels = value.get('Config', {}).get('Labels', {})
        e.require(value.get('Id') == self.container and value.get('Image') == self.image and labels.get(LABEL) == NAMESPACE and labels.get('dev.veyport.candidate') == self.candidate['candidate_id'], 'runtime candidate identity changed')
        networks = value.get('NetworkSettings', {}).get('Networks', {})
        e.require(set(networks) == {self.config['docker_network']} and networks[self.config['docker_network']].get('NetworkID') == self.config['docker_network_id'], 'candidate network changed')
        host = value.get('HostConfig', {})
        e.require(not host.get('Privileged') and host.get('ReadonlyRootfs') is True and host.get('CapDrop') == ['ALL'], 'candidate runtime isolation changed')
        mounts = [x for x in value.get('Mounts', []) if x.get('Destination') == '/data']
        e.require(len(mounts) == 1 and mounts[0].get('Source') == str(self.work / 'hub-data'), 'candidate data mount changed')
        return value

    def start(self):
        command(['/usr/bin/python3', str(Path(__file__).with_name('firewall.py')), 'verify'])
        network = self.config['docker_network']
        net = e.parse_json(command(['docker', 'network', 'inspect', network]))
        e.require(len(net) == 1, 'candidate network is unavailable')
        expected_subnet = validate_network(net[0], self.config)
        for name in ('reports/veyport.scan-binding.json', 'reports/veyport.config.json'):
            e.require((self.delivery / name).stat().st_size <= MAX_METADATA, 'candidate OCI metadata exceeds bound')
        binding = e.parse_json((self.delivery / 'reports/veyport.scan-binding.json').read_bytes())
        e.require(binding.get('version') == self.candidate['version'] and binding.get('revision') == self.candidate['revision'] and re.fullmatch(r'sha256:[a-f0-9]{64}', binding.get('config_digest', '')), 'candidate OCI scan binding mismatch')
        # The entire archive/report bytes are already bound by the authenticated candidate inventory.
        image_tag = 'veyport-ssdf-candidate:' + str(self.candidate['run_id']) + '-' + str(self.candidate['run_attempt'])
        converted = self.work / 'converted.docker.tar'
        runtime_archive = self.work / 'runtime.docker.tar'
        try:
            command(['skopeo', 'copy', '--override-os', 'linux', '--override-arch', 'amd64', 'oci-archive:' + str(self.delivery / 'veyport.oci.tar'), 'docker-archive:' + str(converted) + ':' + image_tag], timeout=300)
            command(['docker', 'image', 'load', '--input', str(converted)], timeout=300)
            image = e.parse_json(command(['docker', 'image', 'inspect', image_tag]))
            e.require(len(image) == 1 and re.fullmatch(r'sha256:[a-f0-9]{64}', image[0].get('Id', '')), 'loaded image identity unavailable')
            source_config = e.parse_json((self.delivery / 'reports/veyport.config.json').read_bytes())
            command(['docker', 'image', 'save', '--output', str(runtime_archive), image[0]['Id']], timeout=300)
            imported_config = e.parse_json(command(['skopeo', 'inspect', '--config', 'docker-archive:' + str(runtime_archive)], limit=MAX_METADATA))
            conversion = config_conversion_binding(source_config, imported_config, binding['config_digest'], image[0]['Id'])
            unchanged = e.parse_json(command(['docker', 'image', 'inspect', image_tag]))
            e.require(unchanged[0]['Id'] == image[0]['Id'], 'candidate image tag changed during conversion verification')
        finally:
            converted.unlink(missing_ok=True)
            runtime_archive.unlink(missing_ok=True)
        labels = image[0].get('Config', {}).get('Labels', {})
        e.require(labels.get('org.opencontainers.image.version') == self.candidate['version'] and labels.get('org.opencontainers.image.revision') == self.candidate['revision'], 'loaded image source labels mismatch')
        self.image = image[0]['Id']
        data = self.work / 'hub-data'
        data.mkdir(mode=0o700)
        # Numeric runtime UID is explicitly configured and checked against the image before starting.
        runtime_user = str(self.config['hub_uid']) + ':' + str(self.config['hub_gid'])
        e.require(image[0].get('Config', {}).get('User') in (runtime_user, str(self.config['hub_uid']), 'veyport'), 'unexpected candidate image user')
        os.chown(data, self.config['hub_uid'], self.config['hub_gid'])
        args = ['docker', 'create', '--name', self.name, '--label', LABEL + '=' + NAMESPACE, '--label', 'dev.veyport.candidate=' + self.candidate['candidate_id'], '--label', 'org.veyport.ssdf.candidate=' + self.candidate['candidate_id'], '--network', network, '--network-alias', 'candidate-hub', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '256', '--memory', self.config.get('hub_memory', '512m'), '--memory-swap', self.config.get('hub_memory', '512m'), '--cpus', '1.5', '--user', runtime_user, '--mount', 'type=bind,src=' + str(data) + ',dst=/data', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m']
        # Docker 29 suppresses published ports on internal networks; host probes use only the inspected bridge IP.
        args += [self.image, '--addr', ':8081', '--grpc-addr', ':9090', '--grpc-external-addr', 'candidate-hub:9090', '--db', '/data/veyport.db', '--agent-bin-dir', '/app']
        self.container = command(args).decode().strip()
        e.require(re.fullmatch(r'[a-f0-9]{64}', self.container), 'invalid candidate container identity')
        command(['docker', 'start', self.container])
        info = self.inspect()
        address = info.get('NetworkSettings', {}).get('Networks', {}).get(network, {}).get('IPAddress')
        e.require(address and ipaddress.ip_address(address) in expected_subnet, 'candidate private network address unavailable')
        return {'schema': 1, 'candidate_id': self.candidate['candidate_id'], 'revision': self.candidate['revision'], 'version': self.candidate['version'], 'artifact_manifest_sha256': e.digest(e.canonical(self.candidate)), 'hub_base_url': 'http://' + address + ':8081', 'grpc_addr': address + ':9090', 'ssh_addr': address + ':2222', 'hub_network_ip': address, 'oci_conversion_binding': conversion, 'hub_container_id': self.container, 'hub_image_id': self.image, 'hub_data_dir': str(data), 'agent_binary': str(self.delivery / 'bin/veyport-agent-linux-amd64'), 'cli_binary': str(self.delivery / 'bin/vey-linux-amd64'), 'work_dir': str(self.work / 'native'), 'network': network, 'hub_network_alias': 'candidate-hub', 'hub_internal_grpc': 'candidate-hub:9090', 'agent_binary_sha256': file_hash(self.delivery / 'bin/veyport-agent-linux-amd64'), 'cli_binary_sha256': file_hash(self.delivery / 'bin/vey-linux-amd64'), 'native_probe': self.config['native_probe'], 'allow_disposable_database_faults': True, 'audit_profile': self.config['audit_profile'], 'agent_runtime_image': self.config['agent_runtime_image']}

    def stop(self):
        if self.container:
            self.inspect()
            command(['docker', 'rm', '-f', self.container])


def verify_inventory(candidate, delivery, retained_only=False):
    for item in candidate['files']:
        if retained_only and item['name'] not in RETAINED:
            continue
        path = safe_file(delivery, item['name'])
        e.require(path.is_file() and path.stat().st_size == item['size'] and file_hash(path) == item['sha256'], 'candidate bytes changed during qualification')


def validate_report(report, candidate, runtime, config):
    e.require(isinstance(report, dict) and report.get('schema_version') == 1 and report.get('candidate_qualified') is True and report.get('status') == 'completed', 'native qualification incomplete')
    for key in ('candidate_id', 'revision'):
        e.require(report.get(key) == candidate[key], 'native report source binding mismatch')
    e.require(report.get('artifact_manifest_sha256') == e.digest(e.canonical(candidate)), 'native report inventory binding mismatch')
    e.require(report.get('runtime', {}).get('agent_image_id') == config.get('agent_runtime_image') and report.get('runtime', {}).get('agent_binary_sha256') == runtime.get('agent_binary_sha256'), 'native agent runtime/binary binding mismatch')
    e.require(report.get('runtime', {}).get('hub_image_id') == runtime['hub_image_id'] and report.get('runtime', {}).get('hub_container_id') == runtime['hub_container_id'], 'native report runtime binding mismatch')
    cases = report.get('cases')
    e.require(isinstance(cases, list) and 1 <= len(cases) <= 128 and all(isinstance(x, dict) and x.get('status') == 'pass' for x in cases), 'native protocol cases incomplete')
    ids = [x.get('id') for x in cases]
    e.require(all(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9._:-]{0,127}', value) for value in ids), 'invalid native case identity')
    e.require(len(set(ids)) == len(ids) and set(config['required_cases']) <= set(ids), 'required native protocol coverage missing')
    e.require(len(config['required_cases']) >= 6 and len(set(config['required_cases'])) == len(config['required_cases']), 'native protocol policy is incomplete')
    e.require(report.get('required_scopes') == ['native:grpc', 'native:ssh'], 'native required scope declaration mismatch')
    scopes = report.get('scopes')
    e.require(isinstance(scopes, list) and {x.get('id') for x in scopes} == {'native:grpc', 'native:ssh'} and all(x.get('status') == 'completed' and x.get('authenticated') is True and x.get('coverage_complete') is True and x.get('findings') == [] for x in scopes), 'native protocol scopes incomplete')
    profile = config.get('audit_profile')
    e.require(profile in ('standard', 'enhanced') and report.get('audit_profile') == profile and candidate.get('audit_profile') == profile, 'candidate audit profile mismatch')
    e.require(report.get('required_audit_admission_exercised') is True, 'required audit admission not qualified')
    if profile == 'enhanced':
        e.require(report.get('enhanced_receipt_exercised') is True, 'enhanced external receipt failure not qualified')
    else:
        e.require(report.get('enhanced_receipt_exercised') is False, 'standard mode must not claim enhanced receipt coverage')
    e.require(len(e.canonical(report)) <= 8192, 'native summary exceeds receipt bound')
    return report


def run_harness(config, runtime, work):
    e.require(re.fullmatch(r'sha256:[a-f0-9]{64}', config.get('agent_runtime_image', '')), 'operator agent fixture image pin unavailable')
    support_image = e.parse_json(command(['docker', 'image', 'inspect', config['agent_runtime_image']]))
    e.require(len(support_image) == 1 and support_image[0].get('Id') == config['agent_runtime_image'], 'operator agent fixture image unavailable')
    executable = Path(config['harness_executable'])
    e.require(executable.is_absolute() and not executable.is_symlink() and executable.is_file() and executable.stat().st_uid == 0 and executable.stat().st_mode & 0o022 == 0, 'native harness is not operator-owned')
    e.require(file_hash(executable) == config['harness_sha256'], 'native harness differs from reviewed deployment')
    output, private = Path(work) / 'native-report.json', Path(work) / 'runtime.json'
    temporary_root = Path(config['native_tmp_root'])
    e.require(temporary_root.is_absolute() and temporary_root.is_dir() and not temporary_root.is_symlink(), 'native private temporary directory unavailable')
    native_temporary = Path(tempfile.mkdtemp(prefix='native-', dir=temporary_root))
    runtime = dict(runtime, work_dir=str(native_temporary / 'work'))
    private.write_bytes(e.canonical(runtime))
    probe = Path(config['native_probe'])
    e.require(probe.is_absolute() and not probe.is_symlink() and probe.is_file() and probe.stat().st_uid == 0 and probe.stat().st_mode & 0o022 == 0 and file_hash(probe) == config['native_probe_sha256'], 'native probe differs from reviewed deployment')
    try:
        command(['/usr/bin/python3', str(executable), '--config', str(private), '--output', str(output)], timeout=900)
    finally:
        shutil.rmtree(native_temporary)  # Revoke transient synthetic secrets even on failed qualification.
    e.require(not output.is_symlink() and output.is_file() and output.stat().st_size <= MAX_METADATA, 'native report missing or exceeds bound')
    return e.parse_json(output.read_bytes())


def disclosure_safe_report(report):
    # The private full report may contain endpoints, synthetic identities and diagnostic details.
    # Only these policy-relevant constants and safe counts cross the public status boundary.
    return {key: report[key] for key in ('schema_version', 'candidate_qualified', 'candidate_id', 'revision', 'artifact_manifest_sha256', 'status', 'required_scopes')} | {
        'scopes': [{'id': scope['id'], 'status': scope['status'], 'authenticated': scope['authenticated'], 'coverage_complete': scope['coverage_complete'], 'findings': []} for scope in report['scopes']],
        'cases': [{'id': case['id'], 'status': 'pass'} for case in report['cases']],
        'audit_profile': report.get('audit_profile', report.get('audit_mode')),
        'enhanced_receipt_exercised': report.get('enhanced_receipt_exercised', False),
        'required_audit_admission_exercised': report['required_audit_admission_exercised'],
    }


def qualification_receipt(candidate, report, config):
    started = e.now().replace(microsecond=0)
    payload = {'schema': 1, 'status': 'qualified', 'repository': candidate['repository'], 'run_id': candidate['run_id'], 'run_attempt': candidate['run_attempt'], 'revision': candidate['revision'], 'candidate_id': candidate['candidate_id'], 'audit_profile': candidate['audit_profile'], 'artifact_manifest_sha256': e.digest(e.canonical(candidate)), 'qualified_at': e.iso(started), 'expires_at': e.iso(started + dt.timedelta(minutes=30)), 'report': disclosure_safe_report(report)}
    return {'payload': payload, 'signature': e.sign(e.canonical(payload), config['signing_key_file'])}


def save_state(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    descriptor, pending = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(e.canonical(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def publish_qualification(api, envelope):
    payload = envelope['payload']
    encoded = base64.urlsafe_b64encode(e.canonical(envelope)).decode().rstrip('=')
    e.require(len(encoded) <= 16000, 'candidate receipt exceeds bound')
    url = f"https://github.com/{payload['repository']}/actions/runs/{payload['run_id']}#ssdf-candidate={encoded}"
    body = {'state': 'success', 'context': f"ssdf-candidate/{payload['run_id']}/{payload['run_attempt']}", 'description': 'Exact candidate native qualification completed', 'target_url': url}
    api.request(api.prefix + '/statuses/' + payload['revision'], 'POST', body)


@contextlib.contextmanager
def lease(config):
    root = Path(config['state_root'])
    e.require(root.is_absolute() and not root.is_symlink() and root.is_dir() and root.stat().st_mode & 0o022 == 0, 'invalid candidate state root')
    e.require(shutil.disk_usage(root).free >= config.get('minimum_free_bytes', 12 << 30), 'insufficient private candidate storage')
    descriptor = os.open(root / 'lease.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise e.EvidenceError('another candidate holds the qualification lease') from exc
        yield root


def qualify(config, api, run, artifact):
    e.trusted_run(run, config)
    e.verify_trust_anchor(api, run, config)
    e.require(run['status'] == 'in_progress', 'candidate workflow is no longer active')
    with lease(config) as root:
        work = Path(tempfile.mkdtemp(prefix='run-' + str(run['id']) + '-' + str(run['run_attempt']) + '-', dir=root))
        runtime = None
        try:
            download_candidate(api, artifact, run, work / 'artifact.zip')
            unwrap_candidate(work / 'artifact.zip', work / 'candidate.age')
            candidate = decrypt_candidate(work / 'candidate.age', config['identity_file'], work / 'delivery')
            bind_manifest(candidate, run, config)
            e.require(candidate['audit_profile'] == config['audit_profile'], 'requested candidate audit profile is not active')
            e.require(RETAINED <= {item['name'] for item in candidate['files']}, 'candidate native artifact inventory incomplete')
            verify_inventory(candidate, work / 'delivery', retained_only=True)
            runtime = DockerRuntime(config, candidate, work / 'delivery', work)
            identity = runtime.start()
            report = validate_report(run_harness(config, identity, work), candidate, identity, config)
            runtime.inspect()
            verify_inventory(candidate, work / 'delivery', retained_only=True)
            current = api.get('/actions/runs/' + str(run['id']))
            e.require(current['status'] == 'in_progress' and current['run_attempt'] == run['run_attempt'] and current['head_sha'] == run['head_sha'], 'candidate run cancelled or superseded')
            envelope = qualification_receipt(candidate, report, config)
            # Persist private result before publishing an authenticated short-lived acknowledgement.
            path = work / 'qualification.json'
            with path.open('xb') as output:
                output.write(e.canonical(envelope))
                output.flush()
                os.fsync(output.fileno())
            completed = root / 'completed'
            completed.mkdir(mode=0o700, exist_ok=True)
            state = {'artifact_id': artifact['id'], 'artifact_digest': artifact['digest'], 'receipt': envelope, 'published': False}
            marker = completed / (str(run['id']) + '-' + str(run['run_attempt']) + '.json')
            save_state(marker, state)
            publish_qualification(api, envelope)
            state['published'] = True
            save_state(marker, state)
            return envelope
        finally:
            if runtime:
                runtime.stop()
            # Preserve private diagnostics. A separate operator applies work-directory retention.


def poll(config, api):
    api.verified_sources = set()
    runs = api.pages('/actions/runs?status=in_progress', 'workflow_runs')
    for run in runs:
        try:
            e.trusted_run(run, config)
        except e.EvidenceError:
            continue
        artifacts = api.pages('/actions/runs/' + str(run['id']) + '/artifacts', 'artifacts')
        selected = [x for x in artifacts if x['name'] == f"ssdf-candidate-v1-{run['id']}-{run['run_attempt']}"]
        e.require(len(selected) <= 1, 'ambiguous candidate artifacts')
        if selected:
            marker = Path(config['state_root']) / 'completed' / (str(run['id']) + '-' + str(run['run_attempt']) + '.json')
            if marker.exists():
                previous = e.parse_json(marker.read_bytes())
                e.require(previous.get('artifact_id') == selected[0]['id'] and previous.get('artifact_digest') == selected[0]['digest'], 'completed candidate artifact identity changed')
                if not previous.get('published'):
                    envelope = previous['receipt']
                    payload = envelope['payload']
                    e.verify_signature(e.canonical(payload), envelope['signature'], config['signing_public_key_file'])
                    e.require(e.timestamp(payload['qualified_at']) <= e.now() < e.timestamp(payload['expires_at']), 'stored qualification expired before publication')
                    e.require(payload['run_id'] == run['id'] and payload['run_attempt'] == run['run_attempt'] and payload['revision'] == run['head_sha'], 'stored qualification source mismatch')
                    publish_qualification(api, envelope)
                    previous['published'] = True
                    save_state(marker, previous)
                # Never silently rescan or renew a qualification lease. An expired receipt requires a new attempt.
                continue
            qualify(config, api, run, selected[0])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('poll', 'preflight'))
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        config = e.parse_json(Path(args.config).read_bytes())
        e.require(os.geteuid() == 0, 'candidate Docker coordinator requires its dedicated operator service identity')
        for name in ('docker', 'skopeo', 'age', 'openssl'):
            e.require(shutil.which(name), 'candidate coordinator dependency unavailable')
        e.require(config.get('network_isolation_verified') is True, 'operator network isolation prerequisite unverified')
        if args.command == 'preflight':
            with lease(config):
                pass
            print('candidate coordinator storage and dependency preflight passed; runtime qualification still required')
            return
        token = Path(config['token_file']).read_text().strip()
        poll(config, e.GitHub(config['repository'], token))
    except (e.EvidenceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile, urllib.error.URLError) as exc:
        print('candidate qualification failed: ' + (str(exc) if isinstance(exc, e.EvidenceError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
