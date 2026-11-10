"""Legacy bootstrap preparation never executes candidate helpers/configuration."""
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PIN = 'da509180b0de5725a5059e9aa031f22d39aa5856'
SOURCE = 'a' * 40
FILES = {'unit': {'coverage-hub.out', 'coverage-hub-cmd.out', 'coverage-agent.out', 'coverage-cli.out', 'coverage-proto.out', 'web/coverage/lcov.info'},
         'integration': {'coverage-integration.out', 'coverage-agent-integration.out'}}


def code():
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    block = workflow.split("python3 -I -S - <<'BOOTSTRAP_PY'\n", 1)[1].split('          BOOTSTRAP_PY', 1)[0]
    return '\n'.join(line[10:] for line in block.splitlines())


def zipped(group, change=None):
    entries = [(name, b'mode: atomic\n' if name.endswith('.out') else b'TN:\nSF:web/src/main.tsx\nDA:1,1\nend_of_record\n', stat.S_IFREG) for name in sorted(FILES[group])]
    if change: entries = change(entries)
    output = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(output, 'w') as archive:
        warnings.simplefilter('ignore', UserWarning)
        for name, value, kind in entries:
            entry = zipfile.ZipInfo(name); entry.external_attr = (kind | 0o644) << 16
            archive.writestr(entry, value)
    return output.getvalue()


class LegacyCredentialPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.workspace = self.root / 'workspace'; self.workspace.mkdir()
        self.source = self.workspace / 'candidate-source'; self.source.mkdir()
        self.control = self.workspace / 'trusted-bootstrap'; self.control.mkdir()
        release = self.control / 'scripts/release'; release.mkdir(parents=True)
        fixtures = ROOT / 'scripts/release/fixtures/sonar-bootstrap-main'
        for name in ('sonar_context.py', 'metadata.py'):
            (release / name).write_bytes((fixtures / (name + '.txt')).read_bytes())
        self.profile = (ROOT / 'sonar-project.properties').read_bytes()
        (self.control / 'sonar-project.properties').write_bytes(self.profile)
        (self.source / 'sonar-project.properties').write_text('sonar.scanner.javaExePath=./candidate-java\nsonar.host.url=https://example.invalid\n')
        self.canary = self.root / 'candidate-executed'
        poison = 'from pathlib import Path\nPath(' + repr(str(self.canary)) + ').touch()\n'
        for name in ('sitecustomize.py', 'metadata.py', 'sonar_context.py', 'json.py'):
            (self.source / name).write_text(poison)
        (self.source / 'scripts/release').mkdir(parents=True)
        (self.source / 'scripts/release/sonar_context.py').write_text(poison)
        self.runner = self.root / 'runner'; self.runner.mkdir()
        for group in FILES:
            path = self.runner / ('bootstrap-coverage-' + group); path.mkdir()
            # Raw download basename is deliberately unrelated to artifact name.
            (path / 'opaque-content-disposition.payload').write_bytes(zipped(group))
        self.event = self.root / 'event.json'
        self.event_value = {'repository': {'full_name': 'lorconksu/veyport', 'private': False},
            'pull_request': {'number': 115, 'state': 'open', 'merged': False, 'merged_at': None,
                'head': {'sha': SOURCE, 'ref': 'feat/bootstrap', 'repo': {'full_name': 'lorconksu/veyport'}},
                'base': {'ref': 'main', 'repo': {'full_name': 'lorconksu/veyport'}}}}
        self.event.write_text(json.dumps(self.event_value))
        self.output = self.root / 'output'
        self.env = dict(os.environ, GITHUB_WORKSPACE=str(self.workspace), RUNNER_TEMP=str(self.runner),
            GITHUB_EVENT_PATH=str(self.event), GITHUB_OUTPUT=str(self.output), EXPECTED_SOURCE_SHA=SOURCE,
            GITHUB_REPOSITORY='lorconksu/veyport', GITHUB_EVENT_NAME='pull_request',
            GITHUB_REF='refs/pull/115/merge', GITHUB_SHA='c' * 40, SONAR_PULL_REQUEST_REQUIRED='false',
            PYTHONPATH=str(self.source), SONAR_TOKEN='')
        self.assertFalse(self.canary.exists()); self.assertFalse(self.output.exists())

    def run_prepare(self, control_sha=PIN, script=None):
        # The production pin/hash constants stay untouched. Only actual Git
        # subprocess responses are isolated test doubles; no fetch/object-store
        # dependency or runtime profile substitution is involved.
        launcher = '''import subprocess
from pathlib import Path
control = CONTROL_PATH
source = SOURCE_PATH
def output(argv, _control=control, _source=source, **kwargs):
    if argv == ['git', '-C', _control, 'rev-parse', 'HEAD']: return CONTROL_SHA + '\\n'
    if argv == ['git', '-C', _source, 'rev-parse', 'HEAD']: return SOURCE_SHA + '\\n'
    raise AssertionError('Unexpected subprocess')
def run(argv, **kwargs):
    if argv[:3] == ['git', 'merge-base', '--is-ancestor']:
        return subprocess.CompletedProcess(argv, 0)
    raise AssertionError('Unexpected candidate command')
subprocess.check_output = output
subprocess.run = run
_native_script = SCRIPT
exec(compile(_native_script, '<legacy-native>', 'exec'))
'''.replace('CONTROL_PATH', repr(str(self.control))).replace('SOURCE_PATH', repr(str(self.source))).replace('CONTROL_SHA', repr(control_sha)).replace('SOURCE_SHA', repr(SOURCE)).replace('SCRIPT', repr(script if script is not None else code()))
        return subprocess.run([sys.executable, '-I', '-S', '-c', launcher], cwd=self.source,
                              env=self.env, capture_output=True, text=True, timeout=10)

    def reject(self, result, message=None):
        self.assertNotEqual(result.returncode, 0)
        if message: self.assertIn(message, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.canary.exists())

    def test_pr_head_data_poisoned_helper_and_profile_never_execute(self):
        (self.source / '.scannerwork').mkdir()
        (self.source / '.scannerwork/candidate-cache').write_text('untrusted')
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.canary.exists())
        self.assertEqual((self.source / 'sonar-project.properties').read_bytes(), self.profile)
        self.assertNotIn(b'javaExePath', (self.source / 'sonar-project.properties').read_bytes())
        self.assertFalse((self.source / '.scannerwork').exists())
        self.assertTrue((self.runner / 'bootstrap-sonar').is_dir())
        self.assertEqual(self.output.read_text(), 'gate_args=-Dsonar.pullrequest.key=115 -Dsonar.pullrequest.branch=feat/bootstrap -Dsonar.pullrequest.base=main\n')
        for group, names in FILES.items():
            for name in names:
                target = self.source / name
                self.assertTrue(target.is_file(), (group, name))
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_main_context_uses_same_trusted_profile_and_real_required_gate(self):
        self.env.update(GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_SHA=SOURCE)
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), 'gate_args=-Dsonar.branch.name=main\n')

    def test_wrong_control_head_or_worktree_helper_is_rejected_before_loading(self):
        self.reject(self.run_prepare(control_sha='b' * 40), 'Protected legacy Sonar preparation refused')
        target = self.control / 'scripts/release/metadata.py'
        target.write_text('from pathlib import Path\nPath(' + repr(str(self.canary)) + ').touch()\n')
        self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused')

    def test_source_profile_and_report_ancestor_links_are_rejected(self):
        for name in ('sonar-project.properties', 'web', 'web/coverage', '.scannerwork'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as outside:
                target = self.source / name
                if target.exists():
                    if target.is_dir(): shutil.rmtree(target)
                    else: target.unlink()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(outside)
                self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused')
                target.unlink()

    def test_source_fifo_and_trusted_helper_link_are_rejected_without_blocking(self):
        fifo = self.source / 'candidate-pipe'; os.mkfifo(fifo)
        self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused'); fifo.unlink()
        target = self.control / 'scripts/release/metadata.py'; target.unlink()
        target.symlink_to(ROOT / 'scripts/release/fixtures/sonar-bootstrap-main/metadata.py.txt')
        self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused')

    def test_zip_extra_traversal_duplicate_link_fifo_empty_and_missing_reports_reject(self):
        mutations = [lambda rows: rows + [('sonar-project.properties', b'poison', stat.S_IFREG)],
                     lambda rows: rows + [('../escaped', b'poison', stat.S_IFREG)],
                     lambda rows: rows + [rows[0]],
                     lambda rows: [(rows[0][0], b'target', stat.S_IFLNK)] + rows[1:],
                     lambda rows: [(rows[0][0], b'pipe', stat.S_IFIFO)] + rows[1:],
                     lambda rows: [(rows[0][0], b'', stat.S_IFREG)] + rows[1:],
                     lambda rows: rows[1:]]
        raw = self.runner / 'bootstrap-coverage-unit/opaque-content-disposition.payload'
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                raw.write_bytes(zipped('unit', mutate))
                self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused')
                self.assertFalse((self.workspace / 'escaped').exists())
        self.assertEqual((self.control / 'sonar-project.properties').read_bytes(), self.profile)

    def test_raw_and_entry_size_limits_reject_before_large_read(self):
        raw = self.runner / 'bootstrap-coverage-unit/opaque-content-disposition.payload'
        value = bytearray(zipped('unit')); index = value.index(b'PK\x01\x02')
        struct.pack_into('<I', value, index + 24, (64 << 20) + 1)
        raw.write_bytes(value)
        self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused')
        with raw.open('wb') as stream: stream.truncate((128 << 20) + 1)
        self.reject(self.run_prepare(), 'Protected legacy Sonar preparation refused')

    def test_empty_directory_entries_for_expected_report_ancestors_are_safe(self):
        path = self.runner / 'bootstrap-coverage-unit/opaque-content-disposition.payload'
        path.write_bytes(zipped('unit', lambda rows: [('web/', b'', stat.S_IFDIR), ('web/coverage/', b'', stat.S_IFDIR)] + rows))
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mismatched_pr_head_and_foreign_repository_never_emit_scanner_args(self):
        for field in ('sha', 'repository'):
            with self.subTest(field=field):
                event = json.loads(json.dumps(self.event_value))
                if field == 'sha': event['pull_request']['head']['sha'] = 'b' * 40
                else: event['pull_request']['head']['repo']['full_name'] = 'foreign/fork'
                self.event.write_text(json.dumps(event))
                self.reject(self.run_prepare())
                # The first failure may have prepared data, but each new event
                # must reach its own context check rather than a stale mkdir.
                shutil.rmtree(self.runner / 'bootstrap-sonar', ignore_errors=True)

    def test_native_preparation_and_scanner_are_pinned_with_no_candidate_command(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        job = workflow.split('  sonarcloud:\n', 1)[1].split('  secret-scan:\n', 1)[0]
        self.assertNotIn('run: python3 scripts/release/sonar_context.py', job)
        self.assertIn('ref: ' + PIN, job)
        self.assertEqual(job.count('persist-credentials: false'), 2)
        self.assertEqual(job.count('skip-decompress: true'), 2)
        self.assertIn('projectBaseDir: candidate-source', job)
        self.assertIn('-Dsonar.host.url=https://sonarcloud.io', job)
        self.assertIn('-Dsonar.qualitygate.wait=true', job)
        self.assertLess(job.index("python3 -I -S - <<'BOOTSTRAP_PY'"), job.index('SONAR_TOKEN:'))
        self.assertEqual(job.count('SONAR_TOKEN:'), 1)


if __name__ == '__main__':
    unittest.main()
