"""Offline acceptance tests; fixture findings are synthetic and contain no secrets."""
import copy
import importlib.util
import json
import os
import re
import shutil
import stat
from pathlib import Path
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest import mock

POLICY_PATH = Path(__file__).with_name('snyk_policy.py')
WORKFLOW_PATHS = tuple(POLICY_PATH.parents[2] / '.github/workflows' / name for name in
                       ('snyk-policy.yml', 'snyk-policy-qualification.yml'))


def workflows():
    return ((path.name, path.read_text()) for path in WORKFLOW_PATHS)


def final_gate(workflow):
    return textwrap.dedent(workflow.rsplit('run: |', 1)[1])


def report(project='hub/go.mod', issues=None):
    issues = issues or []
    manager = 'gomodules' if project.endswith('go.mod') else 'npm' if project.endswith('package.json') else 'pip'
    return {'ok': not issues, 'dependencyCount': 3, 'vulnerabilities': issues,
            'licensesPolicy': {'orgLicenseRules': None, 'severities': None},
            'filtered': {'ignore': [], 'patch': []}, 'hasUnknownVersions': False,
            'targetFile': Path(project).name, 'packageManager': manager, 'org': 'lorconksu'}


def issue(severity='high', kind='vuln', **extra):
    finding = {'id': 'SNYK-JS-SYNTHETIC-123', 'severity': severity, 'type': kind,
               'name': 'synthetic-package', 'isUpgradable': False, 'fixedIn': [],
               'publicationTime': '2001-01-01'}
    if kind == 'license':
        license_name=extra.get('license', 'Synthetic-License')
        finding.update(id='snyk:lic:npm:synthetic-package:'+str(license_name), license=license_name)
    return {**finding, **extra}


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not POLICY_PATH.exists():
            raise AssertionError('Missing candidate policy implementation')
        spec = importlib.util.spec_from_file_location('snyk_policy', POLICY_PATH)
        cls.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.policy)

    def test_old_unfixed_high_and_critical_block_independently(self):
        result = self.policy.assess(report(issues=[issue(), issue('critical')]), 1, 'hub/go.mod')
        self.assertEqual(result['blocking_vulnerability_records'], 2)
        self.assertEqual(result['finding_verdict'], 'blocked')
        self.assertEqual(result['policy_status'], 'incomplete')

    def test_severity_with_critical_uses_higher_of_both_fields(self):
        for a, b in [('medium', 'critical'), ('critical', 'medium')]:
            result = self.policy.assess(report(issues=[issue(a, severityWithCritical=b)]), 1, 'hub/go.mod')
            self.assertEqual(result['blocking_vulnerability_records'], 1)

    def test_high_unknown_and_medium_licenses_are_distinct(self):
        result = self.policy.assess(report(issues=[issue('high', 'license'),
            issue('medium', 'license', license='Unknown'), issue('medium', 'license')]), 1, 'hub/go.mod')
        self.assertEqual(result['blocking_license_records'], 2)
        self.assertEqual(result['nonblocking_license_records'], 1)

    def test_license_identity_uses_license_field_not_package_name(self):
        result=self.policy.assess(report(issues=[issue('medium', 'license',
            name='synthetic-package', license='Unknown'), issue('medium', 'license',
            name='synthetic-package', license='GPL-3.0')]), 1, 'hub/go.mod')
        self.assertEqual(result['blocking_license_records'], 2)

    def test_license_id_and_field_must_have_one_consistent_identity(self):
        for encoded in ['Unknown', *sorted(self.policy.HIGH_LICENSES)]:
            value=issue('medium', 'license', license='MIT', id='snyk:lic:npm:synthetic-package:'+encoded)
            assessed=self.policy.assess(report(issues=[value]), 1, 'hub/go.mod')
            self.assertFalse(assessed['technically_complete'])
        for identity, license_name in [(None, 'MIT'), ('', 'MIT'),
                ('snyk:lic:npm:synthetic-package:', 'MIT'),
                ('snyk:lic::synthetic-package:MIT', 'MIT'), ('snyk:lic:npm::MIT', 'MIT'),
                ('snyk:lic:npm:synthetic-package:Unknown:MIT', 'MIT'),
                ('snyk:lic:npm:synthetic-package:MIT\x00', 'MIT\x00'),
                ('snyk:lic:npm:synthetic-package:MIT', None),
                ('snyk:lic:npm:synthetic-package:MIT', ''),
                ('snyk:lic:npm:synthetic-package:MIT', ' MIT')]:
            with self.subTest(identity=identity, license=license_name):
                assessed=self.policy.assess(report(issues=[issue('medium', 'license',
                    id=identity, license=license_name)]), 1, 'hub/go.mod')
                self.assertFalse(assessed['technically_complete'])
        missing_id=issue('medium', 'license', license='MIT'); missing_id.pop('id')
        self.assertFalse(self.policy.assess(report(issues=[missing_id]), 1, 'hub/go.mod')['technically_complete'])
        missing=issue('medium', 'license', id='snyk:lic:npm:synthetic-package:MIT'); missing.pop('license')
        self.assertFalse(self.policy.assess(report(issues=[missing]), 1, 'hub/go.mod')['technically_complete'])

    def test_empty_targetfile_uses_real_legacy_display_target(self):
        value=report('web/package.json', [issue()])
        value.update(targetFile='', displayTargetFile='package.json')
        self.assertEqual(self.policy.assess(value, 1, 'web/package.json')['blocking_vulnerability_records'], 1)

    def test_medium_only_is_nonblocking_but_missing_coverage_cannot_pass(self):
        result = self.policy.assess(report(issues=[issue('medium')]), 1, 'hub/go.mod')
        self.assertEqual(result['finding_verdict'], 'nonblocking')
        self.assertEqual(result['policy_status'], 'incomplete')
        self.assertFalse(result['license_controls_verified'])

    def test_unqualified_coverage_has_no_json_attestation_bypass(self):
        for coverage in [None, {}, {'Unknown': 'high'}, {'severities': {'Unknown': 'high'}},
                         {'authenticated': True, 'unknown': 'high', 'approved': True}]:
            value = report()
            value['licensesPolicy'] = coverage
            value['license_coverage_qualified'] = True
            self.assertEqual(self.policy.assess(value, 0, 'hub/go.mod')['policy_status'], 'incomplete')

    def test_malformed_and_suppressed_reports_fail_closed(self):
        changes = [ {'org': 'wrong'}, {'packageManager': 'pip'}, {'targetFile': 'wrong'},
            {'displayTargetFile': 'wrong'}, {'vulnerabilities': [issue('high', 'license', license=None)]},
            {'filtered': {'ignore': [{}], 'patch': []}}, {'filtered': {'ignore': [], 'patch': {}}},
            {'filtered': None}, {'hasUnknownVersions': True}, {'vulnerabilities': [issue('unknown')]},
            {'vulnerabilities': [issue(severityWithCritical=None)]}, {'vulnerabilities': [issue(kind='other')]},
            {'vulnerabilities': [issue(severity=None)]}, {'dependencyCount': True}, {'exceptions': []}]
        for change in changes:
            with self.subTest(change=change):
                value = report(); value.update(change)
                self.assertFalse(self.policy.assess(value, 1 if value['vulnerabilities'] else 0,
                                                   'hub/go.mod')['technically_complete'])
        for code in [2, 124, True]:
            self.assertFalse(self.policy.assess(report(), code, 'hub/go.mod')['technically_complete'])

    def test_legacy_vulnerability_and_license_markers_are_unambiguous(self):
        legacy=issue('medium'); legacy.pop('type')
        assessed=self.policy.assess(report(issues=[legacy]), 1, 'hub/go.mod')
        self.assertTrue(assessed['technically_complete'])
        self.assertEqual(assessed['nonblocking_vulnerability_records'], 1)
        ambiguous=[]
        for license_name in ['Unknown', 'GPL-3.0']:
            missing=issue('medium', 'license', license=license_name); missing.pop('type')
            ambiguous.append(missing)
            marker_only=dict(missing); marker_only.pop('license'); ambiguous.append(marker_only)
            ambiguous.append(issue('medium', 'vuln', license=license_name))
        ambiguous += [dict(legacy, type=None), dict(legacy, id='unrecognized'),
                      issue('medium', 'license', id='SNYK-JS-SYNTHETIC-123'),
                      issue('medium', 'vuln', id='snyk:lic:npm:synthetic-package:Unknown')]
        for finding in ambiguous:
            with self.subTest(finding=finding):
                result=self.policy.assess(report(issues=[finding]), 1, 'hub/go.mod')
                self.assertFalse(result['technically_complete'])
                self.assertEqual(result['policy_status'], 'incomplete')

    def test_shared_runner_removes_stale_reports_before_each_attempt(self):
        for code in (0, 1):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); raw=root/'raw'; raw.mkdir()
                stale=report(issues=[issue()] if code else None)
                def produce(command, cwd, prefix, timeout, env=None):
                    self.policy.trial.write_json(prefix.with_suffix('.json'), stale)
                    return code
                with mock.patch.object(self.policy.trial, 'python_resolver_command', return_value=root/'wrapper'), \
                     mock.patch.object(self.policy.trial, 'capture', side_effect=produce):
                    first=self.policy.trial.scan_projects(root/'source', root/'scanner', raw, root/'python', root/'public',
                        projects=('hub/go.mod',), assessor=self.policy.assess, ignore_policy=True,
                        attempt_binding='a'*64)
                self.assertIn(first[0]['status'], self.policy.trial.COMPLETE)
                # Model both an earlier completed invocation and an old second-attempt output.
                self.policy.trial.write_json(raw/'project-0-attempt-2.json', stale)
                def no_output(command, cwd, prefix, timeout, env=None):
                    self.assertFalse(prefix.with_suffix('.json').exists())
                    return code
                with mock.patch.object(self.policy.trial, 'python_resolver_command', return_value=root/'wrapper'), \
                     mock.patch.object(self.policy.trial, 'capture', side_effect=no_output):
                    rows=self.policy.trial.scan_projects(root/'source', root/'scanner', raw, root/'python', root/'public',
                        projects=('hub/go.mod',), assessor=self.policy.assess, ignore_policy=True,
                        attempt_binding='a'*64)
                self.assertEqual(rows[0]['status'], 'scan_incomplete')
                self.assertEqual(len(rows[0]['attempts']), 2)
                self.assertTrue(all(attempt['report_sha256'] is None for attempt in rows[0]['attempts']))

    def test_strict_json_duplicate_key_and_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            for text in ['{"ok":true,"ok":false}', '{"count":NaN}', '{"count":1e999}', '[{}]']:
                path.write_text(text)
                self.assertFalse(self.policy.assess(self.policy.trial.load_report(path), 0,
                                                   'hub/go.mod')['technically_complete'])

    def test_missing_or_duplicate_eighth_project_incomplete(self):
        rows = [dict(path=p, **self.policy.assess(report(p), 0, p)) for p in self.policy.PROJECTS]
        self.assertEqual(len(rows), 8)
        for candidates in [rows[:-2] + rows[-1:], rows + [rows[0]], rows + [dict(rows[0], path='extra')]]:
            self.assertEqual(self.policy.policy_result(candidates)['exit_code'], 2)

    def test_summary_rebuilds_allowlist(self):
        rows = [dict(path=p, **self.policy.assess(report(p, [issue()]), 1, p), secret='SENTINEL')
                for p in self.policy.PROJECTS]
        state = {'source_sha': 'a'*40, 'control_sha': 'b'*40, 'versions': {'snyk': 'SENTINEL'},
                 'projects': rows, 'secret': 'SENTINEL', 'preparation_complete': True,
                 'manifests_unchanged': True}
        text = json.dumps(self.policy.public_summary(state))
        for private in ['SENTINEL', 'SNYK-JS-SYNTHETIC-123', 'publicationTime']:
            self.assertNotIn(private, text)

    def test_final_gate_requires_every_outcome(self):
        good = dict(scan='success', policy='success', encrypt='success', upload='success', cleanup='success')
        for name, workflow in workflows():
            with self.subTest(workflow=name):
                gate = final_gate(workflow)
                def check(outcomes, fresh='0'):
                    environment={key.upper()+'_OUTCOME': value for key,value in outcomes.items()}
                    if fresh is not None: environment['SEALED_POLICY_EXIT']=fresh
                    return subprocess.run(['/bin/bash', '-c', gate], env=environment, capture_output=True).returncode
                self.assertEqual(check(good), 0)
                for fresh in ['1', '2', '', '00', 'true', 'clean', '0\n', None]:
                    self.assertNotEqual(check(good, fresh), 0)
                for step in good:
                    for outcome in ['failure', 'skipped', 'cancelled', '']:
                        self.assertNotEqual(check(dict(good, **{step: outcome})), 0)

    def make_source(self, root):
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        for name in self.policy.MANIFESTS:
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
            content = ('module example.test/module\n\ngo 1.26.11\n' if name.endswith('go.mod') else
                       'boto3==1.40.72\ncryptography==50.0.2\n' if name.endswith('requirements.txt') else
                       '{"lockfileVersion":3,"packages":{}}\n' if name.endswith('package-lock.json') else
                       '{}\n' if name.endswith('package.json') else '')
            path.write_text(content)
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Synthetic', '-c',
                        'user.email=synthetic@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        return self.policy.trial.revision(root)

    def test_candidate_requires_new_exact_python_bytes_even_when_old_bytes_are_committed(self):
        for content, accepted in [('boto3==1.40.72\ncryptography==50.0.2\n', True),
                                  ('boto3==1.40.72\ncryptography==46.0.5\n', False),
                                  ('boto3==1.40.72\ncryptography==50.0.2\n\n', False)]:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); self.make_source(root)
                (root/self.policy.PROJECTS[-1]).write_text(content)
                subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(root), '-c', 'user.name=Synthetic', '-c',
                    'user.email=synthetic@example.invalid', 'commit', '--allow-empty', '-qm', 'requirements'], check=True)
                sha=self.policy.trial.revision(root)
                if accepted:
                    self.assertIn(self.policy.PROJECTS[-1], self.policy.validate_source(root, sha))
                else:
                    with self.assertRaisesRegex(ValueError, 'Python wheel closure unqualified'):
                        self.policy.validate_source(root, sha)

    def test_candidate_python_hash_reaches_mirror_and_every_scan_attempt(self):
        for tamper in (False, True):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as directory, \
                 tempfile.TemporaryDirectory(prefix='veyport-snyk-public.', dir='/tmp') as public_directory:
                root=Path(directory); source=root/'source'; source.mkdir(); sha=self.make_source(source)
                public=Path(public_directory); raw=root/'raw'; raw.mkdir()
                trial=self.policy.trial
                binding=trial.create_python_mirror(public, source, sha, sources={sha:self.policy.GO_VERSION},
                    expected_requirements_sha256=self.policy.PYTHON_REQUIREMENTS_SHA256)
                args=SimpleNamespace(source=source, control=root/'control', sha=sha, control_sha='b'*40,
                    scanner=root/'scanner', public_root=public)
                lock=args.control/'scripts/security/snyk_policy_requirements.lock'
                lock.parent.mkdir(parents=True); lock.write_text('synthetic candidate lock')
                hashes=self.policy.validate_source(source, sha)
                state={'source_sha':sha, 'control_sha':args.control_sha, 'preparation_complete':True,
                    'manifest_hashes':hashes, 'python_mirror':binding, 'versions':{'snyk':'1.2.3'},
                    'run_identity_sha256':'f'*64,
                    'python_lock':{'path':'scripts/security/snyk_policy_requirements.lock',
                                   'sha256':self.policy.file_digest(lock)}}
                trial.write_json(raw/'state.json', state)
                python_attempts=[]
                def capture(command, cwd, prefix, timeout, env=None):
                    project=self.policy.PROJECTS[int(prefix.name.split('-')[1])]
                    if project.endswith('requirements.txt'):
                        python_attempts.append(prefix.name)
                        self.assertEqual((cwd/'requirements.txt').read_text(),
                            'boto3==1.40.72\ncryptography==50.0.2\n')
                        if len(python_attempts)==1:
                            if tamper:
                                mirror=cwd/'requirements.txt'; mirror.chmod(0o600); mirror.write_text('tampered\n')
                            return 2
                    trial.write_json(prefix.with_suffix('.json'), report(project))
                    return 0
                with mock.patch.dict(os.environ, {'SNYK_TOKEN':'synthetic-test-token'}), \
                     mock.patch.object(self.policy, 'verify_revisions', return_value=hashes), \
                     mock.patch.object(trial, 'verify_snyk_resolution', return_value='1.2.3'), \
                     mock.patch.object(trial, 'python_resolver_command', return_value=root/'wrapper'), \
                     mock.patch.object(self.policy, 'run_controls', return_value=True), \
                     mock.patch.object(trial, 'capture', side_effect=capture):
                    if tamper:
                        with self.assertRaisesRegex(ValueError, 'Python mirror source or content hash mismatch'):
                            self.policy.scan(args, raw)
                        self.assertEqual(len(python_attempts), 1)
                    else:
                        self.assertTrue(self.policy.scan(args, raw))
                        self.assertEqual(len(python_attempts), 2)

    def test_historical_python_defaults_bind_original_bytes_and_original_lock(self):
        trial=self.policy.trial
        sha=next(iter(trial.SOURCES))
        for version, accepted in [('46.0.5', True), ('50.0.2', False)]:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory, \
                 tempfile.TemporaryDirectory(prefix='veyport-snyk-public.', dir='/tmp') as public_directory:
                root=Path(directory); source=root/'source'; manifest=source/trial.PROJECTS[-1]
                manifest.parent.mkdir(parents=True); manifest.write_text('boto3==1.40.72\ncryptography=='+version+'\n')
                if accepted:
                    binding=trial.create_python_mirror(Path(public_directory), source, sha)
                    self.assertEqual(trial.verify_python_mirror(Path(public_directory), source, sha, binding), binding)
                else:
                    with self.assertRaises(ValueError): trial.create_python_mirror(Path(public_directory), source, sha)
                args=SimpleNamespace(source=source, control=root/'control', public_root=Path(public_directory))
                commands=trial.dependency_commands(args, projects=(trial.PROJECTS[-1],))
                install=commands[2][0]
                self.assertEqual([install[i+1] for i,item in enumerate(install) if item=='-r'],
                    [args.control/'scripts/diagnostics/snyk_runner_trial_requirements.lock', manifest])

    def test_inventory_and_canonical_source_bound_to_git_bytes(self):
        for change in ['none', 'missing_e2e', 'extra', 'symlink', 'drift', 'go', 'python', 'npmrc', 'toolchain', 'generated-link']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); sha = self.make_source(root)
                if change == 'missing_e2e': (root / 'tests/e2e/package.json').unlink()
                elif change == 'extra': (root / 'pyproject.toml').write_text('')
                elif change == 'symlink':
                    path = root / 'web/package.json'; path.unlink(); path.symlink_to('/dev/null')
                elif change == 'drift': (root / 'web/package.json').write_text('{"changed":true}')
                elif change == 'go': (root / 'hub/go.mod').write_text('module x\ngo 1.99\n')
                elif change == 'python': (root / self.policy.PROJECTS[-1]).write_text('unsafe\n')
                elif change == 'npmrc': (root / '.npmrc').write_text('onload-script=unsafe\n')
                elif change == 'generated-link': (root/'web/node_modules').symlink_to('/tmp', target_is_directory=True)
                elif change == 'toolchain': (root / 'hub/go.mod').write_text('module x\ngo 1.26.11\ntoolchain go1.99\n')
                if change == 'none': self.assertEqual(set(self.policy.validate_source(root, sha)), set(self.policy.MANIFESTS))
                else:
                    with self.assertRaises(ValueError): self.policy.validate_source(root, sha)

    def test_untrusted_paths_and_external_replacements_rejected_even_when_committed(self):
        for name, content in [('hub/go.mod', 'module x\ngo 1.26.11\nreplace x => /tmp\n'),
                              ('web/package.json', '{"dependencies":{"x":"file:/tmp"}}'),
                              ('web/package-lock.json', '{"lockfileVersion":3,"packages":{"node_modules/x":{"resolved":"git+https://example.invalid/x"}}}'),
                              ('.npmrc', 'registry=https://example.invalid'),
                              ('web/package.json', '{"engines":{"node":">=99"}}'),
                              ('.nvmrc', '99')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.make_source(root)
                (root / name).write_text(content)
                subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(root), '-c', 'user.name=Synthetic', '-c',
                                'user.email=synthetic@example.invalid', 'commit', '-qm', 'change'], check=True)
                with self.assertRaises(ValueError): self.policy.validate_source(root, self.policy.trial.revision(root))

    def test_go_replacement_scope_covers_quoted_escaped_and_block_forms(self):
        cases = [
            ('replace example.com/x => ../agent', True),
            ('replace example.com/x => ../agent // quoted text: "../../outside"', True),
            ('replace (\n example.com/x => ../agent\n)', True),
            ('replace example.com/x => example.com/replacement v1.2.3', True),
            ('replace example.com/x => ../../outside', False),
            ('replace example.com/x => /tmp', False),
            ('replace example.com/x => "../../outside"', False),
            (r'replace example.com/x => "\x2e\x2e/\x2e\x2e/outside"', False),
            ('replace (\n example.com/x => ../../outside\n)', False),
            ('replace (\n example.com/x => "../../outside"\n)', False),
            (r'replace (' + '\n' + r' example.com/x => "\x2e\x2e/\x2e\x2e/outside"' + '\n)', False),
            ('replace example.com/x => "../agent"', False),
        ]
        for directive, accepted in cases:
            with self.subTest(directive=directive), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                self.make_source(source)
                (source / 'hub/go.mod').write_text('module example.test/module\n\ngo 1.26.11\n\n' + directive + '\n')
                subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(source), '-c', 'user.name=Synthetic', '-c',
                                'user.email=synthetic@example.invalid', 'commit', '-qm', 'replacement fixture'], check=True)
                sha = self.policy.trial.revision(source)
                if accepted:
                    self.assertEqual(set(self.policy.validate_source(source, sha)), set(self.policy.MANIFESTS))
                else:
                    with self.assertRaises(ValueError): self.policy.validate_source(source, sha)

    def test_committed_unsupported_common_ecosystem_inputs_are_rejected(self):
        names = ['deno.json', 'deno.jsonc', 'deno.lock', 'pubspec.yaml', 'pubspec.lock',
                 'mix.exs', 'mix.lock', 'Package.swift', 'Package.resolved', 'packages.config',
                 'Directory.Packages.props', 'conanfile.py', 'vcpkg.json', 'build.sbt',
                 'deps.edn', 'Gopkg.toml', 'gradle.lockfile', 'renv.lock', 'stack.yaml', 'example.cabal']
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                self.make_source(source)
                manifest = source / 'additional-project' / name
                manifest.parent.mkdir()
                manifest.write_text('{}\n')
                subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(source), '-c', 'user.name=Synthetic', '-c',
                                'user.email=synthetic@example.invalid', 'commit', '-qm', 'unsupported manifest fixture'], check=True)
                with self.assertRaisesRegex(ValueError, 'unsupported dependency manifest'):
                    self.policy.validate_source(source, self.policy.trial.revision(source))

    def test_missing_credentials_prevents_scanner(self):
        args = SimpleNamespace()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(self.policy.trial, 'scan_projects',
                side_effect=AssertionError('scanner started')):
            with self.assertRaises(ValueError): self.policy.scan(args, Path('/unneeded'))

    def test_prepare_records_eight_targets_and_has_private_version_workspace(self):
        for failure in [None, 'dependency', 'version', 'drift']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, \
                 tempfile.TemporaryDirectory(prefix='veyport-snyk-public.', dir='/tmp') as public_directory:
                root=Path(directory); source=root/'source'; source.mkdir(); sha=self.make_source(source)
                control=root/'controller'; lock=control/'scripts/security/snyk_policy_requirements.lock'
                lock.parent.mkdir(parents=True); lock.write_text('synthetic trusted lock')
                raw=root/'raw'; raw.mkdir(mode=0o700)
                args=SimpleNamespace(root=root, source=source, control=control, sha=sha, control_sha='b'*40,
                                     scanner=root/'scanner', public_root=Path(public_directory))
                args.scanner.write_text('synthetic scanner bytes')
                hashes=self.policy.validate_source(source, sha)
                versions={'snyk':'1.2.3', 'go':'go version go1.26.11 linux/amd64', 'node':'v25.2.0',
                          'npm':'11.6.2', 'python':'Python 3.12.13', 'age':'v1.2.1'}
                seen=[]
                def capture(command, cwd, prefix, timeout, env=None):
                    seen.append(command)
                    if prefix.name.startswith('version-'):
                        private=Path(env['SNYK_TMP_PATH'])
                        self.assertTrue(private.is_dir(), 'version subprocess requires private temporary directory')
                        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
                        name=prefix.name.removeprefix('version-')
                        prefix.with_suffix('.stdout').write_text('unsupported' if failure=='version' and name=='go' else versions[name])
                    return 1 if failure=='dependency' and prefix.name=='prepare-0' else 0
                with mock.patch.dict(os.environ, {}, clear=True), \
                     mock.patch.object(self.policy, 'verify_revisions', side_effect=[hashes, {} if failure=='drift' else hashes]), \
                     mock.patch.object(self.policy.trial, 'verify_snyk_resolution', return_value='1.2.3'), \
                     mock.patch.object(self.policy.trial, 'resolver_permissions'), \
                     mock.patch.object(self.policy.trial, 'capture', side_effect=capture):
                    self.assertEqual(self.policy.prepare(args, raw), failure is None)
                state=self.policy.trial.load_report(raw/'state.json')
                self.assertEqual(state['source_sha'], sha)
                self.assertEqual(state['python_lock'], {'path':'scripts/security/snyk_policy_requirements.lock',
                    'sha256':self.policy.file_digest(lock)})
                install=next(cmd for cmd in seen if '--require-hashes' in cmd)
                self.assertEqual([install[i+1] for i,item in enumerate(install) if item=='-r'],
                    [lock, source/'infra/audit-lab/storage/requirements.txt'])
                self.assertEqual(state['preparation_complete'], failure is None)
                npm=[command for command in seen if command[:2]==['npm', 'ci']]
                self.assertEqual(len(npm), 2)

    def test_scan_rechecks_manifests_and_bootstrap_before_any_invocation(self):
        for failure in ['manifest', 'bootstrap']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); raw = root / 'raw'; raw.mkdir()
                args = SimpleNamespace(root=root, source=root/'source', control=root/'controller',
                    sha='a'*40, control_sha='b'*40, scanner=root/'scanner', public_root=root/'public')
                hashes = {'manifest': 'expected'}
                state = {'source_sha': args.sha, 'control_sha': args.control_sha,
                    'preparation_complete': True, 'manifest_hashes': hashes, 'versions': {'snyk': '1.2.3'}}
                self.policy.trial.write_json(raw/'state.json', state)
                with mock.patch.dict(os.environ, {'SNYK_TOKEN': 'synthetic-test-token'}), \
                     mock.patch.object(self.policy, 'verify_revisions', return_value={} if failure == 'manifest' else hashes), \
                     mock.patch.object(self.policy.trial, 'verify_python_mirror'), \
                     mock.patch.object(self.policy.trial, 'verify_snyk_resolution', side_effect=ValueError('stale')), \
                     mock.patch.object(self.policy.trial, 'scan_projects', side_effect=AssertionError('scanner started')):
                    with self.assertRaises(ValueError): self.policy.scan(args, raw)

    def test_shared_runner_scans_eight_with_ignore_policy_and_dev_flags(self):
        trial = self.policy.trial
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); raw=root/'raw'; raw.mkdir()
            observed=[]
            def scanner(command, cwd, prefix, timeout, env=None):
                project = self.policy.PROJECTS[len(observed)]
                observed.append((command, cwd))
                output = Path(next(arg.split('=', 1)[1] for arg in command if str(arg).startswith('--json-file-output=')))
                value=report(project); trial.write_json(output, value)
                return 0
            recheck=mock.Mock()
            with mock.patch.object(trial, 'python_resolver_command', return_value=root/'wrapper'), \
                 mock.patch.object(trial, 'verify_python_mirror_files'), mock.patch.object(trial, 'capture', side_effect=scanner):
                rows=trial.scan_projects(root/'source', root/'scanner', raw, root/'python', root/'public',
                    projects=self.policy.PROJECTS, assessor=self.policy.assess, ignore_policy=True, verify_source=recheck,
                    attempt_binding='f'*64)
            self.assertEqual([row['path'] for row in rows], list(self.policy.PROJECTS))
            self.assertEqual(recheck.call_count, 8)
            for index, row in enumerate(rows):
                assessed=self.policy.application_report(raw, index, row['path'], row['attempts'], 'f'*64)
                self.assertTrue(assessed['technically_complete'])
                self.assertEqual(row['attempts'][0]['report_sha256'],
                                 self.policy.file_digest(raw/f'project-{index}-attempt-1.json'))
            for command, cwd in observed:
                self.assertIn('--ignore-policy', command)
                if '--file=package.json' in command: self.assertIn('--dev', command)

    def test_source_scripts_never_executed_during_preflight_or_command_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); sha=self.make_source(root)
            script=root/'web/hostile.py'; script.write_text('raise RuntimeError("executed")')
            args=SimpleNamespace(source=root, control=root/'unused', public_root=root/'public')
            self.policy.validate_source(root, sha)
            commands=self.policy.trial.dependency_commands(args, projects=self.policy.PROJECTS)
            npm=[cmd for cmd, cwd in commands if cmd[0]=='npm']
            self.assertEqual(len(npm), 2)
            self.assertTrue(all('--ignore-scripts' in cmd for cmd in npm))
            self.assertFalse(any(str(script) in list(map(str, cmd)) for cmd,cwd in commands))

    def test_encryption_failure_never_publishes_plaintext_or_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); raw=root/'raw'; raw.mkdir()
            (raw/'private.txt').write_text('SENTINEL')
            args=SimpleNamespace(root=root, sha='a'*40, control_sha='b'*40)
            (root/'public').mkdir(); (root/'public/summary.json').write_text('STALE')
            with mock.patch.object(self.policy.trial, 'capture', return_value=1):
                with self.assertRaises(ValueError): self.policy.seal(args, raw)
            self.assertTrue((raw/'private.txt').exists())
            self.assertFalse((root/'public/evidence.tar.gz.age').exists())
            self.assertFalse((root/'public/summary.json').exists())

    def test_successful_seal_uses_age_and_only_public_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); raw=root/'raw'; raw.mkdir()
            (raw/'private.txt').write_text('SENTINEL')
            args=SimpleNamespace(root=root, sha='a'*40, control_sha='b'*40)
            def encrypt(command, cwd, prefix, timeout):
                self.assertEqual(command[:3], ['age', '-r', self.policy.trial.RECIPIENT])
                Path(command[4]).write_bytes(b'SYNTHETIC-CIPHERTEXT')
                return 0
            with mock.patch.object(self.policy.trial, 'capture', side_effect=encrypt): self.policy.seal(args, raw)
            self.assertFalse(raw.exists())
            self.assertFalse((root/'evidence.tar.gz').exists())
            self.assertNotIn('SENTINEL', (root/'public/summary.json').read_text())

    def test_cli_cleanup_attempts_plaintext_removal_after_public_scope_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'raw').mkdir(); (root/'raw/private').write_text('SENTINEL')
            for name in ['home', 'config', 'cache', 'license-control']:
                (root/name).mkdir(); (root/name/'private').write_text('SENTINEL')
            (root/'run-identity.json').write_text('SENTINEL')
            unsafe=root/'unsafe'; unsafe.mkdir()
            command=[os.sys.executable, '-I', '-B', str(POLICY_PATH), 'cleanup', '--source', str(root/'source'),
                '--control', str(root/'control'), '--sha', 'a'*40, '--control-sha', 'b'*40,
                '--root', str(root), '--scanner', str(root/'scanner'), '--public-root', str(unsafe)]
            result=subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse((root/'raw').exists())
            self.assertTrue(unsafe.exists())
            for name in ['home', 'config', 'cache', 'license-control']: self.assertFalse((root/name).exists())
            self.assertNotIn('SENTINEL', result.stdout+result.stderr)

    def test_workflows_restrict_launch_credentials_and_cleanup(self):
        for name, workflow in workflows():
            diagnostic = name == 'snyk-policy-qualification.yml'
            event, ref = ('push', 'diagnostic/snyk-policy-qualification') if diagnostic else ('workflow_dispatch', 'main')
            with self.subTest(workflow=name):
                triggers = workflow.split('on:\n', 1)[1].split('\npermissions:', 1)[0]
                self.assertEqual(re.findall(r'^  ([a-z_]+):', triggers, re.M), [event])
                if diagnostic:
                    self.assertEqual(re.search(r'branches: \[(.*)\]', triggers)[1], ref)
                self.assertNotIn('pull_request', workflow)
                self.assertNotIn('continue-on-error', workflow)
                self.assertIn('go-version: 1.26.11', workflow)
                self.assertNotIn('go-version-file:', workflow)
                permissions = re.findall(r'^ *permissions:\n((?: +[^\n]+\n)+)', workflow, re.M)
                self.assertEqual(workflow.count('permissions:'), 1)
                self.assertEqual([block.strip() for block in permissions], ['contents: read'])
                guard = re.search(r'^    if: (.*)$', workflow, re.M)[1]
                self.assertRegex(guard, r"^github\.[a-z_]+ == '[^']+'(?: && github\.[a-z_]+ == '[^']+')*$")
                shell = re.sub(r'github\.([a-z_]+)', lambda m: '"$GH_' + m[1].upper() + '"', guard)
                good = dict(event_name=event, repository='lorconksu/veyport', repository_owner_id='13374789',
                            actor_id='13374789', actor='lorconksu', triggering_actor='lorconksu', ref='refs/heads/'+ref)
                def allowed(context):
                    env = {'GH_'+key.upper(): value for key, value in context.items()}
                    return subprocess.run(['/bin/bash', '-c', '[[ '+shell+' ]]'], env=env,
                                          capture_output=True).returncode == 0
                self.assertTrue(allowed(good))
                for key in good:
                    for bad in ['', 'other', '0']:
                        with self.subTest(boundary=key, value=bad):
                            self.assertFalse(allowed(dict(good, **{key: bad})))
                for bad in ['pull_request', 'pull_request_target', 'workflow_run',
                            'workflow_dispatch' if diagnostic else 'push']:
                    self.assertFalse(allowed(dict(good, event_name=bad)))
                self.assertFalse(allowed(dict(good, ref='refs/heads/'+ref+'-other')))
                steps = workflow.split('\n      - ')[1:]
                token_steps = [step for step in steps if 'secrets.' in step]
                self.assertEqual(len(token_steps), 1)
                self.assertIn('id: scan\n', token_steps[0])
                self.assertEqual(workflow.count('secrets.SNYK_TOKEN'), 1)
                self.assertEqual(workflow.count('secrets.'), 1)
                checkouts = [step for step in steps if 'uses: actions/checkout@' in step]
                self.assertEqual(len(checkouts), 2)
                for checkout in checkouts:
                    self.assertIn('persist-credentials: false', checkout)
                    self.assertIn('repository: lorconksu/veyport', checkout)
                cleanup = next(step for step in steps if 'id: cleanup\n' in step)
                self.assertIn('if: always()', cleanup)
                self.assertLess(steps.index(cleanup), len(steps)-1)
                self.assertIn('if: always()', steps[-1])
                self.assertIn('steps.encrypt.outputs.sealed_policy_exit', steps[-1])
                for step in ['scan', 'policy', 'encrypt', 'upload', 'cleanup']:
                    self.assertIn(step.upper()+'_OUTCOME: ${{ steps.'+step+'.outcome }}', steps[-1])

    def test_initializers_export_private_npm_configs_that_real_npm_loads(self):
        npm = shutil.which('npm')
        for name, workflow in workflows():
            with self.subTest(workflow=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); output = root/'github-env'; output.touch()
                env = {'PATH': os.environ.get('PATH', os.defpath), 'RUNNER_TEMP': str(root),
                       'HOME': str(root/'initial-home'), 'GITHUB_ENV': str(output),
                       'SOURCE_SHA': 'a'*40, 'CONTROL_SHA': 'b'*40}
                job_env = workflow.split('    env:\n', 1)[1].split('    steps:', 1)[0]
                for key, value in re.findall(r'^      ([A-Z_]+): (.+)$', job_env, re.M):
                    if '${{' not in value: env[key] = value.strip("'")
                initializer = textwrap.dedent(workflow.split('run: |', 1)[1].split('\n      - ', 1)[0])
                self.assertLess(workflow.index('run: |'), workflow.index('uses: actions/setup-node@'))
                for key in ['SOURCE_SHA', 'CONTROL_SHA']:
                    invalid = subprocess.run(['/bin/bash', '-c', initializer], env=dict(env, **{key: 'bad-sha'}),
                                             cwd=root, capture_output=True)
                    self.assertNotEqual(invalid.returncode, 0)
                    self.assertEqual(output.read_bytes(), b'')
                result = subprocess.run(['/bin/bash', '-c', initializer], env=env, cwd=root, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                env.update(line.split('=', 1) for line in output.read_text().splitlines())
                self.addCleanup(shutil.rmtree, env['PUBLIC_PYTHON_ROOT'], ignore_errors=True)
                private = Path(env['TRIAL_ROOT']); user = Path(env['NPM_CONFIG_USERCONFIG']); global_ = Path(env['NPM_CONFIG_GLOBALCONFIG'])
                self.assertNotEqual(user, global_)
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
                for config in [user, global_]:
                    self.assertEqual(config.parent, private/'config')
                    self.assertEqual(config.read_bytes(), b'')
                    self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
                self.assertEqual(env['HOME'], str(private/'home'))
                self.assertEqual(env['NPM_CONFIG_CACHE'], str(private/'cache/npm'))
                self.assertEqual(env['NPM_CONFIG_IGNORE_SCRIPTS'], 'true')
                if not npm:
                    with self.subTest(real_npm='unavailable'):
                        self.skipTest('npm absent: initializer checks passed; real loader subcheck unavailable')
                    continue
                if npm:
                    for key, expected in [('userconfig', str(user)), ('globalconfig', str(global_)),
                                          ('cache', str(private/'cache/npm')), ('ignore-scripts', 'true')]:
                        loaded = subprocess.run([npm, 'config', 'get', key], env=env, cwd=root,
                                                capture_output=True, text=True, timeout=30)
                        self.assertEqual(loaded.returncode, 0, loaded.stderr)
                        self.assertEqual(loaded.stdout.strip(), expected)



# Control reports use public metadata; application findings above remain synthetic.
def control_report():
    return {'ok': False, 'dependencyCount': 3, 'vulnerabilities': [
        issue('high', 'license', name='meld-spec', version='0.4.2', license='Unknown',
              id='snyk:lic:npm:meld-spec:Unknown', severityWithCritical='high'),
        issue('high', 'license', name='languages', version='0.1.3', license='GPL-3.0',
              id='snyk:lic:npm:languages:GPL-3.0', severityWithCritical='high')],
        'licensesPolicy': {'orgLicenseRules': None, 'severities': None},
        'filtered': {'ignore': [], 'patch': []}, 'hasUnknownVersions': False,
        'targetFile': '', 'displayTargetFile': 'package-lock.json',
        'packageManager': 'npm', 'org': 'lorconksu'}


class LicenseControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PolicyTests.setUpClass()
        cls.policy = PolicyTests.policy

    def context(self, root):
        os.environ['SNYK_TOKEN'] = 'synthetic-control-test-token'
        raw = root / 'raw'; raw.mkdir()
        scanner = root / 'tools/snyk'; scanner.parent.mkdir(); scanner.write_text('synthetic verified scanner')
        import hashlib
        digest = hashlib.sha256(scanner.read_bytes()).hexdigest()
        self.policy.trial.write_json(raw / 'snyk-cli.json', {'verified': True, 'version': '1.1308.4',
            'url': 'https://downloads.snyk.io/cli/v1.1308.4/snyk-linux',
            'expected_sha256': digest, 'actual_sha256': digest})
        args = SimpleNamespace(root=root, source=root/'source', control=POLICY_PATH.parents[2],
            scanner=scanner, sha='a'*40, control_sha='b'*40, public_root=root/'unused')
        state = {'source_sha': args.sha, 'control_sha': args.control_sha, 'preparation_complete': True,
            'manifests_unchanged': True, 'manifest_hashes': {'fixture': 'unchanged'}, 'projects': [],
            'python_lock': {'path':'scripts/security/snyk_policy_requirements.lock',
                'sha256':self.policy.file_digest(args.control/'scripts/security/snyk_policy_requirements.lock')},
            'versions': {'snyk': '1.1308.4', 'go': 'go1.26.11', 'node': 'v25.2.0',
                         'npm': '11.6.2', 'python': 'Python 3.12.13', 'age': 'v1.2.1'}}
        self.policy.initialize_controls(args, raw, state)
        self.policy.trial.write_json(raw/'state.json', state)
        return args, raw, state

    def captured(self, value=None, code=1, observed=None):
        def capture(command, cwd, prefix, timeout, env=None):
            output = Path(next(str(arg).split('=', 1)[1] for arg in command if str(arg).startswith('--json-file-output=')))
            self.assertFalse(output.exists(), 'stale control output must be removed before launch')
            if observed is not None: observed.append((command, cwd, timeout))
            if value is not None: self.policy.trial.write_json(output, value)
            return code
        return capture

    def complete(self, args, raw, state, issues=None):
        with mock.patch.object(self.policy.trial, 'capture', side_effect=self.captured(control_report())):
            self.assertTrue(self.policy.run_controls(args, raw, state))
        state['projects'] = []
        for index, project in enumerate(self.policy.PROJECTS):
            findings = issues if index == 0 else None
            value = report(project, findings)
            self.policy.trial.write_json(raw/f'project-{index}-attempt-1.json', value)
            state['projects'].append({'path': project, 'attempts': [{
                'exit_code': 1 if findings else 0, 'status': self.policy.assess(value, 1 if findings else 0, project)['status'],
                'attempt': 1, 'project': project, 'run_identity_sha256': state['run_identity_sha256'],
                'report_sha256': self.policy.file_digest(raw/f'project-{index}-attempt-1.json')}]})
        self.policy.trial.write_json(raw/'state.json', state)

    def test_exact_controls_accept_and_downgrades_duplicates_substitutions_fail(self):
        self.assertTrue(self.policy.assess_controls(control_report(), 1))
        changes = [lambda r: r.update(dependencyCount=0), lambda r: r.update(dependencyCount=4),
            lambda r: r.update(org='wrong'), lambda r: r.update(ok=True),
            lambda r: r.update(displayTargetFile='package.json'),
            lambda r: r['vulnerabilities'].pop(),
            lambda r: r['vulnerabilities'].append(copy.deepcopy(r['vulnerabilities'][0])),
            lambda r: r['vulnerabilities'][0].update(severity='medium'),
            lambda r: r['vulnerabilities'][0].update(severityWithCritical='medium'),
            lambda r: r['vulnerabilities'][0].update(name='substitute'),
            lambda r: r['vulnerabilities'][0].update(version='0.4.3'),
            lambda r: r['vulnerabilities'][0].update(id='substitute'),
            lambda r: r['vulnerabilities'][0].update(license='GPL-3.0'),
            lambda r: r['vulnerabilities'][0].update(type='vuln'),
            lambda r: r['vulnerabilities'].append(issue('critical'))]
        for change in changes:
            value = control_report(); change(value)
            with self.subTest(value=value): self.assertFalse(self.policy.assess_controls(value, 1))
        self.assertFalse(self.policy.assess_controls(control_report(), 0))

    def test_control_command_uses_lockfile_no_install_and_rechecks_binary(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            args, raw, state = self.context(Path(directory)); observed=[]
            # A stale prior output must not become this run's evidence.
            (raw/'license-control-attempt-1.json').write_text('stale')
            with mock.patch.object(self.policy.trial, 'capture', side_effect=self.captured(control_report(), observed=observed)):
                self.assertTrue(self.policy.run_controls(args, raw, state))
            command, cwd, timeout = observed[0]
            for flag in ['test', '--file=package-lock.json', '--ignore-policy', '--org='+self.policy.trial.ORG]:
                self.assertIn(flag, command)
            self.assertNotIn('install', command)
            self.assertLessEqual(timeout, 300)
            self.assertEqual(cwd, args.root/'license-control')
            args.scanner.write_text('tampered')
            with mock.patch.object(self.policy.trial, 'capture', side_effect=AssertionError('scanner launched')):
                with self.assertRaises(ValueError): self.policy.run_controls(args, raw, state)

    def test_policy_negative_control_not_retried_but_processing_failure_bounded(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            args, raw, state = self.context(Path(directory))
            value=control_report(); value['vulnerabilities'][0]['severity']='medium'
            with mock.patch.object(self.policy.trial, 'capture', side_effect=self.captured(value)) as capture:
                self.assertFalse(self.policy.run_controls(args, raw, state)); self.assertEqual(capture.call_count, 1)
            callbacks = [self.captured(None, 124), self.captured(control_report())]
            def processing(*a, **kw): return callbacks.pop(0)(*a, **kw)
            with mock.patch.object(self.policy.trial, 'capture', side_effect=processing) as capture:
                self.assertTrue(self.policy.run_controls(args, raw, state)); self.assertEqual(capture.call_count, 2)

    def test_fixture_bytes_and_canonical_materialized_paths_are_bound(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            args, raw, state = self.context(Path(directory))
            data=self.policy.load_control_fixture()
            self.assertEqual(set(data), {'package.json', 'package-lock.json'})
            path=args.root/'license-control/package-lock.json'; path.chmod(0o600); path.write_text('{}')
            with mock.patch.object(self.policy.trial, 'capture', side_effect=AssertionError('scanner launched')):
                with self.assertRaises(ValueError): self.policy.run_controls(args, raw, state)
            path.unlink(); path.symlink_to(args.scanner)
            with self.assertRaises(ValueError): self.policy.verify_control_workspace(args)
            fixture=Path(directory)/'untrusted.json'; fixture.write_text('{"files":{}}')
            with mock.patch.object(self.policy, 'CANARY_FIXTURE', fixture):
                with self.assertRaises(ValueError): self.policy.load_control_fixture()

    def test_verified_eight_project_policy_exit_contract(self):
        for findings, expected in [(None, 0), ([issue()], 1), ([issue('critical')], 1),
                                   ([issue('medium', 'license')], 0), ([issue('high', 'license')], 1),
                                   ([issue('medium', 'license', license='Unknown')], 1),
                                   ([issue('low', 'license', license='GPL-3.0')], 1)]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {}, clear=True):
                args, raw, state=self.context(Path(directory)); self.complete(args, raw, state, findings)
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                    self.assertEqual(self.policy.evaluate(args, raw), expected)
                    (raw/'project-7-attempt-1.json').unlink()
                    self.assertEqual(self.policy.evaluate(args, raw), 2)

    def test_missing_tampered_replayed_or_wrong_run_control_evidence_incomplete(self):
        for change in ['missing', 'raw', 'metadata', 'source', 'policy', 'fixture', 'nonce', 'scanner', 'run', 'cached-pass']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {'GITHUB_RUN_ID':'123', 'GITHUB_RUN_ATTEMPT':'1', 'GITHUB_JOB':'policy'}, clear=True):
                args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
                if change=='missing': (raw/'license-controls.json').unlink()
                elif change=='raw': (raw/'license-control-attempt-1.json').write_text('{}')
                elif change=='metadata':
                    value=self.policy.trial.load_report(raw/'license-controls.json'); value['attempts'][-1]['exit_code']=0
                    self.policy.trial.write_json(raw/'license-controls.json', value)
                elif change=='source': args.sha='c'*40
                elif change=='scanner': args.scanner.write_text('tampered')
                elif change=='run': os.environ['GITHUB_RUN_ATTEMPT']='2'
                elif change=='cached-pass':
                    (raw/'license-controls.json').unlink(); state['license_controls_verified']=True
                    self.policy.trial.write_json(raw/'state.json', state)
                else:
                    identity=self.policy.trial.load_report(args.root/'run-identity.json')
                    identity[{'policy':'policy_sha256', 'fixture':'fixture_sha256', 'nonce':'nonce'}[change]]='0'*64
                    self.policy.trial.write_json(args.root/'run-identity.json', identity)
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                    self.assertEqual(self.policy.evaluate(args, raw), 2)

    def test_evaluation_rereads_application_and_controls_without_cached_pass(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
            with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                self.assertEqual(self.policy.evaluate(args, raw), 0)
                self.policy.trial.write_json(raw/'project-0-attempt-1.json', report(issues=[issue()]))
                state['projects'][0]['attempts'][0]['exit_code']=1; self.policy.trial.write_json(raw/'state.json',state)
                self.assertEqual(self.policy.evaluate(args, raw), 2)
                (raw/'license-control-attempt-1.json').write_text('{}')
                self.assertEqual(self.policy.evaluate(args, raw), 2)

    def test_application_attempt_binding_missing_malformed_or_tampered_is_incomplete(self):
        for failure in ['missing-hash', 'bad-hash', 'changed-bytes', 'bad-attempt', 'wrong-project',
                        'wrong-run', 'missing-run', 'bad-status']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {}, clear=True):
                args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
                attempt=state['projects'][0]['attempts'][0]
                if failure=='missing-hash': attempt.pop('report_sha256')
                elif failure=='bad-hash': attempt['report_sha256']='0'*64
                elif failure=='changed-bytes':
                    value=report(); value['dependencyCount']=99
                    self.policy.trial.write_json(raw/'project-0-attempt-1.json', value)
                elif failure=='bad-attempt': attempt['attempt']=2
                elif failure=='wrong-project': attempt['project']='agent/go.mod'
                elif failure=='wrong-run': attempt['run_identity_sha256']='0'*64
                elif failure=='missing-run': attempt.pop('run_identity_sha256')
                elif failure=='bad-status': attempt['status']='scan_incomplete'
                self.policy.trial.write_json(raw/'state.json', state)
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                    self.assertEqual(self.policy.evaluate(args, raw), 2)

    def test_scan_and_evaluation_reject_wrong_candidate_lock_provenance(self):
        for change in ['old-lock', 'wrong-digest', 'missing']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {}, clear=True):
                args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
                if change=='old-lock': state['python_lock']['path']='scripts/diagnostics/snyk_runner_trial_requirements.lock'
                elif change=='wrong-digest': state['python_lock']['sha256']='0'*64
                else: state.pop('python_lock')
                self.policy.trial.write_json(raw/'state.json', state)
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']), \
                     mock.patch.object(self.policy.trial, 'verify_python_mirror'), \
                     mock.patch.object(self.policy, 'run_controls', side_effect=AssertionError('controls started')):
                    with self.assertRaisesRegex(ValueError, 'Python lock preparation binding mismatch'):
                        self.policy.scan(args, raw)
                    self.assertEqual(self.policy.evaluate(args, raw), 2)

    def test_scan_controls_precede_apps_and_negative_controls_stop_apps(self):
        for verified in (True, False):
            with self.subTest(verified=verified), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {}, clear=True):
                args, raw, state=self.context(Path(directory)); events=[]
                value=control_report()
                if not verified: value['vulnerabilities'][0]['severity']='medium'
                capture_control=self.captured(value)
                def capture(*a, **kw):
                    events.append('controls'); return capture_control(*a, **kw)
                def apps(*a, **kw):
                    events.append('applications')
                    return [{'path':p, **self.policy.assess(report(p), 0, p)} for p in self.policy.PROJECTS]
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']), \
                     mock.patch.object(self.policy.trial, 'verify_python_mirror'), \
                     mock.patch.object(self.policy.trial, 'capture', side_effect=capture), \
                     mock.patch.object(self.policy.trial, 'scan_projects', side_effect=apps):
                    self.assertEqual(self.policy.scan(args, raw), verified)
                self.assertEqual(events, ['controls', 'applications'] if verified else ['controls'])
                os.environ.pop('SNYK_TOKEN')
                with self.assertRaises(ValueError): self.policy.run_controls(args, raw, state)

    def test_replayed_control_record_fails_new_nonce_and_controls_expire(self):
        import shutil
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second, \
             mock.patch.dict(os.environ, {}, clear=True):
            old_args, old_raw, old_state=self.context(Path(first)); self.complete(old_args, old_raw, old_state)
            args, raw, state=self.context(Path(second))
            for name in ['license-controls.json', 'license-control-attempt-1.json']:
                shutil.copyfile(old_raw/name, raw/name)
            state['license_control_record_sha256']=old_state['license_control_record_sha256']
            self.assertEqual(self.policy.verify_controls(args, raw, state)['status'], 'incomplete')
            self.assertEqual(self.policy.verify_controls(old_args, old_raw, old_state)['status'], 'verified')
            import time
            with mock.patch.object(self.policy.time, 'time_ns', return_value=time.time_ns()+self.policy.MAX_CONTROL_AGE_NS+1):
                self.assertEqual(self.policy.verify_controls(old_args, old_raw, old_state)['status'], 'incomplete')

    def test_missing_duplicate_wrong_org_or_invalid_preparation_is_incomplete(self):
        for failure in ['missing', 'duplicate', 'wrong-org', 'versions']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {}, clear=True):
                args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
                if failure=='missing': state['projects'].pop()
                elif failure=='duplicate': state['projects'][-1]=copy.deepcopy(state['projects'][0])
                elif failure=='versions': state['versions']['go']='unsupported'
                else:
                    value=report(); value['org']='wrong'
                    self.policy.trial.write_json(raw/'project-0-attempt-1.json', value)
                self.policy.trial.write_json(raw/'state.json', state)
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                    self.assertEqual(self.policy.evaluate(args, raw), 2)

    def test_seal_exports_actual_fresh_verdict_without_hiding_failure_evidence(self):
        for findings, expected in [(None, 0), ([issue()], 1)]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {}, clear=True):
                args, raw, state=self.context(Path(directory)); self.complete(args, raw, state, findings)
                output=args.root/'step-output'; output.touch(); os.environ['GITHUB_OUTPUT']=str(output)
                def encrypt(command, cwd, prefix, timeout):
                    Path(command[4]).write_bytes(b'SYNTHETIC-CIPHERTEXT'); return 0
                with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']), \
                     mock.patch.object(self.policy.trial, 'capture', side_effect=encrypt):
                    self.policy.seal(args, raw)
                exported=dict(line.split('=',1) for line in output.read_text().splitlines())
                self.assertEqual(exported.get('sealed_policy_exit'), str(expected))
                self.assertTrue((args.root/'public/evidence.tar.gz.age').exists())
                summary=json.loads((args.root/'public/summary.json').read_text())
                self.assertEqual(summary['policy']['exit_code'], expected)
                environment={key.upper()+'_OUTCOME':'success' for key in ['scan','policy','encrypt','upload','cleanup']}
                environment['SEALED_POLICY_EXIT']=exported.get('sealed_policy_exit','')
                for name, workflow in workflows():
                    with self.subTest(workflow=name):
                        status=subprocess.run(['/bin/bash','-c',final_gate(workflow)],env=environment,capture_output=True).returncode
                        self.assertEqual(status==0, expected==0)
                        self.assertIn("if: always() && steps.encrypt.outcome == 'success'", workflow)

    def test_changed_bound_evidence_after_policy_success_cannot_finish_green(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
            output=args.root/'step-output'; output.write_text('sealed_policy_exit=0\n')
            os.environ['GITHUB_OUTPUT']=str(output)
            def encrypt(command, cwd, prefix, timeout):
                Path(command[4]).write_bytes(b'SYNTHETIC-CIPHERTEXT'); return 0
            with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                self.assertEqual(self.policy.evaluate(args, raw), 0)
                changed=report(); changed['dependencyCount']=99
                self.policy.trial.write_json(raw/'project-0-attempt-1.json',changed)
                with mock.patch.object(self.policy.trial, 'capture', side_effect=encrypt):
                    self.policy.seal(args,raw)
            exported=dict(line.split('=',1) for line in output.read_text().splitlines())
            self.assertEqual(exported.get('sealed_policy_exit'),'2')
            self.assertTrue((args.root/'public/evidence.tar.gz.age').exists(), 'failure evidence remains upload eligible')
            command=[os.sys.executable,'-I','-B',str(POLICY_PATH),'cleanup','--source',str(args.source),
                '--control',str(args.control),'--sha',args.sha,'--control-sha',args.control_sha,
                '--root',str(args.root),'--scanner',str(args.scanner),'--public-root',str(args.public_root)]
            cleanup=subprocess.run(command,capture_output=True)
            self.assertEqual(cleanup.returncode,0)
            self.assertFalse((args.root/'license-control').exists())
            self.assertFalse((args.root/'run-identity.json').exists())
            environment={key.upper()+'_OUTCOME':'success' for key in ['scan','policy','encrypt','upload','cleanup']}
            environment['SEALED_POLICY_EXIT']=exported.get('sealed_policy_exit','')
            for name, workflow in workflows():
                with self.subTest(workflow=name):
                    self.assertNotEqual(subprocess.run(['/bin/bash','-c',final_gate(workflow)],env=environment,capture_output=True).returncode,0)

    def test_public_summary_separates_controls_and_keeps_raw_identities_private(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            args, raw, state=self.context(Path(directory)); self.complete(args, raw, state)
            state['private']='PRIVATE_SENTINEL'
            with mock.patch.object(self.policy, 'verify_revisions', return_value=state['manifest_hashes']):
                evaluated=self.policy.evaluate_result(args, raw)
            summary=self.policy.public_summary(state, evaluated)
            self.assertEqual(summary['policy']['exit_code'], 0)
            self.assertEqual(summary['policy']['dependency_count'], 24)
            self.assertEqual(summary['policy']['blocking_license_records'], 0)
            self.assertEqual(summary['license_controls']['dependency_count'], 3)
            encoded=json.dumps(summary)
            for private in ['meld-spec', 'languages', 'snyk:lic:', 'PRIVATE_SENTINEL', str(args.root)]:
                self.assertNotIn(private, encoded)


if __name__ == '__main__': unittest.main()
