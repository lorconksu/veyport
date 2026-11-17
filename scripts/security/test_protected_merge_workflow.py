"""Offline execution of protected-workflow guards, shell, and token bindings.

Read the small workflow boundary syntax with stdlib; actionlint validates YAML.
Mutants exercise these same assertions against damaged workflow source.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from test_snyk_pr_policy import scalar, workflow_steps, shell_body, expression

WORKFLOW = Path(__file__).parents[2]/'.github/workflows/protected-merge.yml'


def jobs(text):
    return {m[1]: m[2] for m in re.finditer(
        r'^  ([a-z]+):\n(.*?)(?=^  [a-z]+:\n|\Z)', text.split('jobs:\n', 1)[1], re.M | re.S)}


class ProtectedWorkflowTests(unittest.TestCase):
    def source(self):
        self.assertTrue(WORKFLOW.exists(), 'Missing protected workflow')
        text = WORKFLOW.read_text()
        parsed = jobs(text)
        return text, parsed, {key: workflow_steps(block) for key, block in parsed.items()}

    def run_shell(self, step, env):
        return subprocess.run(['/bin/bash', '-c', shell_body(step).replace('/usr/bin/python3.12', sys.executable)],
            env={'PATH': os.defpath, **env}, text=True, capture_output=True, timeout=20)

    def test_dispatch_and_trusted_main_request_guard(self):
        text, parsed, steps = self.source()
        trigger = text.split('on:\n', 1)[1].split('\npermissions:')[0]
        self.assertEqual(re.findall(r'^  ([a-z_]+):', trigger, re.M), ['workflow_dispatch'])
        self.assertEqual(re.findall(r'^      ([a-z_]+):', trigger, re.M), ['operation', 'pr_number', 'head_sha'])
        self.assertEqual(scalar(trigger, 'default', 8), 'verify')
        self.assertEqual(set(parsed), {'admission', 'scan', 'verify', 'merge'})
        good = {'github.event_name': 'workflow_dispatch', 'github.repository': 'lorconksu/veyport',
            'github.repository_id': '1188082218', 'github.repository_owner_id': '13374789',
            'github.ref': 'refs/heads/main', 'github.actor': 'lorconksu',
            'github.actor_id': '13374789', 'github.triggering_actor': 'lorconksu',
            'github.run_attempt': '1', 'vars.PROTECTED_MERGE_ENABLED': 'true'}
        guard = scalar(parsed['admission'], 'if', 4)
        self.assertTrue(expression(guard, good))
        for key in good:
            self.assertFalse(expression(guard, {**good, key: 'other'}), key)
        self.assertEqual(scalar(parsed['admission'], 'admission_json', 6), '${{ steps.admit.outputs.admission_json }}')
        self.assertEqual(scalar(parsed['admission'], 'source_sha', 6), '${{ steps.admit.outputs.source_sha }}')
        for key in ['scan', 'verify', 'merge']:
            self.assertEqual(scalar(parsed[key], 'ADMISSION_JSON', 6), '${{ needs.admission.outputs.admission_json }}')
        self.assertEqual(scalar(parsed['scan'], 'SOURCE_SHA', 6), '${{ needs.admission.outputs.source_sha }}')

    def test_verified_strict_purpose_gates_environment_before_mint(self):
        _, parsed, steps = self.source()
        self.assertEqual(scalar(parsed['merge'], 'needs', 4), '[admission, scan, verify]')
        self.assertEqual(scalar(parsed['merge'], 'environment', 4), 'ssdf-protected-merge')
        good = {'needs.admission.result': 'success', 'needs.scan.result': 'success',
            'needs.verify.result': 'success', 'needs.verify.outputs.verified': 'true',
            'needs.verify.outputs.purpose': 'protected-merge', 'inputs.operation': 'merge'}
        guard = scalar(parsed['merge'], 'if', 4)
        self.assertTrue(expression(guard, good))
        for key in good:
            for bad in ['', 'failure', 'skipped', 'cancelled', 'verify', 'protected-merge-preview']:
                self.assertFalse(expression(guard, {**good, key: bad}), (key, bad))
        # Actions folds case: the strict helper-emitted purpose is the gate.
        self.assertFalse(expression(guard, {**good, 'inputs.operation': 'MERGE',
            'needs.verify.outputs.purpose': 'protected-merge-preview'}))
        for key in ['verified', 'purpose']:
            self.assertEqual(scalar(parsed['verify'], key, 6), '${{ steps.verify.outputs.'+key+' }}')
        self.assertEqual(scalar(steps['merge']['Mint protected merge token'], 'if', 8),
            "steps.preflight.outputs.verified == 'true' && steps.preflight.outputs.purpose == 'protected-merge'")
        self.assertEqual(scalar(steps['merge']['Merge exact owner request once'], 'if', 8),
            "steps.preflight.outputs.verified == 'true' && steps.preflight.outputs.purpose == 'protected-merge'")

    def test_credentials_only_scan_and_final_scoped_action(self):
        text, parsed, steps = self.source()
        self.assertIn('permissions: {}', text)
        self.assertEqual(re.findall(r'secrets\.([A-Z_]+)', text), ['SNYK_TOKEN', 'PROTECTED_MERGE_APP_PRIVATE_KEY'])
        self.assertNotIn('secrets.', text.split('jobs:\n', 1)[0])
        for key in parsed:
            self.assertEqual(dict(re.findall(r'^      ([a-z-]+): (read|write)$', parsed[key], re.M)),
                {'contents': 'read', 'actions': 'read', 'pull-requests': 'read'})
            if key != 'merge':
                for forbidden in ['environment:', 'PROTECTED_MERGE_TOKEN', 'PROTECTED_MERGE_APP_PRIVATE_KEY', 'create-github-app-token']:
                    self.assertNotIn(forbidden, parsed[key])
            for secret in ['GITHUB_TOKEN:', 'SNYK_TOKEN:', 'PROTECTED_MERGE_TOKEN:', 'PRIVATE_KEY:']:
                self.assertNotIn(secret, parsed[key].split('    steps:', 1)[0])
            for name, step in steps[key].items():
                if 'SNYK_TOKEN:' in step:
                    self.assertEqual((key, name), ('scan', 'Scan current source and bound license controls'))
                if 'PROTECTED_MERGE_TOKEN:' in step:
                    self.assertEqual((key, name), ('merge', 'Merge exact owner request once'))
                if 'secrets.' in step:
                    self.assertIn((key, name), [('scan', 'Scan current source and bound license controls'), ('merge', 'Mint protected merge token')])
            self.assertNotIn('continue-on-error', parsed[key])
        mint = steps['merge']['Mint protected merge token']
        self.assertEqual(scalar(mint, 'uses', 8).split(' #')[0], 'actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510')
        expected = {'client-id': '${{ vars.PROTECTED_MERGE_APP_CLIENT_ID }}',
            'private-key': '${{ secrets.PROTECTED_MERGE_APP_PRIVATE_KEY }}', 'owner': 'lorconksu',
            'repositories': 'veyport', 'permission-contents': 'write', 'permission-administration': 'read'}
        self.assertEqual(dict(re.findall(r'^          ([a-z-]+): (.+)$', mint, re.M)), expected)
        merge = steps['merge']['Merge exact owner request once']
        for key, output in [('PROTECTED_MERGE_TOKEN', 'token'), ('PROTECTED_MERGE_MINTED_INSTALLATION_ID', 'installation-id'), ('PROTECTED_MERGE_APP_SLUG', 'app-slug')]:
            self.assertEqual(scalar(merge, key, 10), '${{ steps.app.outputs.'+output+' }}')
        for key in ['ID', 'INSTALLATION_ID', 'RULESET_ID', 'CLIENT_ID']:
            name = 'PROTECTED_MERGE_'+('APP_'+key if key in ['ID', 'CLIENT_ID'] else key)
            self.assertEqual(scalar(merge, name, 10), '${{ vars.'+name+' }}')

    def test_exact_steps_source_checkouts_and_shell_data_handoff(self):
        _, parsed, steps = self.source()
        spec = importlib.util.spec_from_file_location('merge_workflow_contract', Path(__file__).with_name('protected_merge.py'))
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        for key, names in {**helper.REQUIRED_STEPS, 'merge': (*helper.MERGE_PRIOR_STEPS, helper.MERGE_STEP)}.items():
            self.assertEqual(tuple(steps[key]), names)
            self.assertEqual(scalar(parsed[key], 'name', 4), key)
            checkouts = [(name, step) for name, step in steps[key].items() if 'uses: actions/checkout@' in step]
            self.assertEqual(len(checkouts), 2 if key == 'scan' else 1)
            for name, step in checkouts:
                self.assertEqual(scalar(step, 'persist-credentials', 10), 'false')
                self.assertEqual(scalar(step, 'repository', 10), 'lorconksu/veyport')
                self.assertEqual(scalar(step, 'ref', 10), '${{ needs.admission.outputs.source_sha }}' if name == 'Checkout exact admitted source' else '${{ github.sha }}')
        commands = [('admission', 'Admit exact owner request', 'admit'), ('scan', 'Bind protected merge evidence', 'make-evidence'),
            ('verify', 'Verify fresh protected merge evidence', 'verify'), ('merge', 'Preflight fresh protected merge evidence', 'verify'), ('merge', 'Merge exact owner request once', 'merge-once')]
        for key, name, mode in commands:
            step = steps[key][name]
            self.assertNotIn('${{', shell_body(step))
            self.assertIn('/usr/bin/python3.12 -I -B "$CONTROL/scripts/security/protected_merge.py" '+mode, shell_body(step))
            self.assertEqual(scalar(step, 'GITHUB_TOKEN', 10), '${{ github.token }}')
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); script = root/'scripts/security'; script.mkdir(parents=True)
                (script/'protected_merge.py').write_text('import os,sys,json\nfrom pathlib import Path\nPath(os.environ["PROBE"]).write_text(json.dumps([sys.argv[1:],os.environ["ADMISSION_JSON"]]))\n')
                sentinel = root/'injected'; admission = '$(touch '+str(sentinel)+'); `touch '+str(sentinel)+'`'
                probe = root/'probe'
                result = self.run_shell(step, {'CONTROL': str(root), 'ADMISSION_JSON': admission, 'PROBE': str(probe)})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(probe.read_text()), [[mode], admission])
                self.assertFalse(sentinel.exists())

    def test_scanner_gate_and_encrypted_current_run_artifact(self):
        _, _, steps = self.source(); scan = steps['scan']
        gate = scan['Final policy and evidence gate']
        bindings = dict(re.findall(r'^          ([A-Z_]+): (.+)$', gate, re.M))
        expected = ['initialize', 'controller', 'source', 'preflight', 'go', 'node', 'bootstrap', 'tests', 'prepare', 'scan', 'policy', 'encrypt', 'envelope', 'upload', 'cleanup']
        self.assertEqual(set(bindings.values()), {'${{ steps.'+key+'.outcome }}' for key in expected} | {'${{ steps.encrypt.outputs.sealed_policy_exit }}'})
        good = {key: '0' if key == 'SEALED_POLICY_EXIT' else 'success' for key in bindings}
        self.assertEqual(self.run_shell(gate, good).returncode, 0)
        for key in good:
            for bad in ['', 'failure', 'skipped', 'cancelled', '1']:
                self.assertNotEqual(self.run_shell(gate, {**good, key: bad}).returncode, 0, key)
        self.assertEqual(scalar(gate, 'if', 8), 'always()')
        self.assertEqual(scalar(scan['Remove public resolver workspace and private plaintext'], 'if', 8), 'always()')
        upload = scan['Upload only encrypted evidence and allowlisted aggregates']
        self.assertEqual(scalar(upload, 'name', 10), 'protected-merge-${{ github.run_id }}-1')
        paths = upload.split('          path: |\n')[1].split('          if-no-files-found:')[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], ['${{ runner.temp }}/protected-merge/public/'+key for key in ['summary.json', 'evidence.tar.gz.age', 'publication.json']])
        self.assertIn('unset SNYK_TOKEN', shell_body(scan['Bind protected merge evidence']))
        for name, keys in [('Bind protected merge evidence', ['steps.encrypt.outcome']), ('Upload only encrypted evidence and allowlisted aggregates', ['steps.encrypt.outcome', 'steps.envelope.outcome'])]:
            guard = scalar(scan[name], 'if', 8); good = {key: 'success' for key in keys} | {'success()': False}
            self.assertTrue(expression(guard, good))
            for key in keys:
                self.assertFalse(expression(guard, {**good, key: 'failure'}))

    def test_deliberate_workflow_mutants_are_rejected(self):
        text, _, _ = self.source()
        mutants = [
            (" && needs.verify.outputs.purpose == 'protected-merge'", '', 'test_verified_strict_purpose_gates_environment_before_mint'),
            ('  CONTROL: ${{ github.workspace }}/controller', '  SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}', 'test_credentials_only_scan_and_final_scoped_action'),
            ('environment: ssdf-protected-merge', 'environment: wrong', 'test_verified_strict_purpose_gates_environment_before_mint'),
            ('${{ steps.app.outputs.installation-id }}', '${{ vars.PROTECTED_MERGE_INSTALLATION_ID }}', 'test_credentials_only_scan_and_final_scoped_action'),
            ('          permission-contents: write', '          permission-contents: write\n          skip-token-revoke: true', 'test_credentials_only_scan_and_final_scoped_action'),
            ('permission-administration: read', 'permission-administration: write', 'test_credentials_only_scan_and_final_scoped_action'),
            ('${{ steps.app.outputs.token }}', '${{ github.token }}', 'test_credentials_only_scan_and_final_scoped_action'),
            ('test "$CLEANUP_OUTCOME" = success', ': # removed cleanup gate', 'test_scanner_gate_and_encrypted_current_run_artifact'),
            ('"$CONTROL/scripts/security/protected_merge.py" merge-once', '"$SOURCE/scripts/security/protected_merge.py" merge-once', 'test_exact_steps_source_checkouts_and_shell_data_handoff'),
        ]
        for before, after, method in mutants:
            with self.subTest(mutation=before), tempfile.TemporaryDirectory() as folder:
                self.assertIn(before, text)
                mutated = Path(folder)/'workflow.yml'; mutated.write_text(text.replace(before, after, 1))
                with mock.patch(__name__+'.WORKFLOW', mutated), self.assertRaises(AssertionError):
                    getattr(self, method)()


if __name__ == '__main__': unittest.main()
