"""Execute real fixed-fixture workflow guards/shell and reject wiring mutants."""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from test_snyk_pr_policy import scalar, workflow_steps, shell_body, expression
from test_protected_merge_workflow import jobs

WORKFLOW = Path(__file__).parents[2]/'.github/workflows/protected-merge-qualification.yml'
# Independent safety budget: each CLI starts its own bounded readers. Within
# probe, metadata and App preflight readers share the same elapsed-time window.
READ_PHASE_SECONDS = 120
WRITE_PHASE_SECONDS = 30
SETUP_AND_EVIDENCE_RESERVE_SECONDS = 120
CLI_PHASE_SECONDS = {
    'admit': READ_PHASE_SECONDS,
    'produce-canary': READ_PHASE_SECONDS + WRITE_PHASE_SECONDS,
    'probe': READ_PHASE_SECONDS + WRITE_PHASE_SECONDS + READ_PHASE_SECONDS,
}


class QualificationWorkflowTests(unittest.TestCase):
    def source(self):
        text = WORKFLOW.read_text(); parsed = jobs(text)
        return text, parsed, {key: workflow_steps(block) for key, block in parsed.items()}

    def test_job_timeouts_allow_bounded_phases_and_setup(self):
        _, parsed, steps = self.source()
        for key, block in parsed.items():
            modes = [mode for step in steps[key].values() for mode in re.findall(
                r'"\$CONTROL/scripts/security/protected_merge_qualification\.py" ([a-z-]+)', step)]
            required_seconds = sum(CLI_PHASE_SECONDS[mode] for mode in modes) + SETUP_AND_EVIDENCE_RESERVE_SECONDS
            self.assertGreaterEqual(int(scalar(block, 'timeout-minutes', 4))*60, required_seconds,
                f'{key}: timeout must allow bounded helper phases and setup/evidence reserve ({required_seconds}s)')

    def test_each_five_minute_job_mutant_fails_its_budget_assertion(self):
        text, parsed, _ = self.source()
        with self.workflow_source(text):
            self.test_job_timeouts_allow_bounded_phases_and_setup()
        for key, block in parsed.items():
            original = '    timeout-minutes: '+scalar(block, 'timeout-minutes', 4)
            self.assertEqual(block.count(original), 1)
            mutant = text.replace(block, block.replace(original, '    timeout-minutes: 5'), 1)
            self.assertNotEqual(mutant, text)
            with self.subTest(job=key), self.workflow_source(mutant):
                with self.assertRaisesRegex(AssertionError,
                        key+': timeout must allow bounded helper phases and setup/evidence reserve'):
                    self.test_job_timeouts_allow_bounded_phases_and_setup()

    def test_fixed_inputs_owner_guard_and_environment_gate(self):
        text, parsed, steps = self.source()
        trigger = text.split('on:\n', 1)[1].split('\npermissions:')[0]
        self.assertEqual(re.findall(r'^  ([a-z_]+):', trigger, re.M), ['workflow_dispatch'])
        self.assertEqual(re.findall(r'^      ([a-z_]+):', trigger, re.M), ['case', 'pr_number', 'head_sha'])
        self.assertIn('options: [main-settings, wrong-head, direct-push, native-merge, missing-canary, pending-canary, failed-canary, workflow-file-merge]', trigger)
        self.assertEqual(set(parsed), {'admission', 'probe'})
        good = {'github.event_name': 'workflow_dispatch', 'github.repository': 'lorconksu/veyport',
            'github.repository_id': '1188082218', 'github.repository_owner_id': '13374789',
            'github.ref': 'refs/heads/main', 'github.actor': 'lorconksu', 'github.actor_id': '13374789',
            'github.triggering_actor': 'lorconksu', 'github.run_attempt': '1',
            'vars.PROTECTED_MERGE_QUALIFICATION_ENABLED': 'true'}
        guard = scalar(parsed['admission'], 'if', 4)
        self.assertTrue(expression(guard, good))
        for key in good: self.assertFalse(expression(guard, {**good, key: 'other'}), key)
        self.assertEqual(scalar(parsed['probe'], 'environment', 4), 'ssdf-protected-merge')
        self.assertNotIn('environment:', parsed['admission'])
        good = {'needs.admission.result': 'success', 'needs.admission.outputs.admitted': 'true'}
        guard = scalar(parsed['probe'], 'if', 4)
        self.assertTrue(expression(guard, good))
        for key in good: self.assertFalse(expression(guard, {**good, key: ''}))
        for name in ['Mint same least-privilege App token', 'Probe fixed fixture once']:
            self.assertEqual(scalar(steps['probe'][name], 'if', 8), "steps.preflight.outputs.admitted == 'true'")

    def test_exact_credentials_permissions_checkout_and_action_outputs(self):
        text, parsed, steps = self.source()
        self.assertIn('permissions: {}', text)
        self.assertEqual(re.findall(r'secrets\.([A-Z_]+)', text), ['PROTECTED_MERGE_APP_PRIVATE_KEY'])
        self.assertNotIn('continue-on-error', text)
        self.assertNotIn('SNYK_TOKEN', text)
        for key, block in parsed.items():
            self.assertEqual(dict(re.findall(r'^      ([a-z-]+): (read|write)$', block, re.M)),
                {'contents': 'read', 'actions': 'read', 'pull-requests': 'read', 'checks': 'write' if key == 'admission' else 'read'})
            checkout = steps[key]['Checkout trusted main controller']
            self.assertEqual(scalar(checkout, 'uses', 8).split(' #')[0], 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803')
            self.assertEqual(scalar(checkout, 'repository', 10), 'lorconksu/veyport')
            self.assertEqual(scalar(checkout, 'ref', 10), '${{ github.sha }}')
            self.assertEqual(scalar(checkout, 'persist-credentials', 10), 'false')
            self.assertNotIn('PROTECTED_MERGE_TOKEN:', block.split('    steps:', 1)[0])
        mint = steps['probe']['Mint same least-privilege App token']
        self.assertEqual(scalar(mint, 'uses', 8).split(' #')[0], 'actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510')
        self.assertEqual(dict(re.findall(r'^          ([a-z-]+): (.+)$', mint, re.M)), {
            'client-id': '${{ vars.PROTECTED_MERGE_APP_CLIENT_ID }}', 'private-key': '${{ secrets.PROTECTED_MERGE_APP_PRIVATE_KEY }}',
            'owner': 'lorconksu', 'repositories': 'veyport', 'permission-contents': 'write', 'permission-administration': 'read'})
        probe = steps['probe']['Probe fixed fixture once']
        for key, output in [('PROTECTED_MERGE_TOKEN', 'token'), ('PROTECTED_MERGE_MINTED_INSTALLATION_ID', 'installation-id'), ('PROTECTED_MERGE_APP_SLUG', 'app-slug')]:
            self.assertEqual(scalar(probe, key, 10), '${{ steps.app.outputs.'+output+' }}')
        self.assertEqual(tuple(steps['probe']), ('Checkout trusted main controller', 'Revalidate fixed fixture before token', 'Mint same least-privilege App token', 'Probe fixed fixture once'))
        for name, step in steps['admission'].items(): self.assertNotIn('PROTECTED_MERGE_TOKEN', step)

    def test_actual_shell_data_handoff_and_trusted_helper(self):
        _, _, steps = self.source()
        for key, name, mode in [('admission', 'Admit fixed fixture request', 'admit'), ('admission', 'Produce fixed native canary when requested', 'produce-canary'), ('probe', 'Revalidate fixed fixture before token', 'admit'), ('probe', 'Probe fixed fixture once', 'probe')]:
            step = steps[key][name]; shell = shell_body(step)
            self.assertNotIn('${{', shell)
            self.assertIn('/usr/bin/python3.12 -I -B "$CONTROL/scripts/security/protected_merge_qualification.py" '+mode, shell,
                f'{key}/{name}: trusted controller helper required')
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); script = root/'scripts/security'; script.mkdir(parents=True)
                (script/'protected_merge_qualification.py').write_text('import os,sys\nfrom pathlib import Path\nPath(os.environ["PROBE"]).write_text(sys.argv[1])\n')
                probe = root/'probe'
                completed = subprocess.run(['/bin/bash', '-c', shell.replace('/usr/bin/python3.12', sys.executable)],
                    env={'PATH': os.defpath, 'CONTROL': str(root), 'PROBE': str(probe), 'INPUT_CASE': '$(exit 42)'}, capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 0, completed.stderr); self.assertEqual(probe.read_text(), mode)

    def test_native_producer_guard_and_credential_boundary(self):
        _, parsed, steps = self.source()
        producer = steps['admission']['Produce fixed native canary when requested']
        self.assertEqual(tuple(steps['admission']), ('Checkout trusted main controller', 'Admit fixed fixture request', 'Produce fixed native canary when requested'))
        self.assertEqual(scalar(producer, 'GITHUB_TOKEN', 10), '${{ github.token }}')
        guard = scalar(producer, 'if', 8)
        for case in ['pending-canary', 'failed-canary']:
            self.assertTrue(expression(guard, {'steps.admit.outputs.case': case}))
        for case in ['missing-canary', 'native-merge', 'main-settings', 'wrong-head', '']:
            self.assertFalse(expression(guard, {'steps.admit.outputs.case': case}))
        for forbidden in ['PROTECTED_MERGE_TOKEN', 'secrets.', 'create-github-app-token', 'environment:']:
            self.assertNotIn(forbidden, parsed['admission'])

    @contextmanager
    def workflow_source(self, text):
        with tempfile.TemporaryDirectory() as folder:
            workflow = Path(folder)/'workflow.yml'
            workflow.write_text(text)
            with mock.patch(__name__+'.WORKFLOW', workflow):
                yield

    def test_unchanged_workflow_control_preserves_probe_reads(self):
        text, _, _ = self.source()
        with self.workflow_source(text):
            self.test_actual_shell_data_handoff_and_trusted_helper()
            with tempfile.TemporaryDirectory() as folder:
                probe = Path(folder)/'unrelated-probe'
                probe.write_text('real probe output')
                self.assertEqual(probe.read_text(), 'real probe output')

    def test_damaged_workflow_mutants_rejected(self):
        text, _, _ = self.source()
        mutants = [
            ("steps.admit.outputs.case == 'pending-canary' || steps.admit.outputs.case == 'failed-canary'", 'always()', 'test_native_producer_guard_and_credential_boundary'),
            ('      checks: read', '      checks: write', 'test_exact_credentials_permissions_checkout_and_action_outputs'),
            (" && github.run_attempt == '1'", '', 'test_fixed_inputs_owner_guard_and_environment_gate'),
            (" && github.actor == 'lorconksu'", '', 'test_fixed_inputs_owner_guard_and_environment_gate'),
            (" && github.ref == 'refs/heads/main'", '', 'test_fixed_inputs_owner_guard_and_environment_gate'),
            ('environment: ssdf-protected-merge', 'environment: other', 'test_fixed_inputs_owner_guard_and_environment_gate'),
            ("steps.preflight.outputs.admitted == 'true'", 'always()', 'test_fixed_inputs_owner_guard_and_environment_gate'),
            ('permission-administration: read', 'permission-administration: write', 'test_exact_credentials_permissions_checkout_and_action_outputs'),
            ('${{ steps.app.outputs.token }}', '${{ github.token }}', 'test_exact_credentials_permissions_checkout_and_action_outputs'),
            ('${{ steps.app.outputs.installation-id }}', '${{ vars.PROTECTED_MERGE_INSTALLATION_ID }}', 'test_exact_credentials_permissions_checkout_and_action_outputs'),
            ('"$CONTROL/scripts/security/protected_merge_qualification.py" probe', '"$SOURCE/scripts/security/protected_merge_qualification.py" probe', 'test_actual_shell_data_handoff_and_trusted_helper'),
        ]
        for old, new, method in mutants:
            self.assertIn(old, text)
            with self.subTest(mutant=old), self.workflow_source(text.replace(old, new)):
                if method == 'test_actual_shell_data_handoff_and_trusted_helper':
                    with self.assertRaisesRegex(AssertionError, 'probe/Probe fixed fixture once: trusted controller helper required'):
                        getattr(self, method)()
                else:
                    with self.assertRaises(AssertionError): getattr(self, method)()
