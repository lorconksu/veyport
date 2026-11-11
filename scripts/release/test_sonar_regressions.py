"""Regressions for trusted Sonar polling, raw reads and prototype identity."""
import io
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

import git_tag
import metadata
import sonar_bridge as bridge
import sonar_context
import sonar_job_evidence as capture
from test_sonar_bridge_bootstrap import CONTROL, REPO, SOURCE, FakeAPI, public_coverage_fixture, producer_env


def terminal_result(api):
    return {'schema': 1, 'source': bridge.source_identity(api.run),
            'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL,
                         'path': bridge.WORKFLOW, 'tooling_revision': CONTROL},
            'context': bridge.context(api, api.run), 'task_id': 'bounded_task_123',
            'scanner_action': bridge.ACTION, 'scanner_outcome': 'success',
            'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}


class PollingTests(unittest.TestCase):
    def setup_wait(self, finish=1800, mutation=None):
        api = FakeAPI()
        clock = [0]
        api.producer.update(status='in_progress', conclusion=None)
        source = bridge.source_identity(api.run)
        binding = {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL,
                   'path': bridge.WORKFLOW, 'tooling_revision': CONTROL}
        claim = api.add_artifact(223, 'sonar-claim-v1-123-2', 456,
                                 {'claim.json': bridge.canonical({'schema': 1, 'source': source, 'producer': binding})})
        original = api.get
        state = {'changed': False, 'finished': False}
        def get(path, **kwargs):
            if clock[0] >= 120 and mutation and not state['changed']:
                state['changed'] = True
                mutation(api, claim)
            if clock[0] >= finish and not state['finished']:
                state['finished'] = True
                api.producer.update(status='completed', conclusion='success')
                value = terminal_result(api)
                api.add_artifact(224, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(value)})
            return original(path, **kwargs)
        api.get = get
        def sleep(seconds): clock[0] += seconds
        return api, clock, sleep

    def test_thirty_minute_wait_has_bounded_budget_and_final_full_validation(self):
        api, clock, sleep = self.setup_wait()
        with patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(bridge.time, 'sleep', side_effect=sleep):
            result = bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=3000)
        self.assertEqual(result['scan_status'], 'success')
        self.assertEqual(clock[0], 1800)
        self.assertLess(len(api.calls), 350)
        self.assertGreaterEqual(api.calls.count('actions/runs/123'), 32)
        # Claim/control are validated once while waiting, then both descriptor
        # and claim are completely admitted again at terminal acceptance.
        controls = [p for p in api.calls if p.startswith('contents/')]
        self.assertEqual(len(controls), 6 * len(bridge.TRUSTED_FILES) + 1)
        self.assertEqual(sum(p.startswith("git/trees/") for p in api.calls), 1)
        self.assertEqual(api.calls.count('actions/artifacts/223/zip'), 2)
        self.assertGreaterEqual(api.calls.count('actions/artifacts/223'), 31)

    def test_cached_claim_never_hides_mutable_source_producer_or_artifact_changes(self):
        mutations = [lambda a, c: a.run.update(run_attempt=3),
                     lambda a, c: a.run.update(status='completed', conclusion='cancelled'),
                     lambda a, c: a.run.update(head_sha=CONTROL),
                     lambda a, c: a.run.update(head_branch='foreign'),
                     lambda a, c: a.producer.update(run_attempt=2),
                     lambda a, c: a.producer.update(status='completed', conclusion='cancelled'),
                     lambda a, c: c.update(digest='sha256:' + 'f' * 64),
                     lambda a, c: a.artifacts.remove(c)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                api, clock, sleep = self.setup_wait(mutation=mutation)
                with patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(bridge.time, 'sleep', side_effect=sleep), self.assertRaises(ValueError):
                    bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=3000)
                # A terminal producer gets the bounded 120-second descriptor
                # propagation grace; identity/artifact mutations still fail now.
                limit = 240 if api.producer.get('conclusion') == 'cancelled' else 120
                self.assertLessEqual(clock[0], limit)

    def test_recognized_throttle_uses_exponential_bounded_retry_and_fresh_source(self):
        api, clock, sleep = self.setup_wait(finish=240)
        original = api.get
        count = [0]
        def get(path, **kwargs):
            if path == 'actions/runs/123' and count[0] < 2:
                count[0] += 1
                raise bridge.BridgeRateLimit(60)
            return original(path, **kwargs)
        api.get = get
        delays = []
        def pause(seconds): delays.append(seconds); sleep(seconds)
        with patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(bridge.time, 'sleep', side_effect=pause):
            self.assertEqual(bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=1000)['scan_status'], 'success')
        self.assertEqual(delays[:2], [60, 120])
        with patch.object(bridge.time, 'monotonic', return_value=0), patch.object(bridge.time, 'sleep') as sleeper, patch.object(api, 'get', side_effect=bridge.BridgeRateLimit(3600)), self.assertRaises(ValueError):
            bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=3000)
        sleeper.assert_not_called()

    def test_source_retry_during_final_claim_validation_is_refused(self):
        api, clock, sleep = self.setup_wait(finish=60)
        original = api.get
        reads = [0]
        def get(path, **kwargs):
            value = original(path, **kwargs)
            if path == 'actions/artifacts/223/zip':
                reads[0] += 1
                if reads[0] == 2:api.run['run_attempt'] = 3
            return value
        api.get = get
        with patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(bridge.time, 'sleep', side_effect=sleep), self.assertRaises(ValueError):
            bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=3000)
        self.assertEqual(reads[0], 2)

    def test_continuous_throttle_stops_after_five_backoffs(self):
        api, clock, sleep = self.setup_wait()
        delays = []
        def pause(seconds):delays.append(seconds); sleep(seconds)
        with patch.object(api, 'get', side_effect=bridge.BridgeRateLimit(60)) as get, patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(bridge.time, 'sleep', side_effect=pause), self.assertRaises(ValueError):
            bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=3000)
        self.assertEqual(delays, [60, 120, 240, 480, 960])
        self.assertEqual(get.call_count, 6)

    def test_http_permission_failure_is_not_retried_and_throttles_never_redirect_credentials(self):
        for status, headers, expected in [(403, {}, ValueError), (429, {}, bridge.BridgeRateLimit),
                (403, {'Retry-After': '90'}, bridge.BridgeRateLimit),
                (403, {'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '1120'}, bridge.BridgeRateLimit)]:
            error = urllib.error.HTTPError('https://api.github.com/private', status, 'fixed', headers, io.BytesIO(b'private-provider-body'))
            with self.subTest(status=status, headers=headers), patch.object(bridge.urllib.request, 'build_opener') as factory, patch.object(bridge.time, 'time', return_value=1000):
                factory.return_value.open.side_effect = error
                with self.assertRaises(expected) as caught:
                    bridge.API(token='private-test-token').get('actions/runs/123')
                if status == 403 and not headers:
                    self.assertNotIsInstance(caught.exception, bridge.BridgeRateLimit)
                self.assertNotIn('private', str(caught.exception))
                self.assertEqual(factory.return_value.open.call_count, 1)
        for headers in ({'Retry-After': 'broken'}, {'Retry-After': '999999'}, {'X-RateLimit-Remaining': '0'}):
            with self.assertRaises(ValueError):bridge.rate_limit_delay(403, headers)


class IntakeDeadlineTests(unittest.TestCase):
    def intake(self, api, root, clock, pause, **kwargs):
        event = {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}
        with patch.dict(os.environ, producer_env(root), clear=True), \
                patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(bridge.time, 'sleep', side_effect=pause):
            return bridge.intake(api, event, root / 'intake', **kwargs)

    def test_supported_slow_source_path_finishes_once_and_ready_path_has_no_delay(self):
        for ready_at in (0, 6900):
            with self.subTest(ready_at=ready_at), tempfile.TemporaryDirectory() as directory:
                api, clock, pauses = FakeAPI(), [0], []
                original = bridge.coverage_ready
                def ready(*args):return original(*args) if clock[0] >= ready_at else None
                def pause(seconds):pauses.append(seconds);clock[0] += seconds
                with patch.object(bridge, 'coverage_ready', side_effect=ready):
                    plan = self.intake(api, Path(directory), clock, pause)
                self.assertEqual(plan['source']['head_sha'], SOURCE)
                self.assertEqual(clock[0], ready_at)
                if not ready_at:self.assertEqual(pauses, [])

    def test_terminal_success_without_ready_required_jobs_fails_before_sleep_or_claim(self):
        for fault in ('test-missing', 'integration-missing', 'signing-missing', 'job-pending'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root, api, clock, pauses = Path(directory), FakeAPI(), [0], []
                api.run.update(status='completed', conclusion='success')
                if fault == 'job-pending': api.jobs[0]['status'] = 'in_progress'
                else:
                    index = {'test-missing': 0, 'integration-missing': 1, 'signing-missing': 2}[fault]
                    api.jobs.pop(index)
                def pause(seconds):pauses.append(seconds);clock[0] += seconds
                with self.assertRaisesRegex(ValueError, 'Terminal source attempt lacks ready coverage jobs'):
                    self.intake(api, root, clock, pause, timeout=7200)
                self.assertEqual(pauses, [])
                self.assertEqual(clock[0], 0)
                self.assertFalse((root / 'intake').exists())
                self.assertEqual(sum('/attempts/2/jobs?' in path for path in api.calls), 1)
                self.assertFalse(any('/zip' in path for path in api.calls))

    def test_terminal_success_with_ready_jobs_proceeds_and_active_listing_may_converge(self):
        for terminal in (True, False):
            with self.subTest(terminal=terminal), tempfile.TemporaryDirectory() as directory:
                root, api, clock, pauses = Path(directory), FakeAPI(), [0], []
                if terminal: api.run.update(status='completed', conclusion='success')
                else:
                    complete = api.jobs
                    api.jobs = []
                def pause(seconds):
                    pauses.append(seconds); clock[0] += seconds
                    if not terminal: api.jobs = complete
                plan = self.intake(api, root, clock, pause, timeout=60)
                self.assertEqual(plan['source']['head_sha'], SOURCE)
                self.assertTrue((root / 'intake/claim.json').exists())
                self.assertEqual(pauses, [] if terminal else [15])

    def test_active_missing_jobs_keeps_original_finite_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root, api, clock, pauses = Path(directory), FakeAPI(), [0], []
            api.jobs = []
            def pause(seconds):pauses.append(seconds);clock[0] += seconds
            with self.assertRaisesRegex(ValueError, 'deadline|expired'):
                self.intake(api, root, clock, pause, timeout=30)
            self.assertEqual(clock[0], 30)
            self.assertEqual(pauses, [15, 15])
            self.assertFalse((root / 'intake').exists())

    def test_throttled_initial_and_post_output_reads_retry_without_restarting_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root, api, clock, pauses = Path(directory), FakeAPI(), [0], []
            original = api.get
            pending = {'actions/runs/456', 'actions/artifacts/101'}
            def get(path, **kwargs):
                if path in pending:
                    pending.remove(path)
                    if path.endswith('/101'):self.assertTrue((root/'intake/unit/coverage-hub.out').exists())
                    raise bridge.BridgeRateLimit(60)
                return original(path, **kwargs)
            def pause(seconds):pauses.append(seconds);clock[0] += seconds
            api.get = get
            self.intake(api, root, clock, pause)
            self.assertEqual(pauses, [60, 120])
            self.assertFalse(pending)
            self.assertTrue((root/'intake/claim.json').is_file())

    def test_retry_backoff_never_resets_deadline_or_hides_source_retry(self):
        clock, pauses = [0], []
        def pause(seconds):pauses.append(seconds);clock[0] += seconds
        with patch.object(bridge.time, 'monotonic', side_effect=lambda:clock[0]), patch.object(bridge.time, 'sleep', side_effect=pause):
            api = type('Reads', (), {'get':lambda *_a, **_k: (_ for _ in ()).throw(bridge.BridgeRateLimit(90))})()
            with self.assertRaises(ValueError):bridge.IntakeReads(api, 180).get('read-only')
        self.assertEqual(pauses, [90])
        clock[:], pauses[:] = [0], []
        with patch.object(bridge.time, 'monotonic', side_effect=lambda:clock[0]), patch.object(bridge.time, 'sleep', side_effect=pause):
            with self.assertRaisesRegex(ValueError, 'retry limit'):bridge.IntakeReads(api, 7200).get('read-only')
        self.assertEqual(len(pauses), 5)
        with tempfile.TemporaryDirectory() as directory:
            source, clock, sleeps = FakeAPI(), [0], []
            original = source.get
            first = [True]
            def get(path, **kwargs):
                if path == 'actions/runs/123' and first[0]:first[0]=False;raise bridge.BridgeRateLimit(60)
                return original(path, **kwargs)
            def revoke(seconds):sleeps.append(seconds);clock[0]+=seconds;source.run['run_attempt']=3
            source.get=get
            with self.assertRaises(ValueError):self.intake(source, Path(directory), clock, revoke)
            self.assertEqual(sleeps, [60])
            self.assertFalse((Path(directory)/'intake/claim.json').exists())

    def test_permission_error_is_terminal_and_late_final_readback_never_emits_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            api, clock, sleeps = FakeAPI(), [0], []
            api.get=lambda *_a, **_k: (_ for _ in ()).throw(ValueError('fixture permission denied'))
            with self.assertRaisesRegex(ValueError, 'permission denied'):self.intake(api, Path(directory), clock, sleeps.append)
            self.assertEqual(sleeps, [])
        with tempfile.TemporaryDirectory() as directory:
            api, clock, count = FakeAPI(), [0], [0]
            original=api.get
            def get(path, **kwargs):
                value=original(path, **kwargs)
                if path=='pulls/115':
                    count[0]+=1
                    if count[0]==2:clock[0]=11
                return value
            api.get=get
            with self.assertRaises(ValueError):self.intake(api, Path(directory), clock, lambda _:None, timeout=10)
            self.assertFalse((Path(directory)/'intake/claim.json').exists())

    def test_consumer_command_accepts_exact_ceiling_and_rejects_larger_bound(self):
        environment={'SONAR_CREDENTIAL_MODE':'bridge','SONAR_BRIDGE_TOOLING_REVISION':CONTROL,
                     'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}
        value={'task_id':'bounded_task_123','scan_status':'success','context':{}}
        arguments=['sonar_bridge.py','wait','--revision',SOURCE,'--output','unused','--timeout','10800']
        with patch.dict(os.environ,environment,clear=True),patch.object(sys,'argv',arguments), \
             patch.object(bridge,'wait_result',return_value=value) as wait, \
             patch.object(bridge,'write_record'),patch.object(bridge,'outputs'):
            bridge.main()
            self.assertEqual(wait.call_args.args[-1],10800)
        with patch.object(sys,'argv',arguments[:-1]+['10801']),self.assertRaises(ValueError):bridge.main()

    def test_http_and_official_verifier_share_remaining_command_deadline(self):
        self.assertEqual(bridge.IntakeReads(bridge.API(token='',deadline=5),10).deadline,5)
        with patch.object(bridge.time,'monotonic',return_value=4), patch.object(bridge.urllib.request,'build_opener') as opener:
            opener.return_value.open.return_value=io.BytesIO(b'{}')
            self.assertEqual(bridge.API(token='fixture',deadline=5).get('actions/runs/123'), {})
            self.assertEqual(opener.return_value.open.call_args.kwargs['timeout'],1)
        with patch.object(bridge.time,'monotonic',return_value=5), patch.object(bridge.subprocess,'Popen') as child:
            with self.assertRaises(ValueError):bridge.verifier_output(['trusted-verifier'],{},'.',deadline=5)
            child.assert_not_called()
        began=time.monotonic()
        with self.assertRaises(ValueError):
            bridge.verifier_output([sys.executable,'-I','-S','-c','import time;time.sleep(5)'],
                                   {'PATH':'/usr/bin:/bin'},'.',deadline=time.monotonic()+0.1)
        self.assertLess(time.monotonic()-began,2)


def workflow_jobs(text):
    rows=list(re.finditer(r'^  ([A-Za-z][A-Za-z0-9_-]*):\s*$',text,re.M))
    return {m[1]:text[m.end():rows[i+1].start() if i+1<len(rows) else len(text)] for i,m in enumerate(rows)}


class CoverageWorkflowContractTests(unittest.TestCase):
    root=Path(__file__).resolve().parents[2]

    def test_explicit_producer_bridge_and_consumer_budgets_fit_critical_path(self):
        ci=(self.root/'.github/workflows/ci.yml').read_text();jobs=workflow_jobs(ci)
        trusted=(self.root/'.github/workflows/sonar-bridge.yml').read_text();bridge_jobs=workflow_jobs(trusted)
        def minutes(block):
            match=re.search(r'^    timeout-minutes: ([0-9]+)$',block,re.M)
            self.assertIsNotNone(match,'unbounded required job');return int(match[1])
        self.assertIn('if-no-files-found: error',jobs['integration'])
        expected={'unit':60,'server-tests':45,'test':10,'integration':20,'sonarcloud':20}
        for job,value in expected.items():self.assertEqual(minutes(jobs[job]),value,job)
        self.assertEqual(minutes(bridge_jobs['intake']),130);self.assertEqual(minutes(bridge_jobs['scan']),30)
        intake_seconds=int(re.search(r'intake --output [^\n]+ --timeout ([0-9]+)',trusted)[1])
        critical=max(expected['unit'],expected['server-tests'])+expected['test']+expected['integration']+10
        self.assertGreaterEqual(intake_seconds,critical*60+15*60+5*60)
        self.assertGreaterEqual(minutes(bridge_jobs['intake'])*60,intake_seconds+10*60)
        for command in ('prepare','descriptor'):
            self.assertRegex(trusted,command+r'[^\n]+ --timeout 300')
        self.assertIn('        timeout-minutes: 10',bridge_jobs['scan'])
        if 'sonar-scan' in jobs:
            for job,value in {'sonar-coverage-attestation':10,'sonar-context':10,'sonar-scan':190}.items():self.assertEqual(minutes(jobs[job]),value)
            self.assertIn('--timeout 10800',jobs['sonar-scan'])
            # Source can finish early while intake uses a legitimate throttle
            # allowance. Do not subtract the maximum source duration as though
            # it were a guaranteed minimum before the consumer starts.
            self.assertGreaterEqual(10800,minutes(bridge_jobs['intake'])*60+30*60+10*60+10*60)
            self.assertGreaterEqual(minutes(jobs['sonar-scan'])*60,10800+10*60)
        else:
            self.assertIn('Hold legacy stable-tag Sonar scans',jobs['sonarcloud'])

    def test_actual_integration_step_requires_both_reports_without_rerunning_tests(self):
        text=(self.root/'.github/workflows/ci.yml').read_text();job=workflow_jobs(text)['integration']
        title='Require and report complete integration coverage' if 'Require and report complete integration coverage' in job else 'Report agent binary coverage'
        step=job.split('      - name: '+title,1)[1].split('\n      - ',1)[0]
        run=step.split('        run: |\n',1)[1]
        script='\n'.join(line[10:] for line in run.splitlines())
        upload=job.split('      - name: Upload integration coverage',1)[1].split('\n      - ',1)[0]
        for profile in bridge.COVERAGE['integration']:self.assertIn(profile,upload)
        for mode in ('missing-agent','empty-agent','linked-agent','complete'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'hub').mkdir();(root/'agent').mkdir();(root/'tools').mkdir()
                (root/'coverage-integration.out').write_text('mode: atomic\n')
                agent=root/'coverage-agent-integration.out'
                if mode=='empty-agent':agent.touch()
                elif mode=='linked-agent':agent.symlink_to(root/'coverage-integration.out')
                elif mode=='complete':agent.write_text('mode: atomic\n')
                go=root/'tools/go';log=root/'calls'
                go.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\nprintf "total: 80.0%%\\n"\n');go.chmod(0o700)
                result=subprocess.run(['bash','-c',script],cwd=root,env={**os.environ,'PATH':str(root/'tools')+':/usr/bin:/bin','CALLS':str(log)},capture_output=True,timeout=5)
                self.assertEqual(result.returncode==0,mode=='complete',result.stderr)
                calls=log.read_text().splitlines() if log.exists() else []
                self.assertEqual(len(calls),2 if mode=='complete' else 0)
                self.assertTrue(all(call.startswith('tool cover ') for call in calls))


class RawReadTests(unittest.TestCase):
    def test_every_repeated_provider_read_is_preserved_separately(self):
        class Provider:
            def __init__(self):self.count = 0
            def get(self, _endpoint, _params):
                self.count += 1
                return {'sequence': self.count}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = capture.AttemptAPI(Provider(), root, 10, lambda: 0)
            for endpoint in ('project_branches/list', 'project_analyses/search', 'qualitygates/project_status'):
                params = {'p': 1} if endpoint == 'project_analyses/search' else {}
                for _ in range(4):api.get(endpoint, params)
            files = sorted(root.glob('*.json'))
            self.assertEqual(len(files), 12)
            self.assertEqual({json.loads(p.read_text())['sequence'] for p in files}, set(range(1, 13)))
            self.assertEqual(len({p.name for p in files}), 12)


def fake_sonar(endpoint, params):
    if endpoint == 'components/show':return {'component': {'key': sonar_context.PROJECT, 'visibility': 'public'}}
    if endpoint == 'settings/values':return {'settings': [{'key': 'sonar.branch.longLivedBranches.regex', 'value': 'main|release-.*'}]}
    if endpoint == 'project_branches/list':return {'branches': []}
    raise AssertionError((endpoint, params))


class PrototypeIdentityTests(unittest.TestCase):
    def test_ssdf_analysis_does_not_admit_legacy_publication_identity(self):
        for tag in ('prototype-ssdf.1', 'prototype-ssdf.29'):
            with self.assertRaises(ValueError):
                metadata.identity('2.0.58-prototype.1', tag, SOURCE, 'refs/heads/feat/test', True)
            with patch.object(git_tag, 'lookup') as lookup, self.assertRaises(ValueError):
                git_tag.verify(tag, SOURCE, bridge.REPOSITORY, False)
            lookup.assert_not_called()
            api = FakeAPI()
            plan = sonar_context.resolve('workflow_dispatch', {'repository': REPO}, bridge.REPOSITORY,
                'refs/tags/' + tag, SOURCE, True, fetch=lambda path: api.get(path.removeprefix('repos/' + bridge.REPOSITORY + '/')), sonar_fetch=fake_sonar, details=True)
            self.assertIn('sonar.pullrequest.key=115', plan['args'])
            self.assertEqual(plan['gate_args'], plan['args'])
            self.assertEqual(plan['quality_gate_wait'], 'true')

    def test_ssdf_identity_rejects_ambiguous_or_nonprototype_use(self):
        for tag in ('prototype-ssdf.0', 'prototype-ssdf.01', 'prototype-ssdf.-1', 'prototype-ssdf.1-extra', 'prototype-other.1'):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):metadata.identity('2.0.58-prototype.1', tag, SOURCE, 'refs/heads/feat/test', True)
                with patch.object(git_tag, 'lookup') as lookup, self.assertRaises(ValueError):git_tag.verify(tag, SOURCE, bridge.REPOSITORY, False)
                lookup.assert_not_called()
                with self.assertRaises(ValueError):sonar_context.resolve('workflow_dispatch', {'repository': REPO}, bridge.REPOSITORY, 'refs/tags/' + tag, SOURCE, True, fetch=FakeAPI().get, sonar_fetch=fake_sonar)
        for version, ref, prototype in [('2.0.58', 'refs/heads/feat/test', True), ('2.0.58-prototype.1', 'refs/heads/main', True), ('2.0.58', 'refs/tags/prototype-ssdf.1', False)]:
            with self.assertRaises(ValueError):metadata.identity(version, 'prototype-ssdf.1', SOURCE, ref, prototype)


if __name__ == '__main__':
    unittest.main()
