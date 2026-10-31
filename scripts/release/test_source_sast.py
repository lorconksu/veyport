import copy
import datetime as dt
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import source_sast as sast

REV = 'a' * 40


def sarif():
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL'}, 'extensions': [{'rules': [{'id': 'go/auth', 'properties': {'security-severity': '3.0', 'tags': ['external/cwe/cwe-287']}}]}]}, 'versionControlProvenance': [{'revisionId': REV, 'repositoryUri': 'https://github.com/lorconksu/veyport'}], 'results': [{'ruleId': 'go/auth', 'properties': {'github/alertNumber': 7}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'hub/auth.go'}}}]}]}]}


class SourceEvidenceTests(unittest.TestCase):
    def test_baseline_including_dismissed_and_auth_failure_preserved(self):
        alerts = [{'number': 7, 'created_at': '2026-01-01T00:00:00Z', 'state': 'dismissed', 'dismissed_reason': "won't fix"}]
        result = sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58', alerts)
        self.assertEqual(result[0]['severity'], 'low')
        self.assertEqual(result[0]['classification'], 'authentication')
        self.assertTrue(result[0]['suppressed'])
        self.assertEqual(result[0]['first_seen'], '2026-01-01T00:00:00Z')

    def test_wrong_revision_incomplete_execution_and_missing_rule_fail(self):
        for mutate in (lambda r: r['runs'][0]['versionControlProvenance'][0].update(revisionId='b' * 40), lambda r: r['runs'][0].update(invocations=[{'executionSuccessful': False}]), lambda r: r['runs'][0]['tool'].update(extensions=[])):
            raw = sarif()
            mutate(raw)
            with self.assertRaises(ValueError):
                sast.sarif_findings(raw, 'codeql', REV, '2.0.58')

    def test_sarif_false_positive_does_not_disappear(self):
        raw = sarif()
        raw['runs'][0]['results'][0]['suppressions'] = [{'kind': 'external'}]
        result = sast.sarif_findings(raw, 'codeql', REV, '2.0.58', [{'number': 7, 'state': 'dismissed', 'dismissed_reason': 'false positive'}])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['classification'], 'false-positive')

    def test_missing_provider_first_seen_is_not_replaced_by_scan_time(self):
        result = sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58')
        self.assertIsNone(result[0]['first_seen'])

    def test_freshness_bound_and_future_rejected(self):
        at = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)
        sast.fresh('2026-10-30T12:00:00Z', at)
        for value in ('2026-10-30T11:59:59Z', '2026-10-31T12:00:01Z', 'invalid'):
            with self.assertRaises(ValueError):
                sast.fresh(value, at)

    def test_sonar_pagination_never_accepts_missing_pages(self):
        api = sast.Sonar()
        with patch.object(api, 'get', side_effect=[{'paging': {'total': 2}, 'issues': [{'key': 'one'}]}, {'paging': {'total': 2}, 'issues': []}]):
            with self.assertRaises(ValueError):
                api.pages('issues/search', {}, 'issues')

    def test_sonar_current_revision_can_not_replace_historic_evidence(self):
        api = sast.Sonar()
        with patch.object(api, 'get', return_value={'analyses': [{'revision': 'b' * 40}]}):
            with self.assertRaises(ValueError):
                sast.export_sonar(api, '.', REV, '2.0.58', 'main')

    def test_policy_inventory_binds_source_around_annotations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hub").mkdir()
            path = root / "hub/example.go"
            path.write_text('package example\n// NOSONAR: example annotation\nfunc run() {}\n')
            (root / "sonar-project.properties").write_text('sonar.sources=hub\n')
            tracked = b'hub/example.go\0sonar-project.properties\0'
            with patch.object(sast.subprocess, 'check_output', return_value=tracked):
                before = sast.suppression_inventory(root)
                path.write_text(path.read_text().replace('func run()', 'func changed()'))
                after = sast.suppression_inventory(root)
            self.assertEqual(before['annotations'][0]['annotation_sha256'], after['annotations'][0]['annotation_sha256'])
            self.assertNotEqual(before['annotations'][0]['source_sha256'], after['annotations'][0]['source_sha256'])
            self.assertNotEqual(sast.sha(sast.canonical(before)), sast.sha(sast.canonical(after)))

    def test_missing_inventory_review_never_invents_false_positive_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                sast.reviewed_inventory('a' * 64, directory, None)

    def test_codeql_missing_language_is_incomplete_not_clean(self):
        api = sast.ExportAPI('test-token')
        with patch.object(api, 'pages', return_value=[]):
            with self.assertRaises(ValueError):
                sast.export_codeql(api, '.', REV, '2.0.58')


if __name__ == '__main__':
    unittest.main()
