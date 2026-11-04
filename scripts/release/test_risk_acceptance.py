"""Approval trust-boundary tests using only the standard library and fake API data."""
import copy
import datetime as dt
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

import risk_acceptance as risk


AT = dt.datetime(2026, 11, 4, 12, tzinfo=dt.timezone.utc)
REVISION = "a" * 40
INVENTORY_HASH = "b" * 64
OWNER = {"id": 13374789, "login": "lorconksu", "type": "User"}


def proposal(coverage=False):
    common = {
        "schema_version": 1, "reason": "Disclosure-safe reviewed rationale",
        "owner": "lorconksu", "authorized_approver": "lorconksu",
        "approval_time": "2026-11-04T11:00:00Z",
        "expires_at": "2026-11-05T12:00:00Z",
        "private_evidence_reference": "evidence:bootstrap-test",
    }
    if coverage:
        return {**common, "id": "CR-0001", "inventory_sha256": INVENTORY_HASH}
    return {
        **common, "id": "RA-0001", "classification": "accepted-risk",
        "severity": "high", "compensating_controls": "Restricted access",
        "remediation_reference": "issue:123",
        "findings": [{"scope": "source:npm:tests/e2e", "scanner": "snyk",
                      "id": "F-1", "component": "fixture", "version": "1.0.0"}],
    }


class FakeGitHub:
    """An authenticated provider fixture; production code never calls the network."""

    def __init__(self, raw, record_id):
        self.raw = raw
        self.record_id = record_id
        self.repository = {"full_name": risk.REPOSITORY, "default_branch": "main",
                           "owner": copy.deepcopy(OWNER)}
        self.run = {
            "id": 123, "repository": {"full_name": risk.REPOSITORY},
            "actor": copy.deepcopy(OWNER), "triggering_actor": copy.deepcopy(OWNER),
            "head_sha": REVISION, "head_branch": "main", "path": risk.WORKFLOW,
            "event": "workflow_dispatch", "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "created_at": "2026-11-04T11:30:00Z",
        }
        self.environment = {
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                                  "reviewers": [{"type": "User", "reviewer": copy.deepcopy(OWNER)}]}],
        }
        self.branches = {"branch_policies": [{"name": "main", "type": "branch"}]}
        self.ancestry = "ahead"
        self.changed_file = None
        self.approval = None
        self.archive_entries = None
        self.artifacts = {"total_count": 1, "artifacts": [
            {"id": 1, "name": "ssdf-approval-" + record_id,
             "expired": False, "size_in_bytes": 1000}]}
        self.content_requests = []

    def content(self, path, revision):
        self.content_requests.append((path, revision))
        directory = "coverage-reviews" if self.record_id.startswith("CR-") else "risk-acceptances"
        if path == f"docs/security/{directory}/{self.record_id}.md":
            return self.raw
        if path not in risk.TRUSTED_FILES:
            raise AssertionError(path)
        return b"changed implementation" if path == self.changed_file and revision == "main" else b"trusted implementation"

    def get(self, path, raw=False):
        responses = {
            "": self.repository,
            "actions/runs/123": self.run,
            "compare/" + REVISION + "...main": {"status": self.ancestry},
            "environments/" + risk.ENVIRONMENT: self.environment,
            "environments/" + risk.ENVIRONMENT + "/deployment-branch-policies": self.branches,
            "actions/runs/123/artifacts?per_page=100": self.artifacts,
        }
        if path == "actions/artifacts/1/zip":
            if not raw:
                raise AssertionError("artifact must be requested as raw bytes")
            buffer = io.BytesIO()
            entries = self.archive_entries
            if entries is None:
                entries = [("approval.json", risk.canonical(self.approval))]
            with zipfile.ZipFile(buffer, "w") as archive:
                for name, payload in entries:
                    archive.writestr(name, payload)
            return buffer.getvalue()
        if path not in responses:
            raise AssertionError(path)
        return responses[path]


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.reset()

    def reset(self, coverage=False):
        self.record = proposal(coverage)
        self.path = self.folder / (self.record["id"] + ".md")
        self.write_record()
        self.api = FakeGitHub(self.path.read_bytes(), self.record["id"])
        self.approval = risk.prepare(self.api, self.path, REVISION,
                                     risk.sha(self.path.read_bytes()), 123)
        self.api.approval = self.approval

    def write_record(self):
        self.path.write_bytes(b"---\n" + risk.canonical(self.record) + b"\n---\nHuman reasoning.\n")

    def verify(self, **kwargs):
        return risk.verify(self.api, self.path, self.approval, at=kwargs.get("at", AT))

    def test_exact_risk_and_coverage_approvals(self):
        for coverage in (False, True):
            with self.subTest(coverage=coverage):
                self.reset(coverage)
                self.assertEqual(self.verify(), self.record)
                scope = {"inventory_sha256": INVENTORY_HASH} if coverage else self.record["findings"]
                self.assertEqual(self.approval["scope_sha256"], risk.sha(risk.canonical(scope)))
                directory = "coverage-reviews" if coverage else "risk-acceptances"
                self.assertIn((f"docs/security/{directory}/{self.record['id']}.md", REVISION),
                              self.api.content_requests)

    def test_untrusted_run_sources_and_incomplete_runs_fail(self):
        cases = {"repository": {"full_name": "other/veyport"}, "event": "push",
                 "path": ".github/workflows/fake.yml", "head_branch": "feature",
                 "run_attempt": 2, "status": "in_progress", "conclusion": "cancelled"}
        for field, value in cases.items():
            with self.subTest(field=field):
                self.reset()
                self.api.run[field] = value
                with self.assertRaises(ValueError):
                    self.verify()

    def test_both_actors_require_pinned_owner_identity(self):
        for actor in ("actor", "triggering_actor"):
            for field, value in (("id", 1), ("login", "other"), ("type", "Bot")):
                with self.subTest(actor=actor, field=field):
                    self.reset()
                    self.api.run[actor][field] = value
                    with self.assertRaises(ValueError):
                        self.verify()

    def test_repository_and_owner_identity_fail_closed(self):
        for field, value in (("full_name", "other/veyport"), ("default_branch", "develop")):
            with self.subTest(field=field):
                self.reset()
                self.api.repository[field] = value
                with self.assertRaises(ValueError):
                    self.verify()
        for field, value in (("id", 1), ("login", "other"), ("type", "Organization")):
            with self.subTest(owner=field):
                self.reset()
                self.api.repository["owner"][field] = value
                with self.assertRaises(ValueError):
                    self.verify()

    def test_each_trusted_file_and_main_ancestry_are_enforced(self):
        for path in risk.TRUSTED_FILES:
            with self.subTest(path=path):
                self.reset()
                self.api.changed_file = path
                with self.assertRaisesRegex(ValueError, "implementation changed"):
                    self.verify()
        self.reset()
        self.api.ancestry = "diverged"
        with self.assertRaisesRegex(ValueError, "outside trusted main history"):
            self.verify()

    def test_owner_only_protected_environment_is_required(self):
        for change in ("unprotected", "self-review", "extra-reviewer", "wrong-reviewer", "team", "duplicate-rule"):
            with self.subTest(change=change):
                self.reset()
                rules = self.api.environment["protection_rules"]
                if change == "unprotected":
                    rules.clear()
                elif change == "self-review":
                    rules[0]["prevent_self_review"] = True
                elif change == "extra-reviewer":
                    rules[0]["reviewers"].append(copy.deepcopy(rules[0]["reviewers"][0]))
                elif change == "wrong-reviewer":
                    rules[0]["reviewers"][0]["reviewer"]["id"] = 1
                elif change == "team":
                    rules[0]["reviewers"][0]["type"] = "Team"
                else:
                    rules.append(copy.deepcopy(rules[0]))
                with self.assertRaises(ValueError):
                    self.verify()

    def test_environment_allows_only_exact_main_branch(self):
        for policy in ({"protected_branches": True, "custom_branch_policies": False}, None):
            with self.subTest(policy=policy):
                self.reset()
                self.api.environment["deployment_branch_policy"] = policy
                with self.assertRaises(ValueError):
                    self.verify()
        for branches in ([], [{"name": "*", "type": "branch"}],
                         [{"name": "main", "type": "tag"}],
                         [{"name": "main", "type": "branch"}, {"name": "other", "type": "branch"}]):
            with self.subTest(branches=branches):
                self.reset()
                self.api.branches["branch_policies"] = branches
                with self.assertRaises(ValueError):
                    self.verify()

    def test_preparation_requires_exact_hash_revision_and_provider_bytes(self):
        for revision, digest in (("main", risk.sha(self.path.read_bytes())),
                                 (REVISION, "c" * 64)):
            with self.subTest(revision=revision, digest=digest), self.assertRaises(ValueError):
                risk.prepare(self.api, self.path, revision, digest, 123)
        self.api.raw += b"Provider record changed.\n"
        with self.assertRaisesRegex(ValueError, "revision content mismatch"):
            risk.prepare(self.api, self.path, REVISION, risk.sha(self.path.read_bytes()), 123)

    def test_scope_or_reason_changes_cannot_reuse_approval(self):
        for coverage in (False, True):
            for change in ("scope", "reason"):
                with self.subTest(coverage=coverage, change=change):
                    self.reset(coverage)
                    if change == "reason":
                        self.record["reason"] = "Changed reasoning"
                    elif coverage:
                        self.record["inventory_sha256"] = "c" * 64
                    else:
                        self.record["findings"][0]["scope"] = "image:veyport"
                    self.write_record()
                    with self.assertRaises(ValueError):
                        self.verify()

    def test_modified_descriptor_and_artifact_are_rejected(self):
        for field, value in (("record_sha256", "c" * 64), ("scope_sha256", "c" * 64),
                             ("record_revision", "d" * 40), ("approved_by", "other")):
            with self.subTest(field=field):
                changed = {**self.approval, field: value}
                with self.assertRaises(ValueError):
                    risk.verify(self.api, self.path, changed, AT)
        self.api.approval = {**self.approval, "scope_sha256": "c" * 64}
        with self.assertRaisesRegex(ValueError, "authenticated artifact"):
            self.verify()

    def test_missing_expired_ambiguous_or_oversized_artifacts_fail(self):
        for change in ("missing", "expired", "duplicate", "oversized", "pagination"):
            with self.subTest(change=change):
                self.reset()
                items = self.api.artifacts["artifacts"]
                if change == "missing":
                    items.clear()
                elif change == "expired":
                    items[0]["expired"] = True
                elif change == "duplicate":
                    items.append(copy.deepcopy(items[0]))
                elif change == "oversized":
                    items[0]["size_in_bytes"] = risk.MAX_BYTES + 1
                else:
                    self.api.artifacts["total_count"] = 101
                with self.assertRaises(ValueError):
                    self.verify()

    def test_archive_cannot_substitute_paths_or_extra_entries(self):
        payload = risk.canonical(self.approval)
        for entries in ([], [("../approval.json", payload)],
                        [("approval.json", payload), ("extra.txt", b"extra")],
                        [("approval.json", b"x" * 65537)]):
            with self.subTest(names=[name for name, _ in entries]):
                self.api.archive_entries = entries
                with self.assertRaises(ValueError):
                    self.verify()

    def test_approval_time_window_and_stale_proposals_fail(self):
        for at in (AT - dt.timedelta(hours=1), AT + dt.timedelta(days=2)):
            with self.subTest(at=at), self.assertRaises(ValueError):
                self.verify(at=at)
        for created in ("2026-11-04T10:00:00Z", "2026-11-05T11:00:01Z", "2026-11-05T12:00:00Z"):
            with self.subTest(created=created):
                self.api.run["created_at"] = created
                with self.assertRaisesRegex(ValueError, "stale or expired"):
                    risk.prepare(self.api, self.path, REVISION, risk.sha(self.path.read_bytes()), 123)

    def test_invalid_run_ids_fail(self):
        for run_id in (True, 0, -1, "123"):
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                risk.trusted_run(self.api, run_id)


class RecordValidationTests(unittest.TestCase):
    def test_exact_scopes_and_bounded_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RA-0001.md"
            for change in ("unknown-scope", "wildcard", "duplicate-scope", "missing-scope", "long-expiry", "wrong-owner", "private-path"):
                with self.subTest(change=change):
                    record = proposal()
                    if change == "unknown-scope":
                        record["findings"][0]["scope"] = "source:npm:other"
                    elif change == "wildcard":
                        record["findings"][0]["version"] = "*"
                    elif change == "duplicate-scope":
                        record["findings"].append(copy.deepcopy(record["findings"][0]))
                    elif change == "missing-scope":
                        record["findings"][0].pop("scope")
                    elif change == "long-expiry":
                        record["expires_at"] = "2027-11-04T11:00:00Z"
                    elif change == "wrong-owner":
                        record["authorized_approver"] = "other"
                    else:
                        record["private_evidence_reference"] = "/private/evidence"
                    path.write_bytes(b"---\n" + risk.canonical(record) + b"\n---\nHuman reasoning.\n")
                    with self.assertRaises(ValueError):
                        risk.load_record(path)

    def test_duplicate_keys_nonfinite_json_and_missing_reasoning_fail(self):
        for payload in ('{"id":1,"id":2}', '{"value":NaN}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                risk.strict_json(payload)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RA-0001.md"
            path.write_bytes(b"---\n" + risk.canonical(proposal()) + b"\n---\n")
            with self.assertRaisesRegex(ValueError, "human reasoning"):
                risk.load_record(path)


if __name__ == "__main__":
    unittest.main()
